package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/vivekverma239/keystub/internal/gateway"
	"github.com/vivekverma239/keystub/internal/legacy"
	"github.com/vivekverma239/keystub/internal/proxy"
)

// gatewayCmd runs the hosted remote proxy: the agent's forwarding mode for
// many accounts at once, for boxes that set only HTTPS_PROXY and a CA
// file. It holds no keys: tokens are checked with the edge, each account's
// CA comes from the edge, and decrypted requests go to the edge's /h.
func gatewayCmd(args []string) error {
	fs := flag.NewFlagSet("gateway", flag.ExitOnError)
	edge := fs.String("edge", legacy.Getenv("KEYSTUB_EDGE"), "the hosted edge, e.g. https://edge.example.com (default: $KEYSTUB_EDGE)")
	listen := fs.String("listen", ":8080", "address for the proxy")
	health := fs.String("health", ":8081", `address for GET /healthz ("" for none)`)
	certFile := fs.String("tls-cert", "", "serve the proxy over TLS with this certificate (PEM)")
	keyFile := fs.String("tls-key", "", "the --tls-cert certificate's key (PEM)")
	inFront := fs.Bool("tls-in-front", false, "TLS ends in front of the gateway (a TLS-terminating load balancer), so --listen may be plain off loopback")
	checkTTL := fs.Duration("check-ttl", 30*time.Second, "how long a token check is trusted, and how often open connections' tokens are checked again")
	var ports hostList
	fs.Var(&ports, "tunnel-port", "a port CONNECT may name; repeatable (default: 443 only)")
	_ = fs.Parse(args)

	// The credential is a secret: from the environment only, never a flag,
	// which would show in ps.
	key := os.Getenv("KEYSTUB_GATEWAY_KEY")
	if *edge == "" || key == "" {
		return errors.New("usage: KEYSTUB_GATEWAY_KEY=… keystub gateway --edge https://edge.example.com [--listen :8080] [--tls-in-front | --tls-cert FILE --tls-key FILE]")
	}
	u, err := parseRemote(*edge)
	if err != nil {
		return err
	}
	var tlsConfig *tls.Config
	switch {
	case (*certFile == "") != (*keyFile == ""):
		return errors.New("--tls-cert and --tls-key go together")
	case *certFile != "":
		pair, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			return err
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	case !*inFront && !proxy.IsLoopback(*listen):
		// Proxy tokens would cross the network in the clear.
		return fmt.Errorf("the gateway on %s needs TLS: --tls-cert and --tls-key, or --tls-in-front when a load balancer ends TLS", *listen)
	}
	logger := log.New(os.Stderr, "", log.LstdFlags)
	g, err := gateway.New(gateway.Config{Edge: u, Key: key, CheckTTL: *checkTTL, TunnelPorts: ports, ErrorLog: logger})
	if err != nil {
		return err
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	errc := make(chan error, 2)
	go func() { errc <- g.Serve(l, tlsConfig) }()
	var hs *http.Server
	if *health != "" {
		hl, err := net.Listen("tcp", *health)
		if err != nil {
			return fmt.Errorf("health: %w", err)
		}
		hs = &http.Server{Handler: gateway.Health(), ReadHeaderTimeout: 5 * time.Second}
		go func() { errc <- hs.Serve(hl) }()
	}
	scheme := "http"
	if tlsConfig != nil || *inFront {
		scheme = "https"
	}
	fmt.Fprintf(os.Stderr, "Keystub gateway is running, with no keys.\n  Proxy:  %s (boxes: HTTPS_PROXY=%s://keystub:<token>@<this host>)\n  Edge:   %s\n", l.Addr(), scheme, u)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, stopSignals()...)
	select {
	case <-sig:
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if hs != nil {
		_ = hs.Shutdown(ctx)
	}
	return g.Shutdown(ctx)
}
