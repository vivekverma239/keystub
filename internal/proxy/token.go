package proxy

// ProxyAuthToken reads a proxy token from a Proxy-Authorization value
// (Basic with the token as password or user, or Bearer), in its canonical
// form, or "". For front ends that check the token before the proxy runs,
// such as the multi-tenant gateway.
func ProxyAuthToken(h string) string { return proxyAuthToken(h) }
