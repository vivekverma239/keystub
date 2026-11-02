# Conformance cases

Every Keystub data plane (the Go proxy and server, and any other
implementation) must pass these cases, so a request is treated the same
wherever it goes.

`swap.json` covers finding the proxy token in a request and putting the real
key in its place. Tokens are swapped only in auth headers: `authHeaders`
(just `Authorization`) plus the service's own header from the catalog. A token in any
other header refuses the request (`"refused": true`, status 400), because a
service may keep or echo that header and so hand the real key back.

Each other case names a service from `catalog/services.json`, the request
headers as the client sent them, the real key, the token that must be found
(`""` for none), and the headers that must reach the service (`""` means
absent). After the swap, no header may still contain a proxy token in either
form (`sk-stub-…` or `skstub…`).

`usage.json` covers reading usage from a response. Each case names a
service, the request (method, path, and a JSON body when the model comes
from it), and the response (status, headers, body as sent: JSON, or
server-sent events as raw text). `expect` is what the event must carry:
operation, model, outcome, usage (`null` for none), `costMicros` (`null`
when no price applies; priced at `time`, else 2026-10-15T12:00:00Z) and
quota. A runner must get the same answer feeding the body whole, a byte at
a time and in odd chunks, and gzipped, and must hand the body on unchanged.
