Vendored from github.com/quic-go/webtransport-go (main, 2a2b547d91a8), MIT licensed (see LICENSE).

Only change: `Server.Upgrade` writes the response header before calling `HTTPStream`, and handles its error,
to match the quic-go v0.65 `http3.HTTPStreamer` API. Drop this copy once upstream supports it.
