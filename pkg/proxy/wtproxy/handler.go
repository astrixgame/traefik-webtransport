package wtproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/proxy/httputil"
)

const (
	protocolsRequestHeader  = "Wt-Available-Protocols"
	protocolsResponseHeader = "Wt-Protocol"
)

type serverKey struct{}

// WithServer returns a context carrying the WebTransport server of the entry point which accepted the request.
func WithServer(ctx context.Context, server *webtransport.Server) context.Context {
	return context.WithValue(ctx, serverKey{}, server)
}

// IsWebTransportRequest returns whether the request is an extended CONNECT request opening a WebTransport session.
func IsWebTransportRequest(req *http.Request) bool {
	return req.Method == http.MethodConnect && (strings.EqualFold(req.Proto, "webtransport") || strings.EqualFold(req.Proto, "webtransport-h3"))
}

// IsServedWebTransportRequest returns whether the request opens a WebTransport session
// on an entry point whose HTTP/3 server serves the WebTransport sessions.
func IsServedWebTransportRequest(req *http.Request) bool {
	server, _ := req.Context().Value(serverKey{}).(*webtransport.Server)
	return server != nil && IsWebTransportRequest(req)
}

// TLSConfigGetter returns the TLS configuration to use to contact the backend server.
type TLSConfigGetter func() (*tls.Config, error)

// Config is the configuration of the WebTransport proxy of a backend server.
type Config struct {
	Target         *url.URL
	PassHostHeader bool
	PreservePath   bool
	TLSConfig      TLSConfigGetter
	DialTimeout    time.Duration
	// QUICConfig is the QUIC configuration used to contact the backend server, it is cloned for each session.
	QUICConfig *quic.Config
	// Config holds the WebTransport session limits towards the backend server.
	Config *webtransport.Config
}

// Handler proxies the WebTransport sessions to a backend server, and delegates any other request to next.
type Handler struct {
	next http.Handler
	cfg  Config
}

// NewHandler creates a new Handler.
func NewHandler(next http.Handler, cfg Config) *Handler {
	return &Handler{next: next, cfg: cfg}
}

// newTransport creates the transport of a session, as the TLS configuration can change with the dynamic configuration.
func (h *Handler) newTransport(tlsConfig *tls.Config, protocols []string) *webtransport.Transport {
	quicConfig := &quic.Config{}
	if h.cfg.QUICConfig != nil {
		quicConfig = h.cfg.QUICConfig.Clone()
	}
	quicConfig.EnableDatagrams = true
	quicConfig.EnableStreamResetPartialDelivery = true

	return &webtransport.Transport{
		Config:          h.cfg.Config,
		QUICConfig:      quicConfig,
		TLSClientConfig: tlsConfig,
		// The transport only accepts a protocol it offered, so it offers the ones offered by the client.
		ApplicationProtocols: protocols,
		// The session URL may carry the client's Host, the connection always goes to the selected server.
		DialAddr: func(ctx context.Context, _ string, tlsCfg *tls.Config, quicCfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, hostWithPort(h.cfg.Target), tlsCfg, quicCfg)
		},
	}
}

func (h *Handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !IsWebTransportRequest(req) {
		h.next.ServeHTTP(rw, req)
		return
	}

	logger := log.Ctx(req.Context())

	server, _ := req.Context().Value(serverKey{}).(*webtransport.Server)
	if server == nil {
		http.Error(rw, "WebTransport is not enabled on this entry point", http.StatusNotImplemented)
		return
	}

	// The upgrade needs the raw HTTP/3 stream, which is not exposed by the wrappers added by the middlewares.
	raw, err := unwrapResponseWriter(rw)
	if err != nil {
		logger.Error().Err(err).Msg("Unable to access the HTTP/3 stream")
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	backend, err := h.dialBackend(req)
	if err != nil {
		logger.Error().Err(err).Msg("Unable to establish the backend WebTransport session")
		status := http.StatusBadGateway
		if errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		http.Error(rw, http.StatusText(status), status)
		return
	}

	// The subprotocol is negotiated with the backend, the client is only offered the backend's choice.
	negotiated := backend.SessionState().ApplicationProtocol
	req.Header.Del(protocolsRequestHeader)
	if negotiated != "" {
		value, err := httpsfv.Marshal(httpsfv.NewItem(negotiated))
		if err == nil {
			req.Header.Set(protocolsRequestHeader, value)
		}
	}

	client, err := server.Upgrade(raw, req)
	if err != nil {
		logger.Error().Err(err).Msg("Unable to upgrade the client connection to WebTransport")
		_ = backend.CloseWithError(0, "")
		// The upgrade does not write any response on failure.
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if client.SessionState().ApplicationProtocol != negotiated {
		const msg = "application protocol is not supported by the entry point"
		_ = client.CloseWithError(webtransport.WTALPNErrorCode, msg)
		_ = backend.CloseWithError(webtransport.WTALPNErrorCode, msg)
		return
	}

	(&bridge{client: client, backend: backend, logger: *logger}).run()
}

func (h *Handler) dialBackend(req *http.Request) (*webtransport.Session, error) {
	tlsConfig, err := h.cfg.TLSConfig()
	if err != nil {
		return nil, fmt.Errorf("getting TLS config: %w", err)
	}

	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = []string{http3.NextProtoH3}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = h.cfg.Target.Hostname()
	}

	transport := h.newTransport(tlsConfig, offeredProtocols(req.Header))
	defer transport.Close()

	ctx := req.Context()
	if h.cfg.DialTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.cfg.DialTimeout)
		defer cancel()
	}

	rsp, sess, err := transport.Dial(ctx, h.backendURL(req).String(), backendHeaders(req))
	if err != nil {
		if rsp != nil {
			return nil, fmt.Errorf("backend refused the session with status %d: %w", rsp.StatusCode, err)
		}
		return nil, err
	}

	return sess, nil
}

func (h *Handler) backendURL(req *http.Request) *url.URL {
	u := &url.URL{
		Scheme:   "https",
		Host:     h.cfg.Target.Host,
		Path:     req.URL.Path,
		RawPath:  req.URL.RawPath,
		RawQuery: strings.ReplaceAll(req.URL.RawQuery, ";", "&"),
	}

	if h.cfg.PassHostHeader && req.Host != "" {
		u.Host = req.Host
	}

	if h.cfg.PreservePath {
		u.Path, u.RawPath = httputil.JoinURLPath(h.cfg.Target, req.URL)
	}

	return u
}

// backendHeaders returns the headers forwarded to the backend server.
func backendHeaders(req *http.Request) http.Header {
	headers := req.Header.Clone()

	// The entry point owns the HTTP/3 framing, and the transport owns the session negotiation.
	for _, name := range []string{"Connection", "Keep-Alive", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade", protocolsResponseHeader, protocolsRequestHeader} {
		headers.Del(name)
	}

	if !httputil.ShouldNotAppendXFF(req.Context()) {
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			if prior := headers.Values("X-Forwarded-For"); len(prior) > 0 {
				clientIP = strings.Join(prior, ", ") + ", " + clientIP
			}
			headers.Set("X-Forwarded-For", clientIP)
		}
	}

	return headers
}

// offeredProtocols returns the application protocols offered by the client.
func offeredProtocols(header http.Header) []string {
	list, err := httpsfv.UnmarshalList(header.Values(protocolsRequestHeader))
	if err != nil {
		return nil
	}

	var protocols []string
	for _, member := range list {
		item, ok := member.(httpsfv.Item)
		if !ok {
			return nil
		}
		protocol, ok := item.Value.(string)
		if !ok {
			return nil
		}
		protocols = append(protocols, protocol)
	}

	return protocols
}

func hostWithPort(target *url.URL) string {
	if target.Port() != "" {
		return target.Host
	}
	return net.JoinHostPort(target.Hostname(), "443")
}

// unwrapResponseWriter walks the middlewares response writers chain down to the HTTP/3 one.
func unwrapResponseWriter(rw http.ResponseWriter) (http.ResponseWriter, error) {
	for {
		_, isStreamer := rw.(http3.HTTPStreamer)
		_, isSettingser := rw.(http3.Settingser)
		if isStreamer && isSettingser {
			return rw, nil
		}

		unwrapper, ok := rw.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return nil, errors.New("response writer is not an HTTP/3 one")
		}
		rw = unwrapper.Unwrap()
	}
}
