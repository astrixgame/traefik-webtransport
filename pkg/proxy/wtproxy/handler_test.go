package wtproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startBackend starts a backend echoing the streams and the datagrams.
func startBackend(t *testing.T, cert tls.Certificate, onRequest func(*http.Request)) string {
	t.Helper()

	var server *webtransport.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(rw http.ResponseWriter, req *http.Request) {
		if onRequest != nil {
			onRequest(req)
		}

		sess, err := server.Upgrade(rw, req)
		if err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		go func() {
			for {
				str, err := sess.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go func() {
					_, _ = io.Copy(str, str)
					_ = str.Close()
				}()
			}
		}()

		go func() {
			for {
				str, err := sess.AcceptUniStream(context.Background())
				if err != nil {
					return
				}
				go func() {
					data, _ := io.ReadAll(str)
					out, err := sess.OpenUniStream()
					if err != nil {
						return
					}
					_, _ = out.Write(data)
					_ = out.Close()
				}()
			}
		}()

		go func() {
			for {
				data, err := sess.ReceiveDatagram(context.Background())
				if err != nil {
					return
				}
				_ = sess.SendDatagram(data)
			}
		}()

		<-sess.Context().Done()
	})
	mux.HandleFunc("/close", func(rw http.ResponseWriter, req *http.Request) {
		sess, err := server.Upgrade(rw, req)
		if err != nil {
			return
		}
		_ = sess.CloseWithError(42, "bye")
	})
	mux.HandleFunc("/refuse", func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusForbidden)
	})

	_, addr := newWebTransportServerWithHandler(t, cert, []string{"proto-a", "proto-b"}, func(srv *webtransport.Server) http.Handler {
		server = srv
		return mux
	})

	return addr
}

// startProxy starts an HTTP/3 server proxying the WebTransport sessions to the given backend.
func startProxy(t *testing.T, cert tls.Certificate, backendAddr string, clientProtocols []string) string {
	t.Helper()

	target := &url.URL{Scheme: "https", Host: backendAddr}

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		http.Error(rw, "not a WebTransport request", http.StatusTeapot)
	})

	handler := NewHandler(next, Config{
		Target:       target,
		PreservePath: true,
		TLSConfig: func() (*tls.Config, error) {
			return &tls.Config{InsecureSkipVerify: true}, nil
		},
		DialTimeout: 5 * time.Second,
		Config:      &webtransport.Config{MaxIncomingStreams: 100, MaxIncomingUniStreams: 100, MaxIncomingData: 1 << 20},
	})

	_, addr := newWebTransportServerWithHandler(t, cert, clientProtocols, func(server *webtransport.Server) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			handler.ServeHTTP(rw, req.WithContext(WithServer(req.Context(), server)))
		})
	})

	return addr
}

func newWebTransportServerWithHandler(t *testing.T, cert tls.Certificate, protocols []string, handler func(*webtransport.Server) http.Handler) (*webtransport.Server, string) {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	server := &webtransport.Server{
		H3: &http3.Server{
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{http3.NextProtoH3}},
		},
		Config:               &webtransport.Config{MaxIncomingStreams: 100, MaxIncomingUniStreams: 100, MaxIncomingData: 1 << 20},
		ApplicationProtocols: protocols,
		CheckOrigin:          func(*http.Request) bool { return true },
	}

	server.H3.Handler = handler(server)

	go func() { _ = server.Serve(conn) }()
	t.Cleanup(func() { _ = server.Close() })

	return server, conn.LocalAddr().String()
}

func dial(t *testing.T, addr, path string, header http.Header, protocols []string) (*http.Response, *webtransport.Session, error) {
	t.Helper()

	transport := &webtransport.Transport{
		TLSClientConfig:      &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}},
		QUICConfig:           &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true},
		Config:               &webtransport.Config{MaxIncomingStreams: 100, MaxIncomingUniStreams: 100, MaxIncomingData: 1 << 20},
		ApplicationProtocols: protocols,
	}
	t.Cleanup(func() { _ = transport.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	rsp, sess, err := transport.Dial(ctx, "https://"+addr+path, header)
	if sess != nil {
		t.Cleanup(func() { _ = sess.CloseWithError(0, "") })
	}

	return rsp, sess, err
}

func TestHandler_proxiesSessions(t *testing.T) {
	cert := testCertificate(t)

	headers := make(chan http.Header, 1)
	backend := startBackend(t, cert, func(req *http.Request) { headers <- req.Header.Clone() })
	proxyAddr := startProxy(t, cert, backend, []string{"proto-a", "proto-b"})

	header := http.Header{"X-Custom": []string{"value"}}
	_, sess, err := dial(t, proxyAddr, "/echo", header, []string{"proto-b", "proto-c"})
	require.NoError(t, err)

	assert.Equal(t, "proto-b", sess.SessionState().ApplicationProtocol)
	assert.Equal(t, "value", (<-headers).Get("X-Custom"))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("bidirectional stream", func(t *testing.T) {
		str, err := sess.OpenStreamSync(ctx)
		require.NoError(t, err)

		payload := make([]byte, 1<<20)
		_, err = rand.Read(payload)
		require.NoError(t, err)

		go func() {
			_, _ = str.Write(payload)
			_ = str.Close()
		}()

		got, err := io.ReadAll(str)
		require.NoError(t, err)
		assert.Equal(t, payload, got)
	})

	t.Run("unidirectional stream", func(t *testing.T) {
		out, err := sess.OpenUniStreamSync(ctx)
		require.NoError(t, err)

		_, err = out.Write([]byte("hello"))
		require.NoError(t, err)
		require.NoError(t, out.Close())

		in, err := sess.AcceptUniStream(ctx)
		require.NoError(t, err)

		got, err := io.ReadAll(in)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(got))
	})

	t.Run("datagram", func(t *testing.T) {
		require.NoError(t, sess.SendDatagram([]byte("ping")))

		got, err := sess.ReceiveDatagram(ctx)
		require.NoError(t, err)
		assert.Equal(t, "ping", string(got))
	})

	t.Run("stream reset", func(t *testing.T) {
		str, err := sess.OpenStreamSync(ctx)
		require.NoError(t, err)

		_, err = str.Write([]byte("x"))
		require.NoError(t, err)

		str.CancelRead(7)
		str.CancelWrite(7)
	})
}

func TestHandler_propagatesBackendSessionClose(t *testing.T) {
	cert := testCertificate(t)

	backend := startBackend(t, cert, nil)
	proxyAddr := startProxy(t, cert, backend, nil)

	_, sess, err := dial(t, proxyAddr, "/close", nil, nil)
	require.NoError(t, err)

	select {
	case <-sess.Context().Done():
	case <-time.After(10 * time.Second):
		t.Fatal("session not closed")
	}

	_, err = sess.AcceptStream(context.Background())
	sessErr, ok := errors.AsType[*webtransport.SessionError](err)
	require.True(t, ok)
	assert.Equal(t, webtransport.SessionErrorCode(42), sessErr.ErrorCode)
	assert.Equal(t, "bye", sessErr.Message)
}

func TestHandler_propagatesClientSessionClose(t *testing.T) {
	cert := testCertificate(t)

	backend := startBackend(t, cert, nil)
	proxyAddr := startProxy(t, cert, backend, nil)

	_, sess, err := dial(t, proxyAddr, "/echo", nil, nil)
	require.NoError(t, err)

	require.NoError(t, sess.CloseWithError(9, "done"))
	<-sess.Context().Done()
}

func TestHandler_backendRefusal(t *testing.T) {
	cert := testCertificate(t)

	backend := startBackend(t, cert, nil)
	proxyAddr := startProxy(t, cert, backend, nil)

	rsp, _, err := dial(t, proxyAddr, "/refuse", nil, nil)
	require.Error(t, err)
	require.NotNil(t, rsp)
	assert.Equal(t, http.StatusBadGateway, rsp.StatusCode)
}

func TestHandler_backendUnreachable(t *testing.T) {
	cert := testCertificate(t)

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	addr := conn.LocalAddr().String()
	require.NoError(t, conn.Close())

	proxyAddr := startProxy(t, cert, addr, nil)

	rsp, _, err := dial(t, proxyAddr, "/echo", nil, nil)
	require.Error(t, err)
	require.NotNil(t, rsp)
	assert.Contains(t, []int{http.StatusBadGateway, http.StatusGatewayTimeout}, rsp.StatusCode)
}

func TestHandler_nonWebTransportRequest(t *testing.T) {
	handler := NewHandler(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusTeapot)
	}), Config{Target: &url.URL{Scheme: "https", Host: "localhost:1"}})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusTeapot, rec.Code)
}

func TestHandler_missingServer(t *testing.T) {
	handler := NewHandler(http.NotFoundHandler(), Config{Target: &url.URL{Scheme: "https", Host: "localhost:1"}})

	req := httptest.NewRequest(http.MethodConnect, "/", nil)
	req.Proto = "webtransport"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}

func TestIsWebTransportRequest(t *testing.T) {
	tests := []struct {
		method, proto string
		want          bool
	}{
		{http.MethodConnect, "webtransport", true},
		{http.MethodConnect, "webtransport-h3", true},
		{http.MethodConnect, "websocket", false},
		{http.MethodGet, "webtransport", false},
	}

	for _, test := range tests {
		req := &http.Request{Method: test.method, Proto: test.proto}
		assert.Equal(t, test.want, IsWebTransportRequest(req), test.method+" "+test.proto)
	}
}

func TestBackendURL(t *testing.T) {
	target, err := url.Parse("https://backend:8443/base")
	require.NoError(t, err)

	req := &http.Request{
		Method: http.MethodConnect,
		Host:   "example.com",
		URL:    &url.URL{Path: "/wt", RawQuery: "a=1;b=2"},
	}

	tests := []struct {
		desc string
		cfg  Config
		want string
	}{
		{desc: "default", cfg: Config{Target: target}, want: "https://backend:8443/wt?a=1&b=2"},
		{desc: "preserve path", cfg: Config{Target: target, PreservePath: true}, want: "https://backend:8443/base/wt?a=1&b=2"},
		{desc: "pass host header", cfg: Config{Target: target, PassHostHeader: true}, want: "https://example.com/wt?a=1&b=2"},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			h := &Handler{cfg: test.cfg}
			assert.Equal(t, test.want, h.backendURL(req).String())
		})
	}
}
