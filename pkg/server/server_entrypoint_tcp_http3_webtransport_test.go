package server

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/static"
	"github.com/traefik/traefik/v3/pkg/proxy/wtproxy"
	tcprouter "github.com/traefik/traefik/v3/pkg/server/router/tcp"
	traefiktls "github.com/traefik/traefik/v3/pkg/tls"
)

func TestHTTP3WebTransportProxy(t *testing.T) {
	certContent, err := localhostCert.Read()
	require.NoError(t, err)

	keyContent, err := localhostKey.Read()
	require.NoError(t, err)

	tlsCert, err := tls.X509KeyPair(certContent, keyContent)
	require.NoError(t, err)

	// Backend echoing the bidirectional streams and the datagrams.
	backendConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	var backend *webtransport.Server
	backend = &webtransport.Server{
		H3: &http3.Server{
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}, NextProtos: []string{http3.NextProtoH3}},
			Handler: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				sess, err := backend.Upgrade(rw, req)
				if err != nil {
					return
				}

				go func() {
					for {
						data, err := sess.ReceiveDatagram(context.Background())
						if err != nil {
							return
						}
						_ = sess.SendDatagram(data)
					}
				}()

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
			}),
		},
		Config:      &webtransport.Config{MaxIncomingStreams: 10, MaxIncomingUniStreams: 10, MaxIncomingData: 1 << 20},
		CheckOrigin: func(*http.Request) bool { return true },
	}
	go func() { _ = backend.Serve(backendConn) }()
	t.Cleanup(func() { _ = backend.Close() })

	epConfig := &static.EntryPointsTransport{}
	epConfig.SetDefaults()

	wtConfig := &static.WebTransportConfig{}
	wtConfig.SetDefaults()

	// With a zero port the TCP and UDP listeners get different ports, so a free one is picked for both.
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	addr := probe.LocalAddr().String()
	require.NoError(t, probe.Close())

	entryPoint, err := NewTCPEntryPoint(t.Context(), "foo", &static.EntryPoint{
		Address:          addr,
		Transport:        epConfig,
		ForwardedHeaders: &static.ForwardedHeaders{},
		HTTP2:            &static.HTTP2Config{},
		HTTP3:            &static.HTTP3Config{WebTransport: wtConfig},
	}, nil, nil)
	require.NoError(t, err)

	router, err := tcprouter.NewRouter(nil)
	require.NoError(t, err)

	router.AddHTTPTLSConfig("*", &tls.Config{Certificates: []tls.Certificate{tlsCert}, NextProtos: []string{http3.NextProtoH3}}, traefiktls.DefaultTLSConfigName)
	router.SetHTTPSHandler(wtproxy.NewHandler(http.NotFoundHandler(), wtproxy.Config{
		Target:    &url.URL{Scheme: "https", Host: backendConn.LocalAddr().String()},
		TLSConfig: func() (*tls.Config, error) { return &tls.Config{InsecureSkipVerify: true}, nil },
		Config:    &webtransport.Config{MaxIncomingStreams: 10, MaxIncomingUniStreams: 10, MaxIncomingData: 1 << 20},
	}), nil)

	ctx := t.Context()
	go entryPoint.Start(ctx)
	entryPoint.SwitchRouter(router)
	t.Cleanup(func() { entryPoint.Shutdown(ctx) })

	transport := &webtransport.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}},
		QUICConfig:      &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true},
		Config:          &webtransport.Config{MaxIncomingStreams: 10, MaxIncomingUniStreams: 10, MaxIncomingData: 1 << 20},
	}
	t.Cleanup(func() { _ = transport.Close() })

	var sess *webtransport.Session
	require.Eventually(t, func() bool {
		dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()

		_, sess, err = transport.Dial(dialCtx, "https://"+addr+"/wt", nil)
		if err != nil {
			t.Log(err)
		}
		return err == nil
	}, 10*time.Second, 200*time.Millisecond)

	callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	str, err := sess.OpenStreamSync(callCtx)
	require.NoError(t, err)

	_, err = str.Write([]byte("hello"))
	require.NoError(t, err)
	require.NoError(t, str.Close())

	got, err := io.ReadAll(str)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))

	require.NoError(t, sess.SendDatagram([]byte("ping")))
	datagram, err := sess.ReceiveDatagram(callCtx)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(datagram))
}
