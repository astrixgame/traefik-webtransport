package wtproxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/quic-go/webtransport-go"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
)

// ProxyBuilder builds the HTTP proxies of the backend servers.
type ProxyBuilder interface {
	Build(cfgName string, targetURL *url.URL, passHostHeader, preservePath bool, flushInterval time.Duration) (http.Handler, error)
	Update(configs map[string]*dynamic.ServersTransport)
}

// TransportManager manages transport used for backend communications.
type TransportManager interface {
	Get(name string) (*dynamic.ServersTransport, error)
	GetTLSConfig(name string) (*tls.Config, error)
}

// Builder decorates a ProxyBuilder to make the built proxies able to proxy WebTransport sessions.
type Builder struct {
	next             ProxyBuilder
	transportManager TransportManager
	config           *webtransport.Config
}

// NewBuilder creates a new Builder.
func NewBuilder(next ProxyBuilder, transportManager TransportManager, config *webtransport.Config) *Builder {
	return &Builder{next: next, transportManager: transportManager, config: config}
}

// Update is the handler called when the dynamic configuration is updated.
func (b *Builder) Update(configs map[string]*dynamic.ServersTransport) {
	b.next.Update(configs)
}

// Build builds an HTTP proxy for the given URL using the ServersTransport with the given name.
func (b *Builder) Build(cfgName string, targetURL *url.URL, passHostHeader, preservePath bool, flushInterval time.Duration) (http.Handler, error) {
	proxy, err := b.next.Build(cfgName, targetURL, passHostHeader, preservePath, flushInterval)
	if err != nil {
		return nil, err
	}

	// WebTransport sessions are carried over QUIC, which is always encrypted.
	if targetURL.Scheme != "https" {
		return proxy, nil
	}

	serversTransport, err := b.transportManager.Get(cfgName)
	if err != nil {
		return nil, fmt.Errorf("getting ServersTransport: %w", err)
	}

	var dialTimeout time.Duration
	if serversTransport.ForwardingTimeouts != nil {
		dialTimeout = time.Duration(serversTransport.ForwardingTimeouts.DialTimeout)
	}

	return NewHandler(proxy, Config{
		Target:         targetURL,
		PassHostHeader: passHostHeader,
		PreservePath:   preservePath,
		TLSConfig:      func() (*tls.Config, error) { return b.transportManager.GetTLSConfig(cfgName) },
		DialTimeout:    dialTimeout,
		Config:         b.config,
	}), nil
}
