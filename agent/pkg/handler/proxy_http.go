package handler

import (
	"crypto/tls"
	"net/http"
	"strconv"
	"time"

	"github.com/yusing/go-proxy/agent/pkg/agent"
	agentproxy "github.com/yusing/go-proxy/agent/pkg/agentproxy"
	"github.com/yusing/go-proxy/internal/logging"
	gphttp "github.com/yusing/go-proxy/internal/net/http"
	"github.com/yusing/go-proxy/internal/net/http/reverseproxy"
	"github.com/yusing/go-proxy/internal/net/types"
	"github.com/yusing/go-proxy/internal/utils/strutils"
)

func ProxyHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get(agentproxy.HeaderXProxyHost)
	isHTTPs := strutils.ParseBool(r.Header.Get(agentproxy.HeaderXProxyHTTPS))
	skipTLSVerify := strutils.ParseBool(r.Header.Get(agentproxy.HeaderXProxySkipTLSVerify))
	responseHeaderTimeout, err := strconv.Atoi(r.Header.Get(agentproxy.HeaderXProxyResponseHeaderTimeout))
	if err != nil {
		responseHeaderTimeout = 0
	}

	logging.Debug().Msgf("proxy http request: host=%s, isHTTPs=%t, skipTLSVerify=%t, responseHeaderTimeout=%d", host, isHTTPs, skipTLSVerify, responseHeaderTimeout)

	if host == "" {
		http.Error(w, "missing required headers", http.StatusBadRequest)
		return
	}

	scheme := "http"
	if isHTTPs {
		scheme = "https"
	}

	var transport *http.Transport
	if skipTLSVerify {
		transport = gphttp.NewTransportWithTLSConfig(&tls.Config{InsecureSkipVerify: true})
	} else {
		transport = gphttp.NewTransport()
	}

	if responseHeaderTimeout > 0 {
		transport = transport.Clone()
		transport.ResponseHeaderTimeout = time.Duration(responseHeaderTimeout) * time.Second
	}

	r.URL.Scheme = scheme
	r.URL.Host = host
	r.URL.Path = r.URL.Path[agent.HTTPProxyURLStripLen:] // strip the {API_BASE}/proxy/http prefix

	logging.Debug().Msgf("proxy http request: %s %s", r.Method, r.URL.String())

	rp := reverseproxy.NewReverseProxy("agent", types.NewURL(r.URL), transport)
	rp.ServeHTTP(w, r)
}
