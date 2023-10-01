package sproxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"
)

type Proxy struct {
	logger *slog.Logger
}

type ProxyRequestIdGetter func(ctx context.Context) string

func NewProxy(logger *slog.Logger) *Proxy {
	return &Proxy{logger: logger}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else if r.URL.IsAbs() {
		p.handleRequest(w, r)
	} else {
		p.handleNotAllowed(w, r)
	}
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	dest, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		p.logger.LogAttrs(
			r.Context(),
			slog.LevelError,
			"error connecting host",
			slog.String("error", err.Error()),
			slog.String("host", r.Host),
		)
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.logger.LogAttrs(
			r.Context(),
			slog.LevelError,
			"error getting hijack interface",
			slog.String("error", err.Error()),
		)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	client, _, err := hijacker.Hijack()
	if err != nil {
		p.logger.LogAttrs(
			r.Context(),
			slog.LevelError,
			"error hijacking client connection",
			slog.String("error", err.Error()),
		)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// should be w.WriteHeader(http.StatusOK), but the connection is hijacked
	client.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))

	err = p.transfer(dest.(*net.TCPConn), client.(*net.TCPConn))
	if err != nil {
		p.logger.LogAttrs(
			r.Context(),
			slog.LevelError,
			"error copying request/reponse data",
			slog.String("error", err.Error()),
			slog.String("uri", r.RequestURI),
		)
	}
}

func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	p.removeHopHeaders(r.Header)

	response, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		p.logger.LogAttrs(
			r.Context(),
			slog.LevelError,
			"error sending request",
			slog.String("error", err.Error()),
			slog.String("uri", r.RequestURI),
		)
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	defer response.Body.Close()

	p.copyHeader(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)

	_, err = io.Copy(w, response.Body)
	if err != nil {
		p.logger.LogAttrs(
			r.Context(),
			slog.LevelError,
			"error copying request/reponse data",
			slog.String("error", err.Error()),
			slog.String("uri", r.RequestURI),
		)
	}
}

func (p *Proxy) handleNotAllowed(w http.ResponseWriter, r *http.Request) {
	p.logger.LogAttrs(
		r.Context(),
		slog.LevelError,
		"invalid method",
		slog.String("method", r.Method),
		slog.String("uri", r.RequestURI),
	)
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}

func (p *Proxy) copyHeader(dst http.Header, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
func (p *Proxy) removeHopHeaders(header http.Header) {
	hopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	}
	for _, key := range hopHeaders {
		header.Del(key)
	}
}

func (p *Proxy) transfer(dst, src *net.TCPConn) error {
	defer dst.Close()
	defer src.Close()

	done := make(chan error, 2)

	copy := func(dst, src *net.TCPConn) {
		_, err := io.Copy(dst, src)
		dst.CloseWrite()
		done <- err
	}

	go copy(dst, src)
	go copy(src, dst)

	err1 := <-done
	err2 := <-done

	if err1 != nil {
		return err1
	}

	if err2 != nil {
		return err2
	}

	return nil
}
