package middleware

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/oklog/ulid/v2"
)

type requestId string

const requestIdKey requestId = "request-id"

func GetRequestID(ctx context.Context) string {
	value := ctx.Value(requestIdKey)

	if result, ok := value.(string); ok {
		return result
	}

	return ""
}

func SetRequestId(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, requestIdKey, value)
}

type RequestIdMiddleware struct {
	next        http.Handler
	allowRemote bool
}

func NewRequestIdMiddleware(next http.Handler, allowRemote bool) *RequestIdMiddleware {
	return &RequestIdMiddleware{next: next, allowRemote: allowRemote}
}

func (m *RequestIdMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var requestId string
	if m.allowRemote {
		requestId = r.Header.Get("X-Request-ID")
	}
	if requestId == "" {
		requestId = ulid.Make().String()
	}

	ctx := SetRequestId(r.Context(), requestId)

	r = r.WithContext(ctx)

	m.next.ServeHTTP(w, r)
}

type RequestIdHandler struct {
	slog.Handler
}

func NewRequestIdHandler(handler slog.Handler) *RequestIdHandler {
	return &RequestIdHandler{handler}
}

func (h *RequestIdHandler) Handle(ctx context.Context, record slog.Record) error {
	requestId := GetRequestID(ctx)

	if requestId != "" {
		record.AddAttrs(slog.String("request-id", requestId))
	}

	return h.Handler.Handle(ctx, record)
}

func (h *RequestIdHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return NewRequestIdHandler(h.Handler.WithAttrs(attrs))
}

func (h *RequestIdHandler) WithGroup(name string) slog.Handler {
	return NewRequestIdHandler(h.Handler.WithGroup(name))
}
