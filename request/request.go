package request

import (
	"context"
	base "github.com/omegaup/go-base"
	"io"
)

type key int

const requestContextKey key = 0

// Context stores a few variables that are request-specific.
type Context struct {
	Create       bool
	IsAdmin      bool
	CanView      bool
	CanEdit      bool
	HasSolved    bool
	ReviewRef    string
	UpdatedFiles map[string]io.Reader
	Metrics      base.Metrics
}

// NewContext wraps the supplied context and associates a git
// protocol-specific context value to it.
func NewContext(ctx context.Context, metrics base.Metrics) context.Context {
	if metrics == nil {
		metrics = &base.NoOpMetrics{}
	}
	return context.WithValue(ctx, requestContextKey, &Context{
		UpdatedFiles: make(map[string]io.Reader),
		Metrics:      metrics,
	})
}

// FromContext unwraps a Context from the provided context.Context.
func FromContext(ctx context.Context) *Context {
	rc, ok := ctx.Value(requestContextKey).(*Context)
	if !ok {
		return nil
	}
	return rc
}
