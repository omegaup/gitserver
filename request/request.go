package request

import (
	"context"
	"io"

	base "github.com/omegaup/go-base/v2"
)

type key int

const requestContextKey key = 0

// Request stores the request-specific part of the Context, to make it easier
// to serialize.
type Request struct {
	ProblemName string
	Username    string
	Create      bool
	IsSystem    bool
	IsAdmin     bool
	CanView     bool
	CanEdit     bool
	HasSolved   bool
	ReviewRef   string
}

// Context stores a few variables that are request-specific.
type Context struct {
	Request      Request
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
