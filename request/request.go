package request

import (
	"context"
	"io"
)

type key int

const requestContextKey key = 0

// Context stores a few variables that are request-specific.
type Context struct {
	IsAdmin      bool
	CanView      bool
	CanEdit      bool
	HasSolved    bool
	ReviewRef    string
	UpdatedFiles map[string]io.Reader
}

// NewContext wraps the supplied context and associates a git
// protocol-specific context value to it.
func NewContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestContextKey, &Context{
		UpdatedFiles: make(map[string]io.Reader),
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
