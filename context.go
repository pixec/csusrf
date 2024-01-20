package csusrf

import (
	"context"
	"fmt"
)

type contextKey struct {
	name string
}

var (
	ErrCtxKey = contextKey{"csusrf.err"}
	TokCtxKey = contextKey{"csusrf.tok"}
)

// FromContext retrieves a value of type T from the provided context using a specified contextKey.
//
// The function attempts to extract the value associated with the given ctxKey from the context.
// If the value exists and is of type T, it is returned along with a nil error. If the value does not
// exist or is of an incompatible type, the function returns a zero value of type T and an error
// indicating the absence or type mismatch of the context key.
func FromContext[T any](ctx context.Context, ctxKey contextKey) (T, error) {
	val, ok := ctx.Value(ctxKey).(T)
	if !ok {
		return val, fmt.Errorf("csusrf: no value exists for context key: %v", ctxKey)
	}

	return val, nil
}
