package enhanced

import (
	"context"

	"go.opentelemetry.io/otel/trace"
)

// StartSpanFromOTEL creates an enhanced span from an existing OTEL span context
func StartSpanFromOTEL(ctx context.Context, tracer Tracer, opName string, otelSpan trace.Span) (Span, context.Context) {
	if tracer == nil || !tracer.IsEnabled() {
		return nil, ctx
	}
	var traceID string
	if otelSpan != nil && otelSpan.SpanContext().IsValid() {
		traceID = otelSpan.SpanContext().TraceID().String()
	}
	span, newCtx := tracer.StartSpan(ctx, opName, traceID)
	return span, newCtx
}

// SpanFromContext retrieves enhanced span from context
func SpanFromContext(ctx context.Context) Span {
	if span, ok := ctx.Value(enhancedSpanKey{}).(Span); ok {
		return span
	}
	return nil
}

// ContextWithSpan stores enhanced span in context
func ContextWithSpan(ctx context.Context, span Span) context.Context {
	return context.WithValue(ctx, enhancedSpanKey{}, span)
}

type enhancedSpanKey struct{}
