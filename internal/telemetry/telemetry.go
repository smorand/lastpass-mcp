package telemetry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// InitTracer sets up OpenTelemetry with a JSONL file exporter.
// Returns a shutdown function that must be called on application exit.
func InitTracer(serviceName, tracePath string) (func(context.Context) error, error) {
	if err := os.MkdirAll(filepath.Dir(tracePath), 0755); err != nil {
		return nil, fmt.Errorf("create trace directory: %w", err)
	}
	f, err := os.OpenFile(tracePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open trace file %s: %w", tracePath, err)
	}
	exporter, err := stdouttrace.New(stdouttrace.WithWriter(f))
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("create exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(serviceName),
		)),
	)
	otel.SetTracerProvider(tp)
	return func(ctx context.Context) error {
		if err := tp.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown tracer: %w", err)
		}
		return f.Close()
	}, nil
}

// StartSpan creates a new span with the given name and attributes.
func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	tracer := otel.Tracer("lastpass-mcp")
	return tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// EndSpan records error status if err != nil, then ends the span.
func EndSpan(span trace.Span, err error) {
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
	} else {
		span.SetStatus(codes.Ok, "")
	}
	span.End()
}
