package exporters

import (
	"context"
	"time"
)

type Exporter interface {
	ExportSpan(ctx context.Context, spanData SpanData) error
	Shutdown(ctx context.Context) error
}

type SpanData struct {
	TraceID    string                 `json:"traceId"`
	SpanID     string                 `json:"spanId"`
	Name       string                 `json:"name"`
	StartTime  time.Time              `json:"startTime"`
	EndTime    time.Time              `json:"endTime"`
	Duration   time.Duration          `json:"duration"`
	Attributes map[string]interface{} `json:"attributes"`
	Status     string                 `json:"status,omitempty"`
}
