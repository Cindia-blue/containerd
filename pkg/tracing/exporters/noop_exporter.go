package exporters

import "context"

// noopExporter implements Exporter but performs no operations.
type noopExporter struct{}

func NewNoopExporter() Exporter {
	return &noopExporter{}
}

func (n *noopExporter) ExportSpan(ctx context.Context, spanData SpanData) error {
	return nil
}

func (n *noopExporter) Shutdown(ctx context.Context) error {
	return nil
}
