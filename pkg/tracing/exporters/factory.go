// Copyright The containerd Authors.
// SPDX-License-Identifier: Apache-2.0

package exporters

import "fmt"

func CreateExporter(exporterType, endpoint string, options map[string]interface{}) (Exporter, error) {
	switch exporterType {
	case "file":
		return NewFileExporter(endpoint, options)
	case "zipkin":
		return NewZipkinExporter(endpoint, options)
	case "noop":
		return NewNoopExporter(), nil
	default:
		return nil, fmt.Errorf("unknown exporter type: %s", exporterType)
	}
}
