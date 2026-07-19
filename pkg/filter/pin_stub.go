//go:build !linux

package filter

import "fmt"

// InspectPinnedSchema requires bpffs and is only meaningful on Linux.
func InspectPinnedSchema(string) (PinnedSchemaState, error) {
	return PinnedSchemaUncommitted, fmt.Errorf("pinned BPF schemas are only supported on linux")
}
