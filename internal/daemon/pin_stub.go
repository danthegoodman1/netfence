//go:build !linux

package daemon

// ensureBPFPinRoot is a no-op off Linux: the stub filter cannot enforce (or
// pin) anything anyway, and failing here would stop `netfenced start` from
// running at all in non-Linux dev environments under the default
// filter.bpf_pin_dir. Restore then simply finds no pin dirs and takes the
// recreate path.
func ensureBPFPinRoot(string) error {
	return nil
}
