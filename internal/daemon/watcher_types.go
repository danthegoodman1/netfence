package daemon

// watchKind keeps tokens for different target types distinct even if a
// caller accidentally reuses the same target string.
type watchKind uint8

const (
	watchKindInterface watchKind = iota + 1
	watchKindCgroup
)

// watchToken is the opaque identity of one specific watch registration.
// Generations are allocated by TargetWatcher and are never inferred from a
// target name: a delayed removal or unwatch for an older generation must be
// harmless after the same name/path is watched again.
type watchToken struct {
	generation uint64
	target     string
	kind       watchKind
	// identity is the kernel object identity the filter and watch both own:
	// ifindex for interfaces, cgroup id/inode for cgroups.
	identity uint64
}

func (t watchToken) valid() bool {
	return t.generation != 0
}
