//go:build linux

package daemon

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

func TestLoadPinnedFilterErrorReturnsLiteralNilInterface(t *testing.T) {
	for _, attachType := range []apiv1.AttachmentType{
		apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP,
		apiv1.AttachmentType_ATTACHMENT_TYPE_TC,
	} {
		t.Run(attachType.String(), func(t *testing.T) {
			got, err := loadPinnedFilter(
				filepath.Join(t.TempDir(), "missing-pins"),
				"unused-target",
				attachType,
				apiv1.TcDirection_TC_DIRECTION_EGRESS,
			)
			require.Error(t, err)
			require.ErrorIs(t, err, filter.ErrPinnedStateInvalid)
			// A reflection-based Nil assertion accepts an interface containing a
			// nil concrete pointer. Direct comparison is the regression boundary:
			// the pre-fix adapter returned a non-nil Filter interface here.
			if got != nil {
				t.Fatalf("error adapter exposed a typed-nil filter interface: %#v", got)
			}
		})
	}
}
