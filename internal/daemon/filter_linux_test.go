//go:build linux

package daemon

import (
	"errors"
	"os"
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
			require.ErrorIs(t, err, os.ErrNotExist)
			// A reflection-based Nil assertion accepts an interface containing a
			// nil concrete pointer. Direct comparison is the regression boundary:
			// the pre-fix adapter returned a non-nil Filter interface here.
			if got != nil {
				t.Fatalf("error adapter exposed a typed-nil filter interface: %#v", got)
			}
		})
	}
}

func TestCreateFilterConstructorAdaptersPreserveOnlyRealPartials(t *testing.T) {
	primary := errors.New("construction failed")
	tests := []struct {
		name     string
		nilCase  func() (filter.Filter, error)
		nilNil   func() (filter.Filter, error)
		partCase func() (filter.Filter, error)
	}{
		{
			name:    "cgroup",
			nilCase: func() (filter.Filter, error) { return cgroupConstructorResult(nil, primary) },
			nilNil:  func() (filter.Filter, error) { return cgroupConstructorResult(nil, nil) },
			partCase: func() (filter.Filter, error) {
				return cgroupConstructorResult(&filter.CgroupFilter{}, primary)
			},
		},
		{
			name:    "tc",
			nilCase: func() (filter.Filter, error) { return tcConstructorResult(nil, primary) },
			nilNil:  func() (filter.Filter, error) { return tcConstructorResult(nil, nil) },
			partCase: func() (filter.Filter, error) {
				return tcConstructorResult(&filter.TCFilter{}, primary)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.nilCase()
			require.ErrorIs(t, err, primary)
			if got != nil {
				t.Fatalf("nil concrete error became typed-nil interface: %#v", got)
			}
			got, err = tt.nilNil()
			require.NoError(t, err)
			if got != nil {
				t.Fatalf("nil concrete success became typed-nil interface: %#v", got)
			}

			got, err = tt.partCase()
			require.ErrorIs(t, err, primary)
			require.NotNil(t, got, "real partial ownership must survive interface adaptation")
		})
	}
}
