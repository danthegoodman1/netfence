//go:build !linux

package cmd

import (
	"fmt"
	"os"
)

func acquireDaemonLock(string) (*os.File, error) {
	return nil, fmt.Errorf("the netfence daemon requires Linux")
}
