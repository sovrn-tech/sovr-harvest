package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// harden keeps key material out of swap and core dumps. The process holds a
// derived private key for only a short time. That key must leave no trace.
func harden() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE): %w", err)
	}
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		return fmt.Errorf("mlockall: %w (raise LimitMEMLOCK or grant CAP_IPC_LOCK)", err)
	}
	return nil
}
