package utils

import (
	"fmt"
	"github.com/facebookgo/pidfile"
	"os"
	"syscall"
)

func CheckPid(pidfileName string) error {
	pidfile.SetPidfilePath(pidfileName)
	pid, err := pidfile.Read()
	if err == nil && pid > 0 {
		process, err := os.FindProcess(pid)
		if err != nil {
			return fmt.Errorf("Failed to find process: %v", err)
		} else {
			err := process.Signal(syscall.Signal(0))
			if err == nil {
				return fmt.Errorf("Perhaps another lachesis is already running with pid %d", pid)
			}
		}
	}

	if err := pidfile.Write(); err != nil {
		return fmt.Errorf("Error writing into pidfile: %v", err)
	}

	return nil
}