//go:build !windows

package winutils

import "errors"

// GetUserSIDFromPID is a stub on non-Windows platforms.
func GetUserSIDFromPID(pid uint32) (string, error) {
	return "", errors.New("GetUserSIDFromPID is only supported on Windows")
}
