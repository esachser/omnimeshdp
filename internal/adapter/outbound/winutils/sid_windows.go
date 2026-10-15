//go:build windows

package winutils

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// GetUserSIDFromPID queries the Windows Security Identifier (SID) of the owner of a given process ID.
func GetUserSIDFromPID(pid uint32) (string, error) {
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("OpenProcess PID %d failed: %w", pid, err)
	}
	defer windows.CloseHandle(hProcess)

	var token windows.Token
	err = windows.OpenProcessToken(hProcess, windows.TOKEN_QUERY, &token)
	if err != nil {
		return "", fmt.Errorf("OpenProcessToken PID %d failed: %w", pid, err)
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("GetTokenUser PID %d failed: %w", pid, err)
	}

	sidStr := tokenUser.User.Sid.String()
	return sidStr, nil
}
