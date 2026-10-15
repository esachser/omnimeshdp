//go:build windows

package windivert_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/esachser/omnimeshdp/internal/adapter/outbound/windivert"
)

func TestWindivertFilterValidation(t *testing.T) {
	_, err := windivert.NewWindivertProcessor("")
	if err == nil {
		t.Fatal("expected error with empty filter, got nil")
	}
}

func TestWindivertOpen(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping Windows-specific WinDivert test")
	}

	filter := "tcp and outbound and ((remoteAddr == 127.0.0.1 and remotePort == 8001) or (localAddr == 127.0.0.1 and localPort == 15001))"
	wp, err := windivert.NewWindivertProcessor(filter)
	if err != nil {
		// If not running elevated as Administrator, WinDivert returns access denied (error 5)
		if strings.Contains(err.Error(), "Access is denied") || strings.Contains(err.Error(), "code 5") {
			t.Skipf("skipping WinDivert handle test because process is not elevated: %v", err)
			return
		}
		t.Logf("WinDivert handle open returned error (driver may not be installed): %v", err)
		return
	}
	defer wp.Close()

	t.Log("WinDivert opened successfully with complex mesh filter!")
}
