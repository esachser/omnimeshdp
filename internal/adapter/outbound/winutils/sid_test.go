package winutils_test

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/esachser/omnimeshdp/internal/adapter/outbound/winutils"
)

func TestGetUserSIDFromPID(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping Windows-specific test")
	}

	pid := uint32(os.Getpid())
	sid, err := winutils.GetUserSIDFromPID(pid)
	if err != nil {
		t.Fatalf("GetUserSIDFromPID failed for current process %d: %v", pid, err)
	}

	if !strings.HasPrefix(sid, "S-1-") {
		t.Fatalf("expected valid SID starting with 'S-1-', got '%s'", sid)
	}
}
