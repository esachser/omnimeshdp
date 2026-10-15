package model_test

import (
	"testing"
	"unsafe"

	"github.com/esachser/omnimeshdp/internal/domain/model"
)

func TestStructSizes(t *testing.T) {
	proxyConfigSize := unsafe.Sizeof(model.ProxyConfig{})
	if proxyConfigSize != 24 {
		t.Fatalf("expected ProxyConfig size to be 24 bytes, got %d", proxyConfigSize)
	}

	packetInfoSize := unsafe.Sizeof(model.OriginalPacketInfo{})
	if packetInfoSize != 16 {
		t.Fatalf("expected OriginalPacketInfo size to be 16 bytes, got %d", packetInfoSize)
	}
}
