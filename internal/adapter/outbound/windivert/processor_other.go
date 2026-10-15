//go:build !windows

package windivert

import (
	"context"
	"errors"
	"net"

	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

var _ outbound.PacketProcessor = (*WindivertProcessor)(nil)

type WindivertProcessor struct{}

func NewWindivertProcessor(filter string) (*WindivertProcessor, error) {
	return nil, errors.New("WinDivert is only supported on Windows")
}

func (w *WindivertProcessor) Run(ctx context.Context) error {
	return errors.New("WinDivert is only supported on Windows")
}

func (w *WindivertProcessor) GetIdentityByPID(pid uint64) (string, bool) {
	return "", false
}

func (w *WindivertProcessor) GetOriginalPacketInfo(addr net.Addr, socket uintptr) (*model.OriginalPacketInfo, error) {
	return nil, errors.New("WinDivert is only supported on Windows")
}

func (w *WindivertProcessor) Close() error {
	return nil
}
