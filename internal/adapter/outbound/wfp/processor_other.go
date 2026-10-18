//go:build !windows

package wfp

import (
	"context"
	"errors"
	"net"

	"github.com/esachser/omnimeshdp/internal/domain/model"
	"github.com/esachser/omnimeshdp/internal/port/outbound"
)

var _ outbound.PacketProcessor = (*WfpProcessor)(nil)

type WfpProcessor struct{}

func NewWfpProcessor(config []model.ProxyConfig) (*WfpProcessor, error) {
	return nil, errors.New("WFP is only supported on Windows")
}

func (w *WfpProcessor) Run(ctx context.Context) error {
	return errors.New("WFP is only supported on Windows")
}

func (w *WfpProcessor) GetIdentityByPID(pid uint64) (string, bool) {
	return "", false
}

func (w *WfpProcessor) GetOriginalPacketInfo(addr net.Addr, socket uintptr) (*model.OriginalPacketInfo, error) {
	return nil, errors.New("WFP is only supported on Windows")
}

func (w *WfpProcessor) Close() error {
	return nil
}
