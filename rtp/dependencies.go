package rtp

import (
	"context"
	"gitlab.com/permtr.com/check-service/storage"
)

type (
	StorageRTP interface {
		CreateRtpPacket(ctx context.Context, rtPacket storage.RtpPacket) error
	}
)
