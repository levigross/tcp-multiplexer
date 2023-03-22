package connection

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/levigross/logger/logger"
	"github.com/levigross/tcp-multiplexer/pkg/quicutils"
	"github.com/levigross/tcp-multiplexer/pkg/types"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

var log = logger.WithName("connection")

type Connection struct {
	ctx             context.Context
	isAuthenticated bool
	conn            quic.Connection

	streamMap sync.Map
}

func NewConnectionHandler(ctx context.Context, conn quic.Connection, isAuthenticated bool) *Connection {
	return &Connection{ctx: ctx, isAuthenticated: isAuthenticated, conn: conn}
}

func (c *Connection) HandleServerControlStream(stream quic.Stream) {
	for {
		_, err := quicutils.ReceiveControlMessage(stream, c.populateStreamInfo)
		if err != nil { // TODO handle error
			return
		}
	}
}

func (c *Connection) populateStreamInfo(cm types.ControlMessage) (bool, error) {
	switch cm.MessageType {
	case types.StreamInfoMessage: // These are the only messages we should be getting on a general basis
		var si *types.StreamInfo
		if err := json.Unmarshal(cm.Message, &si); err != nil {
			log.Error("Unable to decode JSON ", zap.Error(err))
			return false, err
		}
		c.streamMap.Store(si.QuicStreamID, si.Port)
	default:
		log.Error("Stream info function called with unknown message type", zap.Any("controlMessage", cm))
		return false, fmt.Errorf("unknown message type %v", cm)
	}
	return true, nil
}
