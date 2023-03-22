package connection

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"

	"github.com/levigross/tcp-multiplexer/pkg/quicutils"
	"github.com/levigross/tcp-multiplexer/pkg/types"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

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

// TODO: use more context
func (c *Connection) handleServerStream(stream quic.Stream, port string) {
	localConnection, err := net.Dial("tcp", fmt.Sprintf(":%v", port)) // todo: allow the user to choose the interface
	if err != nil {
		log.Error("Unable to dial out to local port", zap.String("port", port), zap.Error(err))
		// c.errChan <- err
		return
	}
	log.Debug("Connected to ", zap.Stringer("remoteAddr", localConnection.RemoteAddr()), zap.Any("streamID", stream.StreamID()))
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go c.copyStream(localConnection, stream, wg)
	go c.copyLocalConnection(stream, localConnection, wg)
	wg.Wait()
	log.Debug("Stream and local connection closed")
}

func (c *Connection) ConnectionHandler() {
	for {
		stream, err := c.conn.AcceptStream(c.ctx)
		if err != nil {
			log.Error("Error in accepting stream", zap.Error(err))
			continue
			// return err
		}
		port, ok := c.streamMap.Load(stream.StreamID())
		if !ok {
			log.Error("Expected to find stream in stream map", zap.Any("streamID", stream.StreamID()))
			continue
			// return fmt.Errorf("unknown stream id %v", stream.StreamID())
		}
		go c.handleServerStream(stream, port.(string))
	}
}
