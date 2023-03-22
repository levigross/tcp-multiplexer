package connection

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/levigross/logger/logger"
	"github.com/levigross/tcp-multiplexer/pkg/types"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

var log = logger.WithName("connection")

type Connection struct {
	ctx             context.Context
	isAuthenticated bool
	conn            quic.Connection

	// only used on the server
	streamMap sync.Map

	// only used on the client
	controlChannel chan *types.StreamInfo
}

func NewConnectionHandler(ctx context.Context, conn quic.Connection, isAuthenticated bool) *Connection {
	return &Connection{ctx: ctx, isAuthenticated: isAuthenticated, conn: conn, controlChannel: make(chan *types.StreamInfo)}
}

func (c *Connection) logErrorOnClose(closer io.Closer) {
	if err := closer.Close(); err != nil {
		log.Warn("Error in closing (this is a NOOP)", zap.Error(err))
	}
}

// TODO: these functions should be squashed together
func (c *Connection) copyStream(localConnection net.Conn, stream quic.Stream, wg *sync.WaitGroup) {
	defer wg.Done()
	defer c.logErrorOnClose(localConnection)
	defer c.logErrorOnClose(stream)
	n, err := io.Copy(localConnection, stream)
	log.Debug("Finished copying stream => localConnection", zap.Int64("bytesTransffered", n), zap.Error(err))
	streamErr, ok := errors.Unwrap(err).(*quic.StreamError)
	if ok { // TODO: Check if we have been canceled
		// we have a stream error
		log.Info("Stream has closed", zap.Error(streamErr))
		c.logErrorOnClose(localConnection)
		stream.CancelWrite(types.CancelAuthCode)
		return
	}
	if err != nil {
		log.Error("Got an error copying from quic stream => local port", zap.Error(err)) //TODO: Handle error
		return
	}
	log.Info("Copying finished for quic stream => local port")
}

func (c *Connection) copyLocalConnection(stream quic.Stream, localConnection net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer c.logErrorOnClose(localConnection)
	defer c.logErrorOnClose(stream)
	n, err := io.Copy(stream, localConnection)
	log.Debug("Finished copying localConnection => stream", zap.Int64("bytesTransffered", n), zap.Error(err))
	select {
	case <-stream.Context().Done():
		// we have been canceled so close the entire stream
		return
	default:
	}
	if err != nil {
		log.Error("Got an error copying from quic stream => local port", zap.Error(err)) //TODO: Handle error
		return
	}
	log.Info("Copying finished for local port => quic stream")
}
