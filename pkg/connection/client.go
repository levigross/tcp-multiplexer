package connection

import (
	"encoding/json"
	"net"
	"sync"

	"github.com/levigross/tcp-multiplexer/pkg/quicutils"
	"github.com/levigross/tcp-multiplexer/pkg/types"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

func (c *Connection) ClientHandler(controlStream quic.Stream, portsToForward []string) {
	go c.handleClientControlChannel(controlStream)
	for _, port := range portsToForward {
		go c.createListener(port)
	}
}

func (c *Connection) handleClientControlChannel(controlStream quic.Stream) {
	for si := range c.controlChannel {
		log.Debug("Got a new connection", zap.Any("streamInfo", si))
		siBytes, err := json.Marshal(si)
		if err != nil {
			log.Error("Error encoding JSON to send on control stream", zap.Error(err))
			continue // todo handle the error, this "should" never happen
		}
		controlMessage := types.ControlMessage{MessageType: types.StreamInfoMessage, Message: siBytes}
		_, err = quicutils.SendControlMessage(controlMessage, controlStream) // Ignore the OK because this isn't auth
		if err != nil {
			log.Error("Error in sending control message", zap.Error(err))
		}
		si.Done()
	}
}

func (c *Connection) createListener(port string) {
	localListener, err := net.Listen("tcp", ":"+port) // todo allow for picking ipv4/6 and interface
	if err != nil {                                   // TODO: handle this error better
		log.Error("Unable to listen on port", zap.String("port", port), zap.Error(err)) // this is a bad error and we should fail if this happens
		return
	}
	log = log.With(zap.Stringer("localListener", localListener.Addr()))
	for {
		localConnection, err := localListener.Accept()
		if err != nil {
			log.Error("Unable to accept connection on port", zap.Error(err))
			return
		}
		localLogger := log.With(zap.Stringer("localAddr", localConnection.LocalAddr()), zap.Stringer("remoteAddr", localConnection.RemoteAddr()))
		localLogger.Debug("New local connection received")
		stream, err := c.conn.OpenStream()
		if err != nil { // TODO: This is a fatal error
			log.Error("Unable open stream", zap.Error(err))
			return
		}
		localLogger = localLogger.With(zap.Any("streamID", stream.StreamID()))
		localLogger.Debug("QUIC stream created")
		si := types.NewStreamInfo(stream.StreamID(), port)
		c.controlChannel <- si
		si.Wait()
		wg := &sync.WaitGroup{}
		wg.Add(2)
		go c.copyStream(localConnection, stream, wg)
		go c.copyLocalConnection(stream, localConnection, wg)
		wg.Wait()
		localLogger.Debug("Stream and local connection closed")
	}
}
