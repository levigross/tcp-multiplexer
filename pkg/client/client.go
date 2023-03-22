package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/levigross/logger/logger"
	"github.com/levigross/tcp-multiplexer/pkg/quicutils"
	"github.com/levigross/tcp-multiplexer/pkg/types"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

var log = logger.WithName("client")

type Config struct {
	RemoteServer            string
	PortsToForward          []string
	IgnoreServerCertificate bool
	EnableQUICTracing       bool
	MaxIdleTimeout          time.Duration
	JWTFile                 string

	jwt *jwt.JSONWebToken

	controlChannel chan *types.StreamInfo
	quicConnection quic.Connection

	errChan   chan error
	doneSetup chan struct{}
}

func (c *Config) Run(ctx context.Context) (err error) {
	c.errChan = make(chan error, 1)
	c.doneSetup = make(chan struct{})
	c.controlChannel = make(chan *types.StreamInfo)

	if c.JWTFile != "" {
		f, err := os.ReadFile(c.JWTFile)
		if err != nil {
			log.Error("Unable to open JWT file", zap.Error(err))
			return err
		}
		c.jwt, err = jwt.ParseSigned(string(f))
		if err != nil {
			log.Error("Unable to parse JWT file", zap.Error(err))
			return err
		}
	}

	log.Debug("Dialing client")
	tlsConfig := &tls.Config{InsecureSkipVerify: c.IgnoreServerCertificate, NextProtos: []string{"quic"}}
	cq := &quic.Config{EnableDatagrams: true, MaxIdleTimeout: c.MaxIdleTimeout}
	if c.EnableQUICTracing {
		cq.Tracer = quicutils.Tracer
	}
	c.quicConnection, err = quic.DialAddrContext(ctx, c.RemoteServer, tlsConfig, cq)
	if err != nil {
		log.Error("Unable to dial server", zap.Error(err))
		return err
	}
	log.Debug("Connected to client")
	stream, err := c.quicConnection.OpenStreamSync(ctx)
	if err != nil {
		log.Error("Unable to open stream", zap.Error(err))
		return err
	}
	if c.jwt != nil { // we pass in an auth token
		jwtBytes, err := json.Marshal(types.Auth{JWT: c.jwt})
		if err != nil {
			log.Error("Unable to marshal JWT", zap.Error(err))
			return err
		}
		am := types.ControlMessage{MessageType: types.AuthMessage, Message: jwtBytes}
		ok, err := c.sendControlMessage(am, stream)
		if err != nil {
			return err
		}
		if !ok {
			log.Error("Auth Failed -- see server for details")
			return fmt.Errorf("authentication failure")
		}
	}
	go c.handleControlChannel(stream)
	for _, port := range c.PortsToForward {
		go c.handleConnection(port)
	}

	close(c.doneSetup)
	// todo handle graceful shutdown
	select {
	case err := <-c.errChan:
		return err
	}
}

func (c *Config) sendControlMessage(cm types.ControlMessage, stream quic.Stream) (success bool, err error) {
	streamEncoder := json.NewEncoder(stream)
	if err = streamEncoder.Encode(cm); err != nil {
		log.Error("Unable to encode object to stream", zap.Any("controlMessage", cm), zap.Error(err))
		return
	}

	buf := make([]byte, 2)
	if _, err = stream.Read(buf); err != nil {
		log.Error("Unable to read response from server", zap.Error(err))
		return
	}
	return bytes.Equal(buf, []byte(types.OK)), nil
}

func (c *Config) handleControlChannel(stream quic.Stream) {
	for {
		select {
		case si := <-c.controlChannel:
			log.Debug("Got a new connection", zap.Any("streamInfo", si))
			b, err := json.Marshal(si)
			if err != nil {
				log.Error("Error encoding JSON to send on control stream", zap.Error(err))
				c.errChan <- err
				return
			}
			cm := types.ControlMessage{MessageType: types.StreamInfoMessage, Message: b}
			ok, err := c.sendControlMessage(cm, stream)
			if err != nil {
				c.errChan <- err
				return
			}
			if !ok {
				log.Warn("Connection wasn't ACKed by the other side, this may not work")
			}
			log.Debug("Connection acked by the other side")
			si.Done()
		}
	}
}

func (c *Config) handleConnection(port string) {
	l, err := net.Listen("tcp", ":"+port) //todo this should be user configurable
	if err != nil {
		log.Error("Unable to listen on port", zap.String("port", port), zap.Error(err))
		c.errChan <- err
		return
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Error("Unable to accept connection on port", zap.String("port", port), zap.Error(err))
			c.errChan <- err
			return
		}
		log.Debug("New local connection received")
		stream, err := c.quicConnection.OpenStream()
		if err != nil {
			log.Error("Unable open stream", zap.Error(err))
			c.errChan <- err
			return
		}
		ts := types.NewStreamInfo(stream.StreamID(), port)
		c.controlChannel <- ts
		ts.Wait()
		log.Debug("Server has stream information")
		wg := sync.WaitGroup{}
		wg.Add(2)
		go func() {
			defer wg.Done()
			n, err := io.Copy(stream, conn)
			select {
			case <-stream.Context().Done():
				// we have been canceled
				stream.Close()
				conn.Close()
				return
			default:
			}
			if err != nil {
				log.Error("Error in sending conn => stream", zap.Error(err))
				c.errChan <- err
				return
			}
			log.Debug("Connection from conn => stream finished", zap.Int64("bytesTransferred", n))
			time.AfterFunc(time.Second, func() { stream.CancelRead(123) }) // should we even wait?
		}()

		go func() {
			defer wg.Done()
			n, err := io.Copy(conn, stream)
			streamErr, ok := errors.Unwrap(err).(*quic.StreamError)
			if ok {
				log.Debug("Connection from stream => conn finished", zap.Int64("bytesTransferred", n), zap.Error(streamErr))
				time.AfterFunc(time.Second, func() {
					conn.Close()
					stream.CancelWrite(123)
				}) // should we even wait?
				return
			}
			if err != nil {
				log.Error("Error in sending stream => conn", zap.Error(err))
				c.errChan <- err
				return
			}
		}()
		wg.Wait()
		stream.Close()
		conn.Close()
		log.Debug("All connections closed")
	}
}
