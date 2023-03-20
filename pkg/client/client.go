package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/levigross/logger/logger"
	"github.com/levigross/tcp-multiplexer/pkg/types"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
	"go.uber.org/zap"
)

var log = logger.WithName("client")

type Config struct {
	RemoteServer            string
	PortsToForward          []string
	IgnoreServerCertificate bool

	controlChannel chan *types.StreamInfo
	quicConnection quic.Connection

	errChan   chan error
	doneSetup chan struct{}
}

func (c *Config) Run(ctx context.Context) error {
	c.errChan = make(chan error, 1)
	c.doneSetup = make(chan struct{})
	c.controlChannel = make(chan *types.StreamInfo)

	log.Debug("Dialing client")
	tlsConfig := &tls.Config{InsecureSkipVerify: c.IgnoreServerCertificate, NextProtos: []string{"quic"}}
	tracer := qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
		filename := fmt.Sprintf("client_%x.qlog", connID)
		f, err := os.Create(filename)
		if err != nil {
			log.Error("Unable to create file for tracing", zap.Error(err))
		}
		log.Debug("Creating qlog file", zap.String("qlogFile", filename))
		return f
	})
	var err error
	c.quicConnection, err = quic.DialAddrContext(ctx, c.RemoteServer, tlsConfig, &quic.Config{EnableDatagrams: true, Tracer: tracer})
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
	go c.handleControlChannel(stream)
	for _, port := range c.PortsToForward {
		go c.handleConnection(port)
	}
	// portsToForward := []{}
	// portsToForward := map[quic.StreamID]string{}
	// for _, port := range c.PortsToForward {
	// 	stream, err := conn.OpenStream()
	// 	if err != nil {
	// 		log.Error("Unable to open stream to server", zap.Error(err))
	// 		return err
	// 	}
	// 	portsToForward[stream.StreamID()] = port
	// 	go c.handleStream(stream, port)
	// }
	// jsonBytes, err := json.Marshal(portsToForward)
	// if err != nil {
	// 	log.Error("unable to marshal portsToForward map", zap.Error(err))
	// 	return err
	// }

	// if err := conn.SendMessage(jsonBytes); err != nil {
	// 	log.Error("Unable to send inital message of how to forward the ports", zap.Error(err))
	// 	return err
	// }

	close(c.doneSetup)
	// todo handle graceful shutdown
	select {
	case err := <-c.errChan:
		return err
	}
}

func (c *Config) handleControlChannel(stream quic.Stream) {
	streamEncoder := json.NewEncoder(stream)
	for {
		select {
		case si := <-c.controlChannel:
			if err := streamEncoder.Encode(si); err != nil {
				log.Error("Error encoding JSON to send on control stream", zap.Error(err))
				c.errChan <- err
				return
			}
			buf := make([]byte, 2)
			if _, err := stream.Read(buf); err != nil {
				log.Error("Unable to read response from server", zap.Error(err))
				c.errChan <- err
				return
			}
			if !bytes.Equal(buf, []byte("OK")) {
				log.Warn("Didn't get back heathly bytes", zap.Binary("returnBytes", buf))
			}
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
		stream, err := c.quicConnection.OpenStream()
		if err != nil {
			log.Error("Unable open stream", zap.Error(err))
			c.errChan <- err
			return
		}
		ts := types.NewStreamInfo(stream.StreamID(), port)
		c.controlChannel <- ts
		ts.Wait()
		done := make(chan struct{})
		go func() {
			n, err := io.Copy(stream, conn)
			if err != nil {
				log.Error("Error in sending conn => stream", zap.Error(err))
				c.errChan <- err
				return
			}
			log.Debug("Connection from conn => stream finished", zap.Int64("bytesTransferred", n))
			done <- struct{}{}
		}()

		go func() {
			n, err := io.Copy(conn, stream)
			if err != nil {
				log.Error("Error in sending stream => conn", zap.Error(err))
				c.errChan <- err
				return
			}
			log.Debug("Connection from stream => conn finished", zap.Int64("bytesTransferred", n))
			done <- struct{}{}
		}()
		<-done
		<-done
		stream.Close()
		conn.Close()
	}
}
