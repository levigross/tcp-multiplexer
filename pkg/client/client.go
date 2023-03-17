package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"

	"github.com/levigross/logger/logger"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

var log = logger.WithName("client")

type Config struct {
	RemoteServer            string
	PortsToForward          []string
	IgnoreServerCertificate bool

	errChan   chan error
	doneSetup chan struct{}
}

func (c *Config) Run(ctx context.Context) error {
	c.errChan = make(chan error, 1)
	c.doneSetup = make(chan struct{})
	log.Debug("Dialing client")
	tlsConfig := &tls.Config{InsecureSkipVerify: c.IgnoreServerCertificate, NextProtos: []string{"quic"}}
	conn, err := quic.DialAddrContext(ctx, c.RemoteServer, tlsConfig, &quic.Config{EnableDatagrams: true})
	if err != nil {
		log.Error("Unable to dial server", zap.Error(err))
		return err
	}
	log.Debug("Connected to client")
	portsToForward := map[quic.StreamID]string{}
	for _, port := range c.PortsToForward {
		stream, err := conn.OpenStream()
		if err != nil {
			log.Error("Unable to open stream to server", zap.Error(err))
			return err
		}
		portsToForward[stream.StreamID()] = port
		go c.handleStream(stream, port)
	}
	jsonBytes, err := json.Marshal(portsToForward)
	if err != nil {
		log.Error("unable to marshal portsToForward map", zap.Error(err))
		return err
	}

	if err := conn.SendMessage(jsonBytes); err != nil {
		log.Error("Unable to send inital message of how to forward the ports", zap.Error(err))
		return err
	}

	close(c.doneSetup)
	// todo handle graceful shutdown
	select {
	case err := <-c.errChan:
		return err
	}
}

func (c *Config) handleStream(stream quic.Stream, port string) {
	<-c.doneSetup
	l, err := net.Listen("tcp", ":"+port)
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

		go func() {
			_, err := io.Copy(conn, stream)
			if err != nil {
				log.Error("unable to copy server => client", zap.Error(err))
				c.errChan <- err
			}
		}()

		go func() {
			_, err := io.Copy(stream, conn)
			if err != nil {
				log.Error("unable to copy client => server", zap.Error(err))
				c.errChan <- err
			}
		}()
	}
}
