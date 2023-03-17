package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"

	"github.com/levigross/logger/logger"
	"github.com/levigross/tcp-multiplexer/pkg/crypto"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

var log = logger.WithName("server")

type Config struct {
	KeyFile    string
	CertFile   string
	ListenAddr string

	errChan chan error
	done    chan struct{}
}

func (c *Config) StartQUICServer(ctx context.Context) (err error) {
	c.errChan = make(chan error, 1)
	c.done = make(chan struct{})

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	ctx, cancler := context.WithCancel(ctx)
	defer cancler()

	var tlsConfig *tls.Config
	switch {
	case c.KeyFile == "", c.CertFile == "":
		tlsConfig, err = crypto.GenerateTLSConfigInMemory()
	default:
		tlsConfig, err = crypto.GenerateTLSConfigFromFile(c.KeyFile, c.CertFile)
	}
	if err != nil {
		return
	}

	go func() { c.errChan <- c.serveQUIC(ctx, tlsConfig) }()

	// todo clean up nicely
	select {
	case err := <-c.errChan:
		close(c.done)
		return err
	case <-signalChan:
		log.Info("Got SIGINT gracefully closing")
		close(c.done)
	}
	return nil
}

func (c *Config) serveQUIC(ctx context.Context, tlsConfig *tls.Config) error {
	// todo change this to allow for connection IDS to be more meaningful
	l, err := quic.ListenAddr(c.ListenAddr, tlsConfig, &quic.Config{EnableDatagrams: true})
	if err != nil {
		log.Error("Unable to create QUIC listener", zap.Error(err))
		return err
	}

	log.Info("Listening for QUIC connections", zap.String("address", l.Addr().String()))

	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			log.Error("Unable to accept QUIC connection", zap.Error(err))
			return err
		}
		log.Debug("Got QUIC connection", zap.String("remoteAddr", conn.RemoteAddr().String()))
		portList, err := conn.ReceiveMessage()
		if err != nil {
			log.Error("Unable to read portList message from client", zap.Error(err))
			return err
		}
		// The format of this map is streamID => port //todo add more than a 1:1 mapping
		portsToForward := map[quic.StreamID]string{}
		if err := json.Unmarshal(portList, &portsToForward); err != nil {
			log.Error("Unable to unmarshal port list", zap.Error(err))
			return err
		}
		log.Debug("Forwarding ports based map from client", zap.Any("portsToForward", portsToForward))
		// We will just use the count and iterate through the IDs
		for range portsToForward {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				log.Error("Unable to accept stream from client", zap.Error(err))
				return err
			}
			go c.handleStream(stream, portsToForward[stream.StreamID()])
		}
		log.Info("Finished Setting Up connections")
		<-c.done
		if err := l.Close(); err != nil {
			log.Error("Unable to close connections", zap.Error(err))
		}
		return nil // Ignore the error because we are exiting anyways
	}
}

// todo use context to cancel everything
func (c *Config) handleStream(stream quic.Stream, port string) {
	conn, err := net.Dial("tcp", fmt.Sprintf(":%v", port))
	if err != nil {
		log.Error("Unable to dial out to local port", zap.String("port", port), zap.Error(err))
		c.errChan <- err
		return
	}
	log.Debug("Connected to ", zap.Stringer("remoteAddr", conn.RemoteAddr()), zap.Any("streamID", stream.StreamID()))
	go func() {
		for {
			_, err := io.Copy(conn, stream)
			if err != nil {
				log.Error("unable to copy client => server", zap.Error(err))
				c.errChan <- err
				return
			}
		}
	}()

	go func() {
		for {
			_, err := io.Copy(stream, conn)
			if err != nil {
				log.Error("unable to copy server => client", zap.Error(err))
				c.errChan <- err
				return
			}
		}
	}()

	<-c.done
	log.Debug("Closing stream", zap.Error(stream.Close()), zap.Any("streamID", stream.StreamID()))
}
