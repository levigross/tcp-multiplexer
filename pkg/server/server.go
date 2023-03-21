package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/levigross/logger/logger"
	"github.com/levigross/tcp-multiplexer/pkg/crypto"
	"github.com/levigross/tcp-multiplexer/pkg/types"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

var log = logger.WithName("server")

type Config struct {
	KeyFile    string
	CertFile   string
	ListenAddr string

	streamMap sync.Map

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
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			log.Error("Error in accepting stream", zap.Error(err))
			return err
		}
		go c.handleControlStream(stream)

		for {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				log.Error("Error in accepting stream", zap.Error(err))
				return err
			}
			port, ok := c.streamMap.Load(stream.StreamID())
			if !ok {
				log.Error("Expected to find stream in stream map", zap.Any("streamID", stream.StreamID()))
				return fmt.Errorf("unknown stream id %v", stream.StreamID())
			}
			go c.handleStream(stream, port.(string))
		}
	}
}

func (c *Config) handleControlStream(stream quic.Stream) {
	jsonDecoder := json.NewDecoder(stream)
	for {
		var si types.StreamInfo
		if err := jsonDecoder.Decode(&si); err != nil {
			log.Error("Unable to decode JSON ", zap.Error(err))
			c.errChan <- err
			return
		}
		if _, err := stream.Write([]byte("OK")); err != nil {
			log.Error("Unable to write response to client", zap.Error(err))
			c.errChan <- err
			return
		}

		c.streamMap.Store(si.QuicStreamID, si.Port)
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
	wg := sync.WaitGroup{}
	wg.Add(2)
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
			log.Error("unable to copy client => server", zap.Error(err))
			c.errChan <- err
			return
		}
		conn.Close()
		log.Info("Ending stream => conn")
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, conn)
		log.Info("Ending conn => stream")
		select {
		case <-stream.Context().Done():
			// we have been canceled
			stream.Close()
			conn.Close()
			return
		default:
		}
		if err != nil {
			log.Error("unable to copy server => client", zap.Error(err))
			c.errChan <- err
			return
		}
		stream.CancelWrite(123)
	}()
	wg.Wait()
	log.Debug("Closing stream", zap.Any("streamID", stream.StreamID()))
	conn.Close()
	stream.Close()

}
