package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"time"

	"github.com/levigross/logger/logger"
	"github.com/levigross/tcp-multiplexer/pkg/connection"
	"github.com/levigross/tcp-multiplexer/pkg/crypto"
	"github.com/levigross/tcp-multiplexer/pkg/jwtutil"
	"github.com/levigross/tcp-multiplexer/pkg/quicutils"
	"github.com/levigross/tcp-multiplexer/pkg/types"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

var log = logger.WithName("server")

type Config struct {
	KeyFile           string
	CertFile          string
	ListenAddr        string
	EnableQUICTracing bool
	MaxIdleTimeout    time.Duration
	JWKUrl            string
	RequireAuth       bool
	AuthMatchRegex    string

	validationRegex *regexp.Regexp
	auth            *jwtutil.Auth
	tlsConfig       *tls.Config

	streamMap sync.Map

	errChan chan error
	done    chan struct{}
}

func (c *Config) StartQUICServer(ctx context.Context) (err error) {
	c.errChan = make(chan error, 1)
	c.done = make(chan struct{})

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	ctx, cancler := context.WithCancel(ctx) // todo I need to do more with this context
	defer cancler()

	if err := c.createTLSConfig(); err != nil {
		return err
	}

	if c.RequireAuth {
		if err := c.initAuthSubSystem(); err != nil {
			return err
		}

	}

	go func() { c.errChan <- c.serveQUIC(ctx, c.tlsConfig) }()

	// todo clean up nicely using context
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

func (c *Config) initAuthSubSystem() (err error) {
	c.validationRegex, err = regexp.Compile(c.AuthMatchRegex)
	if err != nil {
		log.Error("Unable to compile auth regex")
		return
	}

	resp, err := http.Get(c.JWKUrl) // We should force TLS
	if err != nil {
		log.Error("Unable to fetch JWK url", zap.Error(err))
		return err
	}
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("Unable to read JWK request body", zap.Error(err))
		return err
	}
	resp.Body.Close()
	c.auth, err = jwtutil.NewAuth(respBytes)
	if err != nil {
		return err
	}
	return
}

func (c *Config) createTLSConfig() (err error) {
	switch {
	case c.KeyFile == "", c.CertFile == "":
		c.tlsConfig, err = crypto.GenerateTLSConfigInMemory()
	default:
		c.tlsConfig, err = crypto.GenerateTLSConfigFromFile(c.KeyFile, c.CertFile)
	}
	return
}

func (c *Config) serveQUIC(ctx context.Context, tlsConfig *tls.Config) error {
	// todo change this to allow for connection IDS to be more meaningful
	qc := &quic.Config{EnableDatagrams: true, MaxIdleTimeout: c.MaxIdleTimeout}
	if c.EnableQUICTracing {
		qc.Tracer = quicutils.Tracer
	}
	log.Debug("Quic configured", zap.Any("quicConfig", qc))

	quicListener, err := quic.ListenAddr(c.ListenAddr, tlsConfig, qc)
	if err != nil {
		log.Error("Unable to create QUIC listener", zap.Error(err))
		return err
	}

	log.Info("Listening for QUIC connections", zap.String("address", quicListener.Addr().String()))

	for {
		conn, err := quicListener.Accept(ctx)
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
		authenticated := false
		if c.RequireAuth {
			ok, err := quicutils.ReceiveControlMessage(stream, c.validateAuthentication)
			if err != nil {
				conn.CloseWithError(quic.ApplicationErrorCode(types.AuthError), err.Error())
				continue
			}
			if !ok {
				conn.CloseWithError(quic.ApplicationErrorCode(types.BadAuth), err.Error())
				continue
			}
			log.Info("Authentication Successful")
			authenticated = true
		}
		ch := connection.NewConnectionHandler(ctx, conn, authenticated)
		go ch.HandleServerControlStream(stream)
		for { // todo refactor to handle more than one client
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

func (c *Config) validateAuthentication(cm types.ControlMessage) (ok bool, err error) {
	switch cm.MessageType {
	case types.AuthMessage: // These are the only messages we should be getting on a general basis
		var authMessage *types.Auth
		if err := json.Unmarshal(cm.Message, &authMessage); err != nil {
			log.Error("Unable to decode JSON ", zap.Error(err))
			return false, err
		}
		sub, err := c.auth.ValidateJWT(authMessage.JWT)
		if err != nil {
			return false, err
		}
		return c.validationRegex.MatchString(sub), nil
	default:
		log.Error("Stream info function called with unknown message type", zap.Any("controlMessage", cm))
		return false, fmt.Errorf("unknown message type %v", cm)
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
