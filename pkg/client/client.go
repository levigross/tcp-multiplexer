package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/levigross/logger/logger"
	"github.com/levigross/tcp-multiplexer/pkg/connection"
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

	errChan chan error
}

func (c *Config) Run(ctx context.Context) (err error) {
	c.errChan = make(chan error, 1)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	ctx, cancler := context.WithCancel(ctx) // todo I need to do more with this context
	defer cancler()

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
	tlsConfig := &tls.Config{InsecureSkipVerify: c.IgnoreServerCertificate, NextProtos: []string{"quic"}} // TODO: support MTLS
	cq := &quic.Config{EnableDatagrams: true, MaxIdleTimeout: c.MaxIdleTimeout}
	if c.EnableQUICTracing {
		cq.Tracer = quicutils.Tracer
	}
	quicConnection, err := quic.DialAddrContext(ctx, c.RemoteServer, tlsConfig, cq)
	if err != nil {
		log.Error("Unable to dial server", zap.Error(err))
		return err
	}
	log.Debug("Connected to client")
	stream, err := quicConnection.OpenStreamSync(ctx)
	if err != nil {
		log.Error("Unable to open stream", zap.Error(err))
		return err
	}
	isAuthenticated := false
	if c.jwt != nil { // we pass in an auth token
		jwtBytes, err := json.Marshal(types.Auth{JWT: c.jwt})
		if err != nil {
			log.Error("Unable to marshal JWT", zap.Error(err))
			return err
		}
		ok, err := quicutils.SendControlMessage(types.ControlMessage{MessageType: types.AuthMessage, Message: jwtBytes}, stream)
		if err != nil {
			return err
		}
		if !ok {
			log.Error("Auth Failed -- see server logs for details")
			return fmt.Errorf("authentication failure")
		}
	}
	ch := connection.NewConnectionHandler(ctx, quicConnection, isAuthenticated)
	go ch.ClientHandler(stream, c.PortsToForward)
	// todo handle graceful shutdown
	select {
	case <-signalChan:
		log.Info("Got SIGINT") // todo: Close gracefully
		return
	case err := <-c.errChan:
		return err
	}
}
