package quicutils

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/levigross/logger/logger"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
	"go.uber.org/zap"
)

type discardWriter struct {
	io.Writer
}

func (d discardWriter) Close() error {
	return nil
}

var log = logger.WithName("quicutils")

var Tracer = qlog.NewTracer(func(p logging.Perspective, connID []byte) io.WriteCloser {
	filename := fmt.Sprintf("%v_%x.qlog", strings.ToLower(p.String()), connID)
	f, err := os.Create(filename)
	if err != nil {
		log.Error("Unable to create file for tracing -- tracing will be discarded", zap.Error(err))
		return discardWriter{io.Discard}
	}
	log.Debug("Creating qlog file", zap.String("qlogFile", filename))
	return f
})
