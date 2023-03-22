package types

import (
	"encoding/json"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/quic-go/quic-go"
)

type ControlMessageType uint

const (
	OK   = "OK"
	FAIL = "KO"

	AuthError = 321
	BadAuth   = 911

	CancelAuthCode = 123

	AuthMessage ControlMessageType = iota
	StreamInfoMessage
)

type ControlMessage struct {
	MessageType ControlMessageType
	Message     json.RawMessage
}

type StreamInfo struct {
	QuicStreamID quic.StreamID
	Port         string

	done chan struct{}
}

type Auth struct {
	JWT *jwt.JSONWebToken
}

func NewStreamInfo(id quic.StreamID, port string) *StreamInfo {
	return &StreamInfo{done: make(chan struct{}), QuicStreamID: id, Port: port}
}

func (s *StreamInfo) Wait() {
	<-s.done
}

func (s *StreamInfo) Done() {
	s.done <- struct{}{}
}

type ControlMessageCallback func(ControlMessage) (bool, error)
