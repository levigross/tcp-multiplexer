package types

import "github.com/quic-go/quic-go"

type StreamInfo struct {
	QuicStreamID quic.StreamID
	Port         string

	done chan struct{}
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
