package quicutils

import (
	"bytes"
	"encoding/json"

	"github.com/levigross/tcp-multiplexer/pkg/types"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

func SendControlMessage(cm types.ControlMessage, stream quic.Stream) (success bool, err error) {
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

func ReceiveControlMessage(stream quic.Stream, callBack types.ControlMessageCallback) (success bool, err error) {
	jsonDecoder := json.NewDecoder(stream)
	cm := types.ControlMessage{}
	if err = jsonDecoder.Decode(&cm); err != nil {
		log.Error("Unable to decode controlMessage", zap.Error(err))
		return
	}
	success, err = callBack(cm)
	if err != nil {
		return
	}
	message := []byte(types.FAIL)
	if success {
		message = []byte(types.OK)
	}
	if _, err = stream.Write(message); err != nil {
		log.Error("Unable to write stream message", zap.Error(err))
		return
	}
	return
}
