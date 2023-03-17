package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_generateTLSKey(t *testing.T) {
	assert := assert.New(t)
	tlsConfig, err := GenerateTLSConfigInMemory()
	assert.NoError(err)
	assert.NotNil(tlsConfig)
}
