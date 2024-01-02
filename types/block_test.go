package types

import (
	"testing"

	"github.com/olzh2102/blocker/crypto"
	"github.com/olzh2102/blocker/util"
	"github.com/stretchr/testify/assert"
)

func TestHashBlock(t *testing.T) {
	block := util.RandomBlock()
	hash := HashBlock(block)
	assert.Equal(t, 32, len(hash))
}

func TestSignBlock(t *testing.T) {
	var (
		block   = util.RandomBlock()
		privKey = crypto.GeneratePrivateKey()
		pubKey  = privKey.Public()
	)

	signature := SignBlock(privKey, block)
	assert.Equal(t, 64, len(signature.Bytes()))
	assert.True(t, signature.Verify(pubKey, HashBlock(block)))

}
