package types

import (
	"crypto/sha256"

	"github.com/olzh2102/blocker/crypto"
	"github.com/olzh2102/blocker/proto"
	pb "google.golang.org/protobuf/proto"
)

func SignBlock(pk *crypto.PrivateKey, b *proto.Block) *crypto.Signature {
	return pk.Sign(HashBlock(b))
}

// * creates SHA256 of the header and returns
func HashBlock(block *proto.Block) []byte {
	b, err := pb.Marshal(block)
	if err != nil {
		panic(err)
	}
	hash := sha256.Sum256(b)

	return hash[:] // converts array to slice
}
