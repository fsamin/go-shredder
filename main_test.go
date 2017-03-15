package shredder

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShredAndReassemble(t *testing.T) {
	chunks, err := ShredFile("main.go", &Opts{
		GPGEncryption: &GPGEncryption{
			PublicKey: []byte(publicKey),
		},
		ChunkSize: 100,
	})
	assert.NoError(t, err)

	content, err := Reassemble(chunks, &Opts{
		GPGEncryption: &GPGEncryption{
			PrivateKey: []byte(privateKey),
			Passphrase: []byte("password"),
		},
		ChunkSize: 100,
	})
	assert.NoError(t, err)

	expected, err := ioutil.ReadFile("main.go")
	assert.NoError(t, err)

	assert.Equal(t, string(expected), content.String())

}
