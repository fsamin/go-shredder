package shredder

import (
	"encoding/base64"
	"errors"
	"path/filepath"
)

const (
	BytesContentType = "bytes"
	FileContentType  = "file"
)

//Ctx is a context for a shredding
type Ctx struct {
	UUID         string
	ContentType  string
	content      []byte
	Opts         *Opts
	ChunksNumber int
}

// Bytes returns the content as a string
func (ctx *Ctx) String() string {
	return string(ctx.content)
}

// Bytes returns the content as a byte array
func (ctx *Ctx) Bytes() []byte {
	return ctx.content
}

// File returns the filename and one content according to the context content type.
// If the context content type is not a file, an error will be returned
func (ctx *Ctx) File() (string, []byte, error) {
	if ctx.ContentType != FileContentType {
		return "", nil, errors.New("Context is not a file content")
	}
	filename, err := base64.StdEncoding.DecodeString(ctx.UUID)
	if err != nil {
		return "", nil, err
	}
	return filepath.Base(string(filename)), ctx.content, nil
}

//Opts is here to set option on shredder like Encryption of chunksize
type Opts struct {
	AESEncryption *AESEncryption
	GPGEncryption *GPGEncryption
	ChunkSize     int64
}

//AESEncryption use https://golang.org/pkg/crypto/aes/ for file content encryption/decryption
type AESEncryption struct {
	Key []byte
}

//GPGEncryption use GPG to file content encryption/decryption
type GPGEncryption struct {
	PrivateKey []byte
	Passphrase []byte
	PublicKey  []byte
}

//Chunk is a piece of schredded file
type Chunk struct {
	Ctx    *Ctx
	Data   []byte
	Offset int
}

//Chunks is an array of chunks
type Chunks []Chunk

func (s Chunks) Len() int {
	return len(s)
}
func (s Chunks) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s Chunks) Less(i, j int) bool {
	return s[i].Offset < s[j].Offset
}
