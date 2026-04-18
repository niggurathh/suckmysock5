package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	NonceSize = 32
	KeySize   = 32
)

// DeriveKey derives a 32-byte key from a password using Argon2id
func DeriveKey(password string) []byte {
	// Using a fixed salt for simplicity - in production, use a random salt
	salt := []byte("suckmysock5-salt")
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, KeySize)
}

// DeriveSessionKey derives a session key using HKDF
func DeriveSessionKey(sharedKey, nonce []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, sharedKey, nonce, []byte("suckmysock5-session"))
	sessionKey := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdfReader, sessionKey); err != nil {
		return nil, err
	}
	return sessionKey, nil
}

// CryptoConn wraps a connection with ChaCha20-Poly1305 encryption
type CryptoConn struct {
	conn       io.ReadWriter
	cipher     cipher.AEAD
	readNonce  uint64
	writeNonce uint64
	readMu     sync.Mutex
	writeMu    sync.Mutex
}

// NewCryptoConn creates a new encrypted connection wrapper
func NewCryptoConn(conn io.ReadWriter, key []byte) (*CryptoConn, error) {
	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &CryptoConn{
		conn:   conn,
		cipher: cipher,
	}, nil
}

// generateNonce creates a nonce from the counter
func (c *CryptoConn) generateNonce(counter uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	binary.LittleEndian.PutUint64(nonce, counter)
	return nonce
}

// WriteFrame writes an encrypted frame
func (c *CryptoConn) WriteFrame(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	nonce := c.generateNonce(c.writeNonce)
	c.writeNonce++

	encrypted := c.cipher.Seal(nil, nonce, data, nil)

	// Write length prefix (2 bytes) + encrypted data
	length := uint16(len(encrypted))
	if err := binary.Write(c.conn, binary.BigEndian, length); err != nil {
		return err
	}

	_, err := c.conn.Write(encrypted)
	return err
}

// ReadFrame reads and decrypts a frame
func (c *CryptoConn) ReadFrame() ([]byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Read length prefix
	var length uint16
	if err := binary.Read(c.conn, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	if length == 0 {
		return nil, errors.New("invalid frame length")
	}

	// Read encrypted data
	encrypted := make([]byte, length)
	if _, err := io.ReadFull(c.conn, encrypted); err != nil {
		return nil, err
	}

	nonce := c.generateNonce(c.readNonce)
	c.readNonce++

	return c.cipher.Open(nil, nonce, encrypted, nil)
}

// GenerateNonce generates a random nonce for handshake
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}
