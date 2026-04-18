package main

import (
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// Client represents the reverse SOCKS5 proxy client
type Client struct {
	serverAddr string
	key        []byte
}

// NewClient creates a new client instance
func NewClient(serverAddr, password string) *Client {
	return &Client{
		serverAddr: serverAddr,
		key:        DeriveKey(password),
	}
}

// Run starts the client
func (c *Client) Run() error {
	for {
		if err := c.connect(); err != nil {
			log.Printf("[client] Connection error: %v", err)
			log.Printf("[client] Reconnecting in 5 seconds...")
			time.Sleep(5 * time.Second)
			continue
		}
	}
}

// connect establishes a connection to the server
func (c *Client) connect() error {
	conn, err := net.Dial("tcp", c.serverAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Printf("[client] Connected to server %s", c.serverAddr)

	// Generate and send nonce
	nonce, err := GenerateNonce()
	if err != nil {
		return err
	}

	if _, err := conn.Write(nonce); err != nil {
		return err
	}

	// Derive session key
	sessionKey, err := DeriveSessionKey(c.key, nonce)
	if err != nil {
		return err
	}

	// Create encrypted connection
	crypto, err := NewCryptoConn(conn, sessionKey)
	if err != nil {
		return err
	}

	// Read OK response
	response, err := crypto.ReadFrame()
	if err != nil {
		return err
	}

	if string(response) != "OK" {
		log.Printf("[client] Invalid handshake response: %s", response)
		return err
	}

	log.Printf("[client] Handshake successful")

	// Create multiplexer
	mux := NewMultiplexer(crypto)

	// Set up CONNECT handler
	mux.SetConnectHandler(func(streamID uint32, addr string) {
		go c.handleConnect(mux, streamID, addr)
	})

	// Run multiplexer (blocks until connection closes)
	return mux.Run()
}

// handleConnect handles a CONNECT request from the server
func (c *Client) handleConnect(mux *Multiplexer, streamID uint32, addr string) {
	log.Printf("[client] CONNECT stream=%d to %s", streamID, addr)

	// Register the stream
	stream := mux.RegisterStream(streamID)
	defer func() {
		stream.Close()
		mux.RemoveStream(streamID)
	}()

	// Connect to the target
	targetConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		log.Printf("[client] Failed to connect to %s: %v", addr, err)
		return
	}
	defer targetConn.Close()

	log.Printf("[client] Connected to %s", addr)

	// Relay data bidirectionally
	var wg sync.WaitGroup
	wg.Add(2)

	// Stream -> target
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				targetConn.(*net.TCPConn).CloseWrite()
				return
			}
			if _, err := targetConn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	// Target -> stream
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := targetConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("[client] Read error: %v", err)
				}
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}
