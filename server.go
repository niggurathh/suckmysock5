package main

import (
	"io"
	"log"
	"net"
	"sync"
)

// Server represents the reverse SOCKS5 proxy server
type Server struct {
	listenAddr string
	socksAddr  string
	key        []byte
	mux        *Multiplexer
	muxMu      sync.RWMutex
}

// NewServer creates a new server instance
func NewServer(listenAddr, socksAddr, password string) *Server {
	return &Server{
		listenAddr: listenAddr,
		socksAddr:  socksAddr,
		key:        DeriveKey(password),
	}
}

// Run starts the server
func (s *Server) Run() error {
	// Start tunnel listener
	tunnelListener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	defer tunnelListener.Close()

	log.Printf("[server] Listening for tunnel connections on %s", s.listenAddr)
	log.Printf("[server] SOCKS5 will be available on %s when client connects", s.socksAddr)

	for {
		conn, err := tunnelListener.Accept()
		if err != nil {
			log.Printf("[server] Accept error: %v", err)
			continue
		}

		go s.handleTunnel(conn)
	}
}

// handleTunnel handles a client tunnel connection
func (s *Server) handleTunnel(conn net.Conn) {
	defer conn.Close()

	log.Printf("[server] Tunnel connection from %s", conn.RemoteAddr())

	// Perform handshake
	// Read client's nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(conn, nonce); err != nil {
		log.Printf("[server] Failed to read nonce: %v", err)
		return
	}

	// Derive session key
	sessionKey, err := DeriveSessionKey(s.key, nonce)
	if err != nil {
		log.Printf("[server] Failed to derive session key: %v", err)
		return
	}

	// Create encrypted connection
	crypto, err := NewCryptoConn(conn, sessionKey)
	if err != nil {
		log.Printf("[server] Failed to create crypto conn: %v", err)
		return
	}

	// Send OK response
	if err := crypto.WriteFrame([]byte("OK")); err != nil {
		log.Printf("[server] Failed to send OK: %v", err)
		return
	}

	// Create multiplexer
	mux := NewMultiplexer(crypto)

	s.muxMu.Lock()
	s.mux = mux
	s.muxMu.Unlock()

	log.Printf("[server] Client connected, starting SOCKS5 server")

	// Start SOCKS5 listener
	socksListener, err := net.Listen("tcp", s.socksAddr)
	if err != nil {
		log.Printf("[server] Failed to start SOCKS5 listener: %v", err)
		return
	}
	defer socksListener.Close()

	log.Printf("[server] SOCKS5 listening on %s", s.socksAddr)

	// Handle SOCKS5 connections in goroutine
	go func() {
		for {
			socksConn, err := socksListener.Accept()
			if err != nil {
				return
			}
			go s.handleSOCKS5(socksConn, mux)
		}
	}()

	// Run multiplexer (blocks until connection closes)
	if err := mux.Run(); err != nil {
		log.Printf("[server] Multiplexer error: %v", err)
	}

	s.muxMu.Lock()
	s.mux = nil
	s.muxMu.Unlock()

	log.Printf("[server] Client disconnected")
}

// handleSOCKS5 handles a SOCKS5 connection
func (s *Server) handleSOCKS5(conn net.Conn, mux *Multiplexer) {
	defer conn.Close()

	// Perform SOCKS5 handshake
	targetAddr, err := HandleSOCKS5Handshake(conn)
	if err != nil {
		log.Printf("[server] SOCKS5 handshake error: %v", err)
		return
	}

	log.Printf("[server] SOCKS5 CONNECT to %s", targetAddr)

	// Create a new stream
	stream := mux.CreateStream()
	defer func() {
		stream.Close()
		mux.RemoveStream(stream.ID)
	}()

	// Send CONNECT command through tunnel
	if err := mux.SendConnect(stream.ID, targetAddr); err != nil {
		log.Printf("[server] Failed to send CONNECT: %v", err)
		SendSOCKS5Failure(conn)
		return
	}

	// Wait for response from client (first data packet or close)
	// For simplicity, we send success immediately
	// In production, you'd wait for acknowledgment
	if err := SendSOCKS5Success(conn); err != nil {
		log.Printf("[server] Failed to send SOCKS5 success: %v", err)
		return
	}

	// Relay data bidirectionally
	var wg sync.WaitGroup
	wg.Add(2)

	// SOCKS5 client -> tunnel
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	// Tunnel -> SOCKS5 client
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}
