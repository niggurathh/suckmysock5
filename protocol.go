package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// Command types
const (
	CmdConnect = 0x01
	CmdData    = 0x02
	CmdClose   = 0x03
)

// Frame represents a protocol frame
type Frame struct {
	Cmd      byte
	StreamID uint32
	Data     []byte
}

// EncodeFrame encodes a frame to bytes
func EncodeFrame(f *Frame) []byte {
	buf := make([]byte, 5+len(f.Data))
	buf[0] = f.Cmd
	binary.BigEndian.PutUint32(buf[1:5], f.StreamID)
	copy(buf[5:], f.Data)
	return buf
}

// DecodeFrame decodes bytes to a frame
func DecodeFrame(data []byte) (*Frame, error) {
	if len(data) < 5 {
		return nil, errors.New("frame too short")
	}
	return &Frame{
		Cmd:      data[0],
		StreamID: binary.BigEndian.Uint32(data[1:5]),
		Data:     data[5:],
	}, nil
}

// Stream represents a multiplexed stream
type Stream struct {
	ID       uint32
	dataCh   chan []byte
	closeCh  chan struct{}
	closed   int32 // atomic bool
	mux      *Multiplexer
	closeErr error
}

func (s *Stream) isClosed() bool {
	return atomic.LoadInt32(&s.closed) != 0
}

func (s *Stream) setClosed() bool {
	return atomic.CompareAndSwapInt32(&s.closed, 0, 1)
}

// Read reads data from the stream
func (s *Stream) Read(p []byte) (int, error) {
	select {
	case data, ok := <-s.dataCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, data)
		return n, nil
	case <-s.closeCh:
		return 0, io.EOF
	}
}

// Write writes data to the stream
func (s *Stream) Write(p []byte) (int, error) {
	if s.isClosed() {
		return 0, errors.New("stream closed")
	}

	frame := &Frame{
		Cmd:      CmdData,
		StreamID: s.ID,
		Data:     p,
	}

	if err := s.mux.WriteFrame(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the stream
func (s *Stream) Close() error {
	if !s.setClosed() {
		return nil
	}

	close(s.closeCh)

	frame := &Frame{
		Cmd:      CmdClose,
		StreamID: s.ID,
	}
	return s.mux.WriteFrame(frame)
}

// LocalAddr returns nil (not a real connection)
func (s *Stream) LocalAddr() net.Addr { return nil }

// RemoteAddr returns nil (not a real connection)
func (s *Stream) RemoteAddr() net.Addr { return nil }

// Multiplexer handles stream multiplexing over an encrypted connection
type Multiplexer struct {
	crypto       *CryptoConn
	streams      map[uint32]*Stream
	streamsMu    sync.RWMutex
	nextStreamID uint32 // atomic
	acceptCh     chan *Stream
	closeCh      chan struct{}
	closed       int32 // atomic bool
	onConnect    func(streamID uint32, addr string)
}

func (m *Multiplexer) isClosed() bool {
	return atomic.LoadInt32(&m.closed) != 0
}

func (m *Multiplexer) setClosed() bool {
	return atomic.CompareAndSwapInt32(&m.closed, 0, 1)
}

// NewMultiplexer creates a new multiplexer
func NewMultiplexer(crypto *CryptoConn) *Multiplexer {
	m := &Multiplexer{
		crypto:   crypto,
		streams:  make(map[uint32]*Stream),
		acceptCh: make(chan *Stream, 16),
		closeCh:  make(chan struct{}),
	}
	return m
}

// SetConnectHandler sets the callback for CONNECT commands
func (m *Multiplexer) SetConnectHandler(handler func(streamID uint32, addr string)) {
	m.onConnect = handler
}

// CreateStream creates a new stream
func (m *Multiplexer) CreateStream() *Stream {
	id := atomic.AddUint32(&m.nextStreamID, 1)
	stream := &Stream{
		ID:      id,
		dataCh:  make(chan []byte, 64),
		closeCh: make(chan struct{}),
		mux:     m,
	}

	m.streamsMu.Lock()
	m.streams[id] = stream
	m.streamsMu.Unlock()

	return stream
}

// GetStream gets an existing stream
func (m *Multiplexer) GetStream(id uint32) *Stream {
	m.streamsMu.RLock()
	defer m.streamsMu.RUnlock()
	return m.streams[id]
}

// RegisterStream registers a stream with a specific ID
func (m *Multiplexer) RegisterStream(id uint32) *Stream {
	stream := &Stream{
		ID:      id,
		dataCh:  make(chan []byte, 64),
		closeCh: make(chan struct{}),
		mux:     m,
	}

	m.streamsMu.Lock()
	m.streams[id] = stream
	m.streamsMu.Unlock()

	return stream
}

// RemoveStream removes a stream
func (m *Multiplexer) RemoveStream(id uint32) {
	m.streamsMu.Lock()
	delete(m.streams, id)
	m.streamsMu.Unlock()
}

// WriteFrame writes a frame to the connection
func (m *Multiplexer) WriteFrame(f *Frame) error {
	return m.crypto.WriteFrame(EncodeFrame(f))
}

// SendConnect sends a CONNECT command
func (m *Multiplexer) SendConnect(streamID uint32, addr string) error {
	frame := &Frame{
		Cmd:      CmdConnect,
		StreamID: streamID,
		Data:     []byte(addr),
	}
	return m.WriteFrame(frame)
}

// Run starts the multiplexer read loop
func (m *Multiplexer) Run() error {
	for {
		data, err := m.crypto.ReadFrame()
		if err != nil {
			m.Close()
			return err
		}

		frame, err := DecodeFrame(data)
		if err != nil {
			continue
		}

		switch frame.Cmd {
		case CmdConnect:
			if m.onConnect != nil {
				m.onConnect(frame.StreamID, string(frame.Data))
			}

		case CmdData:
			stream := m.GetStream(frame.StreamID)
			if stream != nil && !stream.isClosed() {
				select {
				case stream.dataCh <- frame.Data:
				default:
					// Drop if buffer full
				}
			}

		case CmdClose:
			stream := m.GetStream(frame.StreamID)
			if stream != nil {
				atomic.StoreInt32(&stream.closed, 1)
				close(stream.dataCh)
				m.RemoveStream(frame.StreamID)
			}
		}
	}
}

// Accept accepts a new stream (for server side)
func (m *Multiplexer) Accept() (*Stream, error) {
	select {
	case stream := <-m.acceptCh:
		return stream, nil
	case <-m.closeCh:
		return nil, errors.New("multiplexer closed")
	}
}

// Close closes the multiplexer
func (m *Multiplexer) Close() error {
	if !m.setClosed() {
		return nil
	}
	close(m.closeCh)

	m.streamsMu.Lock()
	for _, stream := range m.streams {
		atomic.StoreInt32(&stream.closed, 1)
		close(stream.dataCh)
	}
	m.streams = make(map[uint32]*Stream)
	m.streamsMu.Unlock()

	return nil
}
