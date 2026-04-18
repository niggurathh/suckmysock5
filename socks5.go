package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	SOCKS5Version = 0x05
	NoAuth        = 0x00
	CmdCONNECT    = 0x01
	AddrTypeIPv4  = 0x01
	AddrTypeDomain = 0x03
	AddrTypeIPv6  = 0x04
)

// SOCKS5 reply codes
const (
	RepSuccess         = 0x00
	RepGeneralFailure  = 0x01
	RepConnNotAllowed  = 0x02
	RepNetworkUnreach  = 0x03
	RepHostUnreach     = 0x04
	RepConnRefused     = 0x05
	RepTTLExpired      = 0x06
	RepCmdNotSupported = 0x07
	RepAddrNotSupported = 0x08
)

// HandleSOCKS5Handshake performs the SOCKS5 handshake and returns the target address
func HandleSOCKS5Handshake(conn net.Conn) (string, error) {
	// Read version and number of auth methods
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}

	if buf[0] != SOCKS5Version {
		return "", errors.New("invalid SOCKS version")
	}

	numMethods := int(buf[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}

	// Check for no-auth method
	hasNoAuth := false
	for _, m := range methods {
		if m == NoAuth {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		conn.Write([]byte{SOCKS5Version, 0xFF}) // No acceptable methods
		return "", errors.New("no acceptable auth method")
	}

	// Accept no-auth
	if _, err := conn.Write([]byte{SOCKS5Version, NoAuth}); err != nil {
		return "", err
	}

	// Read connection request
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	if header[0] != SOCKS5Version {
		return "", errors.New("invalid SOCKS version in request")
	}

	if header[1] != CmdCONNECT {
		sendSOCKS5Reply(conn, RepCmdNotSupported)
		return "", errors.New("only CONNECT command supported")
	}

	// Parse address
	var addr string
	switch header[3] {
	case AddrTypeIPv4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", err
		}
		addr = net.IP(ipBuf).String()

	case AddrTypeDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return "", err
		}
		addr = string(domainBuf)

	case AddrTypeIPv6:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", err
		}
		addr = "[" + net.IP(ipBuf).String() + "]"

	default:
		sendSOCKS5Reply(conn, RepAddrNotSupported)
		return "", errors.New("unsupported address type")
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return fmt.Sprintf("%s:%d", addr, port), nil
}

// sendSOCKS5Reply sends a SOCKS5 reply
func sendSOCKS5Reply(conn net.Conn, rep byte) error {
	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	reply := []byte{
		SOCKS5Version,
		rep,
		0x00,          // RSV
		AddrTypeIPv4,  // ATYP
		0, 0, 0, 0,    // BND.ADDR (0.0.0.0)
		0, 0,          // BND.PORT (0)
	}
	_, err := conn.Write(reply)
	return err
}

// SendSOCKS5Success sends a successful SOCKS5 reply
func SendSOCKS5Success(conn net.Conn) error {
	return sendSOCKS5Reply(conn, RepSuccess)
}

// SendSOCKS5Failure sends a failure SOCKS5 reply
func SendSOCKS5Failure(conn net.Conn) error {
	return sendSOCKS5Reply(conn, RepGeneralFailure)
}
