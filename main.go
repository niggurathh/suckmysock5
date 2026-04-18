package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	// Parse flags
	listen := flag.String("listen", "", "Server mode: listen address for tunnel (e.g., :8443)")
	connect := flag.String("connect", "", "Client mode: server address to connect to (e.g., server.com:8443)")
	socks := flag.String("socks", ":1080", "SOCKS5 listen address (server mode only)")
	key := flag.String("key", "", "Shared secret key for encryption")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "suckmysock5 - Reverse SOCKS5 Proxy with ChaCha20-Poly1305 encryption\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  Server mode: %s -listen :8443 -socks :1080 -key <secret>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Client mode: %s -connect server:8443 -key <secret>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	// Validate
	if *key == "" {
		log.Fatal("Error: -key is required")
	}

	if *listen == "" && *connect == "" {
		log.Fatal("Error: must specify either -listen (server) or -connect (client)")
	}

	if *listen != "" && *connect != "" {
		log.Fatal("Error: cannot specify both -listen and -connect")
	}

	// Run in appropriate mode
	if *listen != "" {
		// Server mode
		log.Printf("Starting server mode")
		server := NewServer(*listen, *socks, *key)
		if err := server.Run(); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	} else {
		// Client mode
		log.Printf("Starting client mode")
		client := NewClient(*connect, *key)
		if err := client.Run(); err != nil {
			log.Fatalf("Client error: %v", err)
		}
	}
}
