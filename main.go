package main

import (
	"context"
	"log"
	"net"
	"syscall"
)

const listenAddr = ":8000"
const directAddr = ":8001"

// ---- main ----

func main() {
	loadOrCreateCA("ca.crt", "ca.key")

	// Listen with TPROXY
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			c.Control(func(fd uintptr) {
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
			})
			return opErr
		},
	}

	ln, err := lc.Listen(context.Background(), "tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v (need root/CAP_NET_ADMIN)", listenAddr, err)
	}
	defer ln.Close()

	log.Printf("MITM TPROXY listening on %s", listenAddr)
	log.Println("Trust ca.crt in your client, then redirect TLS traffic with iptables TPROXY to this port.")

	// Direct HTTP CONNECT listener (no TPROXY, for curl testing)
	directLn, err := net.Listen("tcp", directAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", directAddr, err)
	}
	defer directLn.Close()
	log.Printf("MITM direct proxy listening on %s (use: curl -x http://localhost%s --cacert ca.crt https://example.com)", directAddr, directAddr)

	go func() {
		for {
			conn, err := directLn.Accept()
			if err != nil {
				log.Printf("direct accept: %v", err)
				continue
			}
			go handleDirectConn(conn)
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn)
	}
}
