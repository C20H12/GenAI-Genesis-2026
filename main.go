package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"syscall"
)

const listenAddr = ":8000"
const directAddr = ":8001"

// ---- main ----

func main() {
	loadEnv(".env")
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
		slog.Error("listen failed", "addr", listenAddr, "error", err, "hint", "need root/CAP_NET_ADMIN")
		os.Exit(1)
	}
	defer ln.Close()

	slog.Info("MITM TPROXY listening", "addr", listenAddr)
	slog.Info("Trust ca.crt in your client, then redirect TLS traffic with iptables TPROXY to this port.")

	// Direct HTTP CONNECT listener (no TPROXY, for curl testing)
	directLn, err := net.Listen("tcp", directAddr)
	if err != nil {
		slog.Error("listen failed", "addr", directAddr, "error", err)
		os.Exit(1)
	}
	defer directLn.Close()
	slog.Info("MITM direct proxy listening", "addr", directAddr, "usage", "curl -x http://localhost"+directAddr+" --cacert ca.crt https://example.com")

	go func() {
		for {
			conn, err := directLn.Accept()
			if err != nil {
				slog.Error("direct accept", "error", err)
				continue
			}
			go handleDirectConn(conn)
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			slog.Error("accept", "error", err)
			continue
		}
		go handleConn(conn)
	}
}
