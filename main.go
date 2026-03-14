package main

import (
	"context"
	_ "embed"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"os"
	"syscall"
)

const listenAddr = ":8000"
const directAddr = ":8001"
const httpAddr = ":8002"

//go:embed install-ca.html
var installCAHTML []byte

// ---- main ----

func main() {
	loadEnv(".env")
	loadOrCreateCA("ca.crt", "ca.key")

	// encode blocked.webp to base64
	blockedImageBase64 = base64.StdEncoding.EncodeToString(blockedImage)
	blockedImageBase64 = "data:image/webp;base64," + blockedImageBase64

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

	// Serve CA certificate and installation page on HTTP
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/install-ca.html", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(installCAHTML)
		})
		mux.HandleFunc("/ca.crt", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "ca.crt")
		})
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				http.Redirect(w, r, "/install-ca.html", http.StatusFound)
				return
			}
			http.NotFound(w, r)
		})

		slog.Info("CA cert installation HTTP server listening", "addr", httpAddr)
		err := http.ListenAndServe(httpAddr, mux)
		if err != nil {
			slog.Error("http server failed", "error", err)
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
