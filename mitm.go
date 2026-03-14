package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	certsMu sync.Map // map[string]*tls.Certificate
)

// ---- CA certificate management ----

func loadOrCreateCA(certFile, keyFile string) {
	// Try to load existing CA
	if certPEM, err := os.ReadFile(certFile); err == nil {
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			slog.Error("ca.crt exists but ca.key missing", "error", err)
			os.Exit(1)
		}
		block, _ := pem.Decode(certPEM)
		caCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			slog.Error("parse ca.crt", "error", err)
			os.Exit(1)
		}
		keyBlock, _ := pem.Decode(keyPEM)
		k, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			slog.Error("parse ca.key", "error", err)
			os.Exit(1)
		}
		caKey = k
		slog.Info("Loaded existing CA", "file", certFile)
		return
	}

	// Generate new CA
	caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "MITM Proxy CA",
			Organization: []string{"MITM Proxy"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		slog.Error("create CA cert", "error", err)
		os.Exit(1)
	}
	caCert, _ = x509.ParseCertificate(der)

	// Write cert
	certOut, _ := os.Create(certFile)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	certOut.Close()

	// Write key
	keyDer, _ := x509.MarshalECPrivateKey(caKey)
	keyOut, _ := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer})
	keyOut.Close()

	slog.Info("Generated new CA", "cert", certFile, "key", keyFile)
}

// ---- Dynamic certificate generation ----

func getCertForHost(host string) *tls.Certificate {
	if c, ok := certsMu.Load(host); ok {
		return c.(*tls.Certificate)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}

	// If host looks like an IP, add it as an IP SAN
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		slog.Error("create cert", "host", host, "error", err)
		return nil
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
	certsMu.Store(host, cert)
	return cert
}

// ---- TPROXY / original destination ----

// getOriginalDst retrieves the original destination address from a TPROXY connection.
func getOriginalDst(conn net.Conn) (net.IP, int, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, 0, fmt.Errorf("not a TCPConn")
	}

	raw, err := tc.SyscallConn()
	if err != nil {
		return nil, 0, err
	}

	var origIP net.IP
	var origPort int
	var syscallErr error

	err = raw.Control(func(fd uintptr) {
		// Try IPv4 SO_ORIGINAL_DST first
		var addr syscall.RawSockaddrInet4
		addrLen := uint32(unsafe.Sizeof(addr))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_IP,
			80, // SO_ORIGINAL_DST
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&addrLen)),
			0,
		)
		if errno == 0 {
			origIP = net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
			origPort = int(addr.Port>>8) | int(addr.Port&0xff)<<8 // ntohs
			return
		}

		// Try IPv6 IP6T_SO_ORIGINAL_DST
		var addr6 syscall.RawSockaddrInet6
		addrLen6 := uint32(unsafe.Sizeof(addr6))
		_, _, errno = syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_IPV6,
			80, // IP6T_SO_ORIGINAL_DST
			uintptr(unsafe.Pointer(&addr6)),
			uintptr(unsafe.Pointer(&addrLen6)),
			0,
		)
		if errno == 0 {
			origIP = addr6.Addr[:]
			origPort = int(addr6.Port>>8) | int(addr6.Port&0xff)<<8
			return
		}

		syscallErr = fmt.Errorf("getsockopt SO_ORIGINAL_DST failed: %v", errno)
	})

	if err != nil {
		return nil, 0, err
	}
	return origIP, origPort, syscallErr
}

// ---- Shared MITM relay logic ----

func mitmRelay(clientConn net.Conn, destAddr, host, clientIP, remoteIP string) {
	// TLS handshake with client — extract SNI via GetConfigForClient
	if host == "" {
		// Will be filled by SNI callback
	}
	var sniHost string
	tlsClientConn := tls.Server(clientConn, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sniHost = hello.ServerName
			if host == "" {
				host = sniHost
			}
			cert := getCertForHost(host)
			if cert == nil {
				return nil, fmt.Errorf("failed to generate cert for %s", host)
			}
			return &tls.Config{
				Certificates: []tls.Certificate{*cert},
			}, nil
		},
	})
	if err := tlsClientConn.Handshake(); err != nil {
		slog.Error("client TLS handshake", "error", err)
		return
	}
	defer tlsClientConn.Close()

	// Connect to real server
	serverConn, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		slog.Error("dial server", "addr", destAddr, "error", err)
		return
	}
	defer serverConn.Close()

	tlsServerConn := tls.Client(serverConn, &tls.Config{
		ServerName: host,
	})
	if err := tlsServerConn.Handshake(); err != nil {
		slog.Error("server TLS handshake", "host", host, "error", err)
		return
	}
	defer tlsServerConn.Close()

	// Relay HTTP: read request, forward, read response, log, forward back
	clientBuf := bufio.NewReader(tlsClientConn)
	serverBuf := bufio.NewReader(tlsServerConn)

	for {
		req, err := http.ReadRequest(clientBuf)
		if err != nil {
			if err != io.EOF {
				slog.Error("read request", "error", err)
			}
			return
		}

		url := fmt.Sprintf("https://%s%s", host, req.URL.RequestURI())
		slog.Info("request", "method", req.Method, "url", url)

		if err := req.Write(tlsServerConn); err != nil {
			slog.Error("forward request", "error", err)
			return
		}

		resp, err := http.ReadResponse(serverBuf, req)
		if err != nil {
			slog.Error("read response", "error", err)
			return
		}

		ct := resp.Header.Get("Content-Type")
		isHTML := strings.Contains(ct, "text/html")

		if isHTML {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				slog.Error("read response body", "error", err)
				return
			}

			decoded := body
			switch resp.Header.Get("Content-Encoding") {
			case "gzip":
				if gr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
					decoded, _ = io.ReadAll(gr)
					gr.Close()
				}
			case "deflate":
				if fr := flate.NewReader(bytes.NewReader(body)); fr != nil {
					decoded, _ = io.ReadAll(fr)
					fr.Close()
				}
			}

			slog.Info("response", "status", resp.StatusCode, "content_type", ct, "bytes", len(decoded))

			// Async fraud detection — does not block
			AnalyzeFraud(url, req.Method, string(decoded), clientIP, remoteIP)

			resp.Body = io.NopCloser(bytes.NewReader(body))
		} else {
			slog.Debug("response", "status", resp.StatusCode, "content_type", ct, "note", "not HTML, skipping body")
		}

		if err := resp.Write(tlsClientConn); err != nil {
			slog.Error("forward response", "error", err)
			return
		}
	}
}

// ---- TPROXY connection handler ----

func handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	// 1) Get original destination
	origIP, origPort, err := getOriginalDst(clientConn)
	if err != nil {
		slog.Error("get original dst", "error", err)
		return
	}
	destAddr := net.JoinHostPort(origIP.String(), fmt.Sprintf("%d", origPort))
	host := origIP.String()

	clientIP := clientConn.RemoteAddr().String()
	mitmRelay(clientConn, destAddr, host, clientIP, destAddr)
}

// ---- HTTP CONNECT proxy handler (no TPROXY) ----

func handleDirectConn(clientConn net.Conn) {
	defer clientConn.Close()

	br := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(br)
	if err != nil {
		slog.Error("direct: read request", "error", err)
		return
	}

	if req.Method != http.MethodConnect {
		slog.Warn("direct: expected CONNECT", "got", req.Method)
		fmt.Fprintf(clientConn, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return
	}

	destAddr := req.Host
	host, _, err := net.SplitHostPort(destAddr)
	if err != nil {
		host = destAddr
		destAddr = net.JoinHostPort(host, "443")
	}

	// Respond 200 to complete the CONNECT tunnel
	fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	slog.Info("direct: CONNECT tunnel", "dest", destAddr)
	clientIP := clientConn.RemoteAddr().String()
	mitmRelay(clientConn, destAddr, host, clientIP, destAddr)
}
