package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
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

const listenAddr = ":8000"
const directAddr = ":8001"

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
			log.Fatalf("ca.crt exists but ca.key missing: %v", err)
		}
		block, _ := pem.Decode(certPEM)
		caCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatalf("parse ca.crt: %v", err)
		}
		keyBlock, _ := pem.Decode(keyPEM)
		k, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			log.Fatalf("parse ca.key: %v", err)
		}
		caKey = k
		log.Println("Loaded existing CA from", certFile)
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
		log.Fatalf("create CA cert: %v", err)
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

	log.Println("Generated new CA:", certFile, keyFile)
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
		log.Printf("create cert for %s: %v", host, err)
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

func mitmRelay(clientConn net.Conn, destAddr, host string) {
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
		log.Printf("client TLS handshake: %v", err)
		return
	}
	defer tlsClientConn.Close()

	// Connect to real server
	serverConn, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		log.Printf("dial server %s: %v", destAddr, err)
		return
	}
	defer serverConn.Close()

	tlsServerConn := tls.Client(serverConn, &tls.Config{
		ServerName: host,
	})
	if err := tlsServerConn.Handshake(); err != nil {
		log.Printf("server TLS handshake (%s): %v", host, err)
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
				log.Printf("read request: %v", err)
			}
			return
		}

		url := fmt.Sprintf("https://%s%s", host, req.URL.RequestURI())
		fmt.Printf("\n\033[1;36m→ %s %s\033[0m\n", req.Method, url)

		if err := req.Write(tlsServerConn); err != nil {
			log.Printf("forward request: %v", err)
			return
		}

		resp, err := http.ReadResponse(serverBuf, req)
		if err != nil {
			log.Printf("read response: %v", err)
			return
		}

		ct := resp.Header.Get("Content-Type")
		isHTML := strings.Contains(ct, "text/html")

		if isHTML {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				log.Printf("read response body: %v", err)
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

			fmt.Printf("\033[1;33m← %d %s (%d bytes)\033[0m\n", resp.StatusCode, ct, len(decoded))
			fmt.Println(string(decoded))

			resp.Body = io.NopCloser(bytes.NewReader(body))
		} else {
			fmt.Printf("\033[1;90m← %d %s (not HTML, skipping body)\033[0m\n", resp.StatusCode, ct)
		}

		if err := resp.Write(tlsClientConn); err != nil {
			log.Printf("forward response: %v", err)
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
		log.Printf("get original dst: %v", err)
		return
	}
	destAddr := net.JoinHostPort(origIP.String(), fmt.Sprintf("%d", origPort))
	host := origIP.String()

	mitmRelay(clientConn, destAddr, host)
}

// ---- HTTP CONNECT proxy handler (no TPROXY) ----

func handleDirectConn(clientConn net.Conn) {
	defer clientConn.Close()

	br := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("direct: read request: %v", err)
		return
	}

	if req.Method != http.MethodConnect {
		log.Printf("direct: expected CONNECT, got %s", req.Method)
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

	log.Printf("direct: CONNECT tunnel to %s", destAddr)
	mitmRelay(clientConn, destAddr, host)
}

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
