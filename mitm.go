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
	"time"

	_ "embed"
)

var (
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	certsMu sync.Map // map[string]*tls.Certificate
)

// ---- CA certificate management ----

//go:embed blocked.webp
var blockedImage []byte
var blockedImageBase64 string

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

	addr := tc.LocalAddr().(*net.TCPAddr)

	return addr.IP, addr.Port, nil
}

// ---- Shared MITM relay logic ----

func mitmRelay(clientConn net.Conn, destAddr, clientIP, remoteIP string) {

	var host string
	// TLS handshake with client — extract SNI via GetConfigForClient
	tlsClientConn := tls.Server(clientConn, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			slog.Info("gen cert for", "sni", hello.ServerName)
			host = hello.ServerName
			cert := getCertForHost(hello.ServerName)
			if cert == nil {
				return nil, fmt.Errorf("failed to generate cert for %s", hello.ServerName)
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

		if isBlocked, score, reason := IsFraudHost(host); isBlocked {
			slog.Warn("mitm: blocking request to fraud domain", "host", host)

			htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<title>Access Blocked</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body { font-family: sans-serif; text-align: center; margin-top: 50px; background-color: #fce4e4; color: #cc0000; }
.container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); display: inline-block; max-width: 600px; }
h1 { margin-top: 0; }
.details { text-align: left; background: #f9f9f9; padding: 20px; border-radius: 4px; color: #333; margin-top: 20px; font-size: 14px; }
</style>
</head>
<body>
<div class="container">
	<h1>🚫 Access Blocked</h1>
	<p>This domain has been identified as a security risk and is blocked by GenAI Genesis.</p>
	<div class="details">
		<p><strong>Domain:</strong> %s</p>
		<p><strong>Fraud Score:</strong> %d</p>
		<p><strong>Reason:</strong> %s</p>
	</div>
	<img src="%s" alt="blocked">
</div>
</body>
</html>`, host, score, reason, blockedImageBase64)

			resp := &http.Response{
				StatusCode: http.StatusForbidden,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header: http.Header{
					"Content-Type": []string{"text/html; charset=utf-8"},
				},
				Body:          io.NopCloser(strings.NewReader(htmlContent)),
				ContentLength: int64(len(htmlContent)),
			}
			resp.Write(tlsClientConn)
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

	clientIP := clientConn.RemoteAddr().String()
	mitmRelay(clientConn, destAddr, clientIP, destAddr)
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
	mitmRelay(clientConn, destAddr, clientIP, destAddr)
}
