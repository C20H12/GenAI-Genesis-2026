package main

import (
	"context"
	"fmt"
	"log/slog"
	// "math"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const domainVerifierDefaultWSURL = "ws://172.105.109.223:8081"
const domainVerifierTimeout = 45 * time.Second

type wsAnalyzeRequest struct {
	Type      string `json:"type"`
	Domain    string `json:"domain"`
	RequestID string `json:"requestId"`
}

type wsAnalyzeResponse struct {
	Type      string `json:"type"`
	Domain    string `json:"domain"`
	RequestID string `json:"requestId"`
	Error     string `json:"error"`
	Result    *struct {
		Malicious  bool    `json:"malicious"`
		Confidence float64 `json:"confidence"`
		Reason     string  `json:"reason"`
	} `json:"result"`
}

func callDomainVerifierWS(domain string) (*fraudResult, error) {
	if strings.TrimSpace(domain) == "" {
		return nil, fmt.Errorf("empty domain")
	}

	wsURL := strings.TrimSpace(os.Getenv("DOMAIN_VERIFY_WS_URL"))
	if wsURL == "" {
		wsURL = domainVerifierDefaultWSURL
	}

	requestID := fmt.Sprintf("fraud-%d", time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), domainVerifierTimeout)
	defer cancel()

	conn, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("connect websocket analyzer: %w", err)
	}
	defer conn.Close()

	// if err := conn.SetReadDeadline(time.Now().Add(domainVerifierTimeout)); err != nil {
	// 	return nil, fmt.Errorf("set websocket read deadline: %w", err)
	// }

	req := wsAnalyzeRequest{
		Type:      "verify-domain",
		Domain:    domain,
		RequestID: requestID,
	}

	if err := conn.WriteJSON(req); err != nil {
		return nil, fmt.Errorf("send websocket request: %w", err)
	}

	for {
		var msg wsAnalyzeResponse
		if err := conn.ReadJSON(&msg); err != nil {
			return nil, fmt.Errorf("read websocket response: %w", err)
		}

		if msg.RequestID != "" && msg.RequestID != requestID {
			continue
		}

		switch msg.Type {
		case "error":
			if msg.Error == "" {
				return nil, fmt.Errorf("websocket analyzer returned unknown error")
			}
			return nil, fmt.Errorf("websocket analyzer error: %s", msg.Error)
		case "result":
			if msg.Result == nil {
				return nil, fmt.Errorf("websocket analyzer returned empty result")
			}

			confidence := msg.Result.Confidence
			if confidence < 0 {
				confidence = 0
			}
			if confidence > 1 {
				confidence = 1
			}

			score := int(confidence)
			if msg.Result.Malicious && score < 65 {
				score = 65
			}

			reason := strings.TrimSpace(msg.Result.Reason)
			if reason == "" {
				reason = "websocket analyzer did not provide a reason"
			}

			return &fraudResult{
				Score:  score,
				Reason: "ws: " + reason,
			}, nil
		}
	}
}

func analyzeAndPersistViaWebsocket(reqURL, method, domain, clientIP, remoteIP string) {
	if strings.TrimSpace(domain) == "" {
		slog.Warn("fraud: websocket analyzer", "url", reqURL, "note", "domain unavailable")
		return
	}

	result, err := callDomainVerifierWS(domain)
	if err != nil {
		slog.Warn("fraud: websocket analyzer", "url", reqURL, "domain", domain, "error", err)
		return
	}

	slog.Info("fraud: websocket result", "url", reqURL, "score", result.Score, "reason", result.Reason)
	persistFraudResult(reqURL, method+"|ws", domain, clientIP, remoteIP, result)
}
