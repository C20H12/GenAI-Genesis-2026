package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"

	"golang.org/x/net/html"
	_ "modernc.org/sqlite"
)

// ---- Database ----

var (
	fraudDB   *sql.DB
	fraudOnce sync.Once
)

func initFraudDB() {
	fraudOnce.Do(func() {
		var err error
		fraudDB, err = sql.Open("sqlite", "fraud.db")
		if err != nil {
			slog.Error("fraud: open db", "error", err)
			return
		}
		_, err = fraudDB.Exec(`CREATE TABLE IF NOT EXISTS fraud_results (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			url        TEXT,
			method     TEXT,
			score      INTEGER,
			reason     TEXT,
			client_ip  TEXT,
			remote_ip  TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
		if err != nil {
			slog.Error("fraud: create table", "error", err)
		}
	})
}

// ---- HTML text extraction ----

// extractText parses HTML and returns visible text content,
// skipping <script>, <style>, and other non-visible elements.
func extractText(htmlBytes []byte) string {
	tokenizer := html.NewTokenizer(bytes.NewReader(htmlBytes))
	var buf strings.Builder
	skip := 0 // depth counter for elements to skip (script, style, etc.)

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return strings.TrimSpace(buf.String())

		case html.StartTagToken:
			tn, _ := tokenizer.TagName()
			tag := string(tn)
			if tag == "script" || tag == "style" || tag == "noscript" {
				skip++
			}

		case html.EndTagToken:
			tn, _ := tokenizer.TagName()
			tag := string(tn)
			if tag == "script" || tag == "style" || tag == "noscript" {
				if skip > 0 {
					skip--
				}
			}

		case html.TextToken:
			if skip > 0 {
				continue
			}
			text := strings.TrimSpace(tokenizer.Token().Data)
			if text != "" {
				if buf.Len() > 0 {
					buf.WriteByte(' ')
				}
				buf.WriteString(text)
			}
		}
	}
}

// ---- OpenRouter LLM call ----

type fraudResult struct {
	Score  int    `json:"score"`
	Reason string `json:"reason"`
}

type openRouterRequest struct {
	Model          string          `json:"model"`
	Messages       []chatMessage   `json:"messages"`
	ResponseFormat *responseFormat `json:"response_format,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type responseFormat struct {
	Type       string      `json:"type"`
	JSONSchema *jsonSchema `json:"json_schema,omitempty"`
}

type jsonSchema struct {
	Name   string     `json:"name"`
	Strict bool       `json:"strict"`
	Schema schemaSpec `json:"schema"`
}

type schemaSpec struct {
	Type                 string                  `json:"type"`
	Properties           map[string]propertySpec `json:"properties"`
	Required             []string                `json:"required"`
	AdditionalProperties bool                    `json:"additionalProperties"`
}

type propertySpec struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

const openRouterURL = "https://openrouter.ai/api/v1/chat/completions"
const fraudModel = "deepseek/deepseek-v3.2"

func callFraudLLM(url, text string) (*fraudResult, error) {
	apiKey := os.Getenv("OPENROUTER_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("OPENROUTER_API_KEY not set")
	}

	// Truncate very long text to avoid excessive token usage
	if len(text) > 8000 {
		text = text[:8000]
	}

	reqBody := openRouterRequest{
		Model: fraudModel,
		Messages: []chatMessage{
			{
				Role:    "system",
				Content: "You are a fraud detection assistant. Analyze the following webpage text and determine if it is fraudulent. Return a fraud score from 0 (not fraud) to 100 (definitely fraud) and a brief reason, in JSON.",
			},
			{
				Role:    "user",
				Content: fmt.Sprintf("URL: %s\n\nPage text:\n%s", url, text),
			},
		},
		ResponseFormat: &responseFormat{
			Type: "json_schema",
			JSONSchema: &jsonSchema{
				Name:   "fraud_detection",
				Strict: true,
				Schema: schemaSpec{
					Type: "object",
					Properties: map[string]propertySpec{
						"score": {
							Type:        "integer",
							Description: "Fraud score from 0 (not fraud) to 100 (definitely fraud)",
						},
						"reason": {
							Type:        "string",
							Description: "Brief explanation of the fraud assessment",
						},
					},
					Required:             []string{"score", "reason"},
					AdditionalProperties: false,
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", openRouterURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openrouter returned %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse the OpenRouter chat completion response
	var completion struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &completion); err != nil {
		return nil, fmt.Errorf("unmarshal completion: %w", err)
	}
	if len(completion.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	var result fraudResult
	if err := json.Unmarshal([]byte(completion.Choices[0].Message.Content), &result); err != nil {
		return nil, fmt.Errorf("unmarshal fraud result: %w (raw: %s)", err, completion.Choices[0].Message.Content)
	}

	return &result, nil
}

// ---- Public API ----

// AnalyzeFraud kicks off an async fraud analysis. It does NOT block the caller.
func AnalyzeFraud(url, method, htmlBody, clientIP, remoteIP string) {
	initFraudDB()

	go func() {
		slog.Info("fraud: start", "url", url, "method", method)

		text := extractText([]byte(htmlBody))
		if len(strings.TrimSpace(text)) == 0 {
			slog.Info("fraud: end", "url", url, "note", "empty text, skipped")
			return
		}

		result, err := callFraudLLM(url, text)
		if err != nil {
			slog.Error("fraud: end", "url", url, "error", err)
			return
		}

		slog.Info("fraud: result", "url", url, "score", result.Score, "reason", result.Reason)

		if fraudDB == nil {
			slog.Warn("fraud: end", "url", url, "note", "db not initialized, skipping insert")
			return
		}

		_, err = fraudDB.Exec(
			`INSERT INTO fraud_results (url, method, score, reason, client_ip, remote_ip) VALUES (?, ?, ?, ?, ?, ?)`,
			url, method, result.Score, result.Reason, clientIP, remoteIP,
		)
		if err != nil {
			slog.Error("fraud: insert", "error", err)
		}

		slog.Info("fraud: end", "url", url, "score", result.Score)
	}()
}
