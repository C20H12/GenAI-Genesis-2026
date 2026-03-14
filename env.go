package main

import (
	"bufio"
	"log/slog"
	"os"
	"strings"
)

// loadEnv reads a .env file and sets the key=value pairs as environment variables.
// It silently does nothing if the file doesn't exist.
func loadEnv(filename string) {
	f, err := os.Open(filename)
	if err != nil {
		slog.Warn("env: could not open file", "file", filename, "error", err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		// Strip surrounding quotes if present
		if len(value) >= 2 &&
			((value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		os.Setenv(key, value)
	}
}
