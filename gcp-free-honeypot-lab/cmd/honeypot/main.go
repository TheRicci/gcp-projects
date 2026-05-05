package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxBodySampleBytes = 4096

type requestEvent struct {
	Timestamp     time.Time           `json:"timestamp"`
	RemoteAddr    string              `json:"remote_addr"`
	RemoteIP      string              `json:"remote_ip"`
	Method        string              `json:"method"`
	Path          string              `json:"path"`
	RawQuery      string              `json:"raw_query,omitempty"`
	Host          string              `json:"host"`
	UserAgent     string              `json:"user_agent,omitempty"`
	Referer       string              `json:"referer,omitempty"`
	ContentLength int64               `json:"content_length"`
	Headers       map[string][]string `json:"headers"`
	BodySample    string              `json:"body_sample,omitempty"`
	BodyEncoding  string              `json:"body_encoding,omitempty"`
	BodyTruncated bool                `json:"body_truncated"`
}

type safeJSONLogger struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func main() {
	addr := getenv("HONEYPOT_ADDR", ":80")
	logDir := getenv("HONEYPOT_LOG_DIR", "/var/log/honeypot")

	if err := os.MkdirAll(logDir, 0o755); err != nil {
		log.Fatalf("create log dir: %v", err)
	}

	logFile, err := os.OpenFile(filepath.Join(logDir, "requests.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatalf("open request log: %v", err)
	}
	defer logFile.Close()

	eventLog := &safeJSONLogger{enc: json.NewEncoder(io.MultiWriter(os.Stdout, logFile))}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, eventLog)
	})

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	log.Printf("honeypot listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen: %v", err)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request, eventLog *safeJSONLogger) {
	bodySample, truncated := readBodySample(r.Body)
	defer r.Body.Close()

	event := requestEvent{
		Timestamp:     time.Now().UTC(),
		RemoteAddr:    r.RemoteAddr,
		RemoteIP:      remoteIP(r.RemoteAddr),
		Method:        r.Method,
		Path:          r.URL.Path,
		RawQuery:      r.URL.RawQuery,
		Host:          r.Host,
		UserAgent:     r.UserAgent(),
		Referer:       r.Referer(),
		ContentLength: r.ContentLength,
		Headers:       cloneHeaders(r.Header),
		BodySample:    base64.StdEncoding.EncodeToString(bodySample),
		BodyEncoding:  "base64",
		BodyTruncated: truncated,
	}

	if len(bodySample) == 0 {
		event.BodySample = ""
		event.BodyEncoding = ""
	}

	eventLog.write(event)
	writeDecoyResponse(w, r)
}

func readBodySample(body io.Reader) ([]byte, bool) {
	limited := io.LimitReader(body, maxBodySampleBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, false
	}
	if len(data) > maxBodySampleBytes {
		return data[:maxBodySampleBytes], true
	}
	return data, false
}

func (l *safeJSONLogger) write(event requestEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.enc.Encode(event); err != nil {
		log.Printf("write request event: %v", err)
	}
}

func writeDecoyResponse(w http.ResponseWriter, r *http.Request) {
	path := strings.ToLower(r.URL.Path)
	w.Header().Set("Server", "nginx")

	switch {
	case strings.Contains(path, "wp-login"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body><form method="post"><input name="log"><input name="pwd" type="password"><button>Log In</button></form></body></html>`)
	case strings.Contains(path, "admin"):
		http.Error(w, "forbidden", http.StatusForbidden)
	case strings.Contains(path, ".env"):
		http.Error(w, "not found", http.StatusNotFound)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func cloneHeaders(headers http.Header) map[string][]string {
	copy := make(map[string][]string, len(headers))
	for key, values := range headers {
		copy[key] = append([]string(nil), values...)
	}
	return copy
}

func getenv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
