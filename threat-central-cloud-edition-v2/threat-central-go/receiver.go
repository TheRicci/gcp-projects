package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

type LogReceiver struct {
	addr    string
	chAlert chan Alert
	chErr   chan error
}

func NewLogReceiver(addr string) *LogReceiver {
	if addr == "" {
		addr = ":8080"
	}
	return &LogReceiver{
		addr:    addr,
		chAlert: make(chan Alert, 100),
		chErr:   make(chan error, 10),
	}
}

// normalizeTierFromSuricata converts Suricata severities (1=high, 2=medium, 3=low)
// into unified tiers (1=low, 2=medium, 3=high).
func normalizeTierFromSuricata(severity int) int {
	switch {
	case severity <= 1:
		return 3
	case severity == 2:
		return 2
	default:
		return 1
	}
}

// normalizeTierFromModsec converts ModSecurity severities (commonly 0-5, where
// 5/4 are most severe) into unified tiers (1=low, 2=medium, 3=high).
func normalizeTierFromModsec(severityStr string) int {
	sev, err := strconv.Atoi(severityStr)
	if err != nil {
		return 1
	}
	switch {
	case sev >= 4:
		return 3
	case sev == 3:
		return 2
	default:
		return 1
	}
}

// normalizeTierFromWazuh converts Wazuh rule levels (0-15) into unified tiers
// (1=low, 2=medium, 3=high).
func normalizeTierFromWazuh(level int) int {
	switch {
	case level >= 8:
		return 3
	case level >= 4:
		return 2
	default:
		return 1
	}
}

func (r *LogReceiver) ServerStart(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /logs", r.handleLogs)

	srv := &http.Server{
		Addr:    r.addr,
		Handler: mux,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			r.sendErr(err)
		}
	}()

	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
		close(r.chAlert)
		close(r.chErr)
	}()
}

func (r *LogReceiver) handleLogs(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		r.sendErr(err)
		return
	}
	defer req.Body.Close()

	logType := req.Header.Get("Log-Type")
	switch logType {
	case "modsec":
		if err := r.handleModsec(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			r.sendErr(err)
			return
		}
	case "suricata":
		if err := r.handleSuricata(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			r.sendErr(err)
			return
		}
	case "wazuh":
		if err := r.handleWazuh(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			r.sendErr(err)
			return
		}
	default:
		http.Error(w, "unknown Log-Type header", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (r *LogReceiver) handleModsec(body []byte) error {
	var list []ModsecAuditLog
	if err := json.Unmarshal(body, &list); err != nil {
		return err
	}

	for _, m := range list {
		if len(m.Transaction.Messages) == 0 {
			return fmt.Errorf("modsec record has no messages")
		}

		severity, _ := strconv.Atoi(m.Transaction.Messages[0].Details.Severity)
		timestamp, err := time.Parse("Mon Jan _2 15:04:05 2006", m.Transaction.TimeStamp)
		if err != nil {
			timestamp = time.Now().UTC()
		}

		logType := "modsec"
		tier := normalizeTierFromModsec(m.Transaction.Messages[0].Details.Severity)
		alert := Alert{
			IP:             m.Transaction.ClientIP,
			DstPort:        &m.Transaction.HostPort,
			Url:            &m.Transaction.Request.URI,
			Threat:         &m.Transaction.Messages[0].Details.Match,
			Severity:       &severity,
			FirstTimestamp: &timestamp,
			Tier:           &tier,
			LogType:        &logType,
			Quantity:       1,
			Modsec:         []ModsecAuditLog{m},
		}
		r.chAlert <- alert
	}

	return nil
}

func (r *LogReceiver) handleSuricata(body []byte) error {
	var list []SuricataEveLog
	if err := json.Unmarshal(body, &list); err != nil {
		return err
	}

	for _, s := range list {
		timestamp, err := time.Parse("2006-01-02T15:04:05.000000-0700", s.Timestamp)
		if err != nil {
			timestamp = time.Now().UTC()
		}

		logType := "suricata"
		tier := normalizeTierFromSuricata(s.Alert.Severity)
		alert := Alert{
			IP:             s.SrcIP,
			DstPort:        &s.DestPort,
			Url:            &s.HTTP.URL,
			Threat:         &s.Alert.Signature,
			FirstTimestamp: &timestamp,
			Severity:       &s.Alert.Severity,
			Tier:           &tier,
			LogType:        &logType,
			Quantity:       1,
			Suricata:       []SuricataEveLog{s},
		}
		r.chAlert <- alert
	}

	return nil
}

func (r *LogReceiver) handleWazuh(body []byte) error {
	var list []WazuhLog
	if err := json.Unmarshal(body, &list); err != nil {
		return err
	}

	for _, w := range list {
		timestamp := parseWazuhTimestamp(w.Timestamp)
		severity := w.Rule.Level
		threat := w.Rule.Description
		logType := "wazuh"
		dstPort := 0
		url := ""
		tier := normalizeTierFromWazuh(severity)
		alert := Alert{
			IP:             w.Agent.IP,
			DstPort:        &dstPort,
			Url:            &url,
			Threat:         &threat,
			Severity:       &severity,
			FirstTimestamp: &timestamp,
			Tier:           &tier,
			LogType:        &logType,
			Quantity:       1,
			Wazuh:          []WazuhLog{w},
		}
		r.chAlert <- alert
	}

	return nil
}

func parseWazuhTimestamp(value string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t
	}
	return time.Now().UTC()
}

func (r *LogReceiver) CatchEvent() (*Alert, error) {
	select {
	case ev, ok := <-r.chAlert:
		if !ok {
			return nil, context.Canceled
		}
		return &ev, nil
	case err, ok := <-r.chErr:
		if !ok {
			return nil, context.Canceled
		}
		return nil, err
	}
}

func (r *LogReceiver) sendErr(err error) {
	select {
	case r.chErr <- err:
	default:
	}
}
