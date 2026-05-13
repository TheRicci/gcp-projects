package main

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/iterator"
)

type AlertStore interface {
	SaveAlert(ctx context.Context, alert *Alert) error
	LoadRecentAlerts(ctx context.Context, limit int) ([]*Alert, error)
	Close() error
}

type FirestoreStore struct {
	client     *firestore.Client
	collection string
}

func NewFirestoreStore(ctx context.Context, projectID, collection string) (*FirestoreStore, error) {
	if projectID == "" {
		return nil, fmt.Errorf("GCP_PROJECT_ID is required for Firestore storage")
	}
	if collection == "" {
		collection = "alerts"
	}

	client, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("firestore.NewClient: %w", err)
	}

	return &FirestoreStore{
		client:     client,
		collection: collection,
	}, nil
}

func (s *FirestoreStore) Close() error {
	return s.client.Close()
}

func (s *FirestoreStore) SaveAlert(ctx context.Context, alert *Alert) error {
	_, _, err := s.client.Collection(s.collection).Add(ctx, alertToDocument(alert))
	if err != nil {
		return fmt.Errorf("firestore SaveAlert: %w", err)
	}
	return nil
}

func (s *FirestoreStore) LoadRecentAlerts(ctx context.Context, limit int) ([]*Alert, error) {
	if limit <= 0 {
		return nil, nil
	}

	iter := s.client.Collection(s.collection).
		OrderBy("received_at", firestore.Desc).
		Limit(limit).
		Documents(ctx)
	defer iter.Stop()

	alerts := make([]*Alert, 0, limit)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("firestore LoadRecentAlerts: %w", err)
		}

		alert := documentToAlert(doc.Data())
		if alert == nil {
			continue
		}
		alerts = append(alerts, alert)
	}

	for i, j := 0, len(alerts)-1; i < j; i, j = i+1, j-1 {
		alerts[i], alerts[j] = alerts[j], alerts[i]
	}
	return alerts, nil
}

func alertToDocument(alert *Alert) map[string]interface{} {
	doc := map[string]interface{}{
		"ip":          alert.IP,
		"quantity":    alert.Quantity,
		"received_at": time.Now().UTC(),
	}

	if alert.DstPort != nil {
		doc["dst_port"] = *alert.DstPort
	}
	if alert.Url != nil {
		doc["url"] = *alert.Url
	}
	if alert.Threat != nil {
		doc["threat"] = *alert.Threat
	}
	if alert.Severity != nil {
		doc["severity"] = *alert.Severity
	}
	if alert.Tier != nil {
		doc["tier"] = *alert.Tier
	}
	if alert.LogType != nil {
		doc["log_type"] = *alert.LogType
	}
	if alert.FirstTimestamp != nil {
		doc["first_timestamp"] = alert.FirstTimestamp.UTC()
	}
	if alert.LastTimestamp != nil {
		doc["last_timestamp"] = alert.LastTimestamp.UTC()
	}
	if len(alert.Suricata) > 0 {
		doc["suricata"] = alert.Suricata
	}
	if len(alert.Modsec) > 0 {
		doc["modsec"] = alert.Modsec
	}
	if len(alert.Wazuh) > 0 {
		doc["wazuh"] = alert.Wazuh
	}

	return doc
}

func documentToAlert(doc map[string]interface{}) *Alert {
	ip := stringFromValue(doc["ip"])
	logType := stringFromValue(doc["log_type"])
	if ip == "" || logType == "" {
		return nil
	}

	quantity := intFromValue(doc["quantity"])
	if quantity == 0 {
		quantity = 1
	}

	alert := &Alert{
		IP:       ip,
		LogType:  stringPtr(logType),
		Quantity: quantity,
	}

	if value, ok := optionalInt(doc["dst_port"]); ok {
		alert.DstPort = &value
	}
	if value := stringFromValue(doc["url"]); value != "" {
		alert.Url = &value
	}
	if value := stringFromValue(doc["threat"]); value != "" {
		alert.Threat = &value
	}
	if value, ok := optionalInt(doc["severity"]); ok {
		alert.Severity = &value
	}
	if value, ok := optionalInt(doc["tier"]); ok {
		alert.Tier = &value
	}

	first := timeFromValue(doc["first_timestamp"])
	if first.IsZero() {
		first = timeFromValue(doc["received_at"])
	}
	if !first.IsZero() {
		alert.FirstTimestamp = &first
	}
	last := timeFromValue(doc["last_timestamp"])
	if last.IsZero() {
		last = first
	}
	if !last.IsZero() {
		alert.LastTimestamp = &last
	}

	return alert
}

func stringFromValue(value interface{}) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

func optionalInt(value interface{}) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}

func intFromValue(value interface{}) int {
	v, _ := optionalInt(value)
	return v
}

func timeFromValue(value interface{}) time.Time {
	if t, ok := value.(time.Time); ok {
		return t.UTC()
	}
	return time.Time{}
}

func stringPtr(value string) *string {
	return &value
}

func NewSharedData() *SharedData {
	return &SharedData{
		SuricataList: []*Alert{},
		ModsecList:   []*Alert{},
		WazuhList:    []*Alert{},
		AlertsList:   []*Alert{},
		IDSAlertsMap: map[string]*Alert{},
		AlertsMap:    map[string]*Alert{},
	}
}
