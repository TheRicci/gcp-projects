package main

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// AlertsTotal counts every alert received, labelled by log source, tier and severity.
	AlertsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "threat_central_alerts_total",
			Help: "Total number of alerts received, by log source, tier and severity.",
		},
		[]string{"log_type", "tier", "severity"},
	)

	// UniqueIPs tracks the number of distinct attacking IPs currently tracked.
	UniqueIPs = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "threat_central_unique_ips",
			Help: "Number of distinct source IPs currently tracked.",
		},
	)

	// AlertsBySource tracks current alert list sizes per log source.
	AlertsBySource = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "threat_central_alerts_by_source",
			Help: "Current number of tracked alerts per log source.",
		},
		[]string{"log_type"},
	)

	// SeverityDistribution counts alerts bucketed by severity level.
	SeverityDistribution = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "threat_central_severity_total",
			Help: "Total alerts counted by severity level.",
		},
		[]string{"severity"},
	)

	// TierDistribution counts alerts bucketed by tier.
	TierDistribution = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "threat_central_tier_total",
			Help: "Total alerts counted by tier (1=watch, 2=block-temp, 3=block-perm).",
		},
		[]string{"tier"},
	)

	// StorageWriteErrors counts errors writing normalized alerts to durable storage.
	StorageWriteErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "threat_central_storage_write_errors_total",
			Help: "Total number of errors writing normalized alerts to durable storage.",
		},
	)
)

// StartServer starts the Prometheus metrics HTTP server on the given address.
// Call this in a goroutine: go StartServer(":2112")
func StartServer(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return http.ListenAndServe(addr, mux)
}
