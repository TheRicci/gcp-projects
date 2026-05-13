package main

import (
	"flag"
	"os"
	"strconv"
)

// Config holds application configuration parameters.
type Config struct {
	ReceiverAddr        string
	MetricsAddr         string
	GCPProjectID        string
	FirestoreCollection string
	BootstrapLimit      int
}

// LoadConfig parses flags and environment variables to build Config.
func LoadConfig() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.ReceiverAddr, "receiver-addr", getEnv("RECEIVER_ADDR", ":8080"), "alert receiver listen address")
	flag.StringVar(&cfg.MetricsAddr, "metrics-addr", getEnv("METRICS_ADDR", ":2112"), "Prometheus metrics listen address")
	flag.StringVar(&cfg.GCPProjectID, "gcp-project-id", getEnv("GCP_PROJECT_ID", ""), "GCP project ID for Firestore")
	flag.StringVar(&cfg.FirestoreCollection, "firestore-collection", getEnv("FIRESTORE_COLLECTION", "alerts"), "Firestore collection for normalized alerts")
	flag.IntVar(&cfg.BootstrapLimit, "bootstrap-limit", getIntEnv("FIRESTORE_BOOTSTRAP_LIMIT", 5000), "Maximum recent Firestore alerts used to rebuild in-memory state on startup")
	flag.Parse()
	return cfg
}

// getEnv returns env var or fallback.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getIntEnv(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		parsed, err := strconv.Atoi(v)
		if err == nil {
			return parsed
		}
	}
	return fallback
}
