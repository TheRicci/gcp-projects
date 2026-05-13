package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg := LoadConfig()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := NewFirestoreStore(ctx, cfg.GCPProjectID, cfg.FirestoreCollection)
	if err != nil {
		log.Fatalf("failed to initialize Firestore storage: %v", err)
	}
	defer store.Close()

	go func() {
		log.Printf("metrics server listening on %s", cfg.MetricsAddr)
		if err := StartServer(cfg.MetricsAddr); err != nil {
			log.Fatalf("metrics server error: %v", err)
		}
	}()

	receiver := NewLogReceiver(cfg.ReceiverAddr)
	eng := NewEngine(receiver, NewSharedData(), store)
	if err := eng.Bootstrap(ctx, cfg.BootstrapLimit); err != nil {
		log.Fatalf("failed to rebuild state from Firestore: %v", err)
	}

	log.Printf("threat-central ingest service listening on %s", cfg.ReceiverAddr)
	log.Printf("normalized alerts will be written to Firestore collection %q", cfg.FirestoreCollection)
	if err := eng.Run(ctx); err != nil {
		log.Fatalf("engine stopped: %v", err)
	}
}
