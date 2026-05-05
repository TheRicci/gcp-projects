package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"cloud.google.com/go/pubsub"
)

type sourceDef struct {
	Name  string
	Path  string
	Topic string
}

type sourceFlags []sourceDef

type offsetState map[string]int64

func main() {
	var sources sourceFlags
	projectID := flag.String("project", getenv("GCP_PROJECT_ID", ""), "GCP project ID")
	statePath := flag.String("state", getenv("SHIPPER_STATE", "/var/lib/honeypot-log-shipper/state.json"), "offset state path")
	pollInterval := flag.Duration("poll", durationFromEnv("LOG_SHIPPER_POLL", 5*time.Second), "poll interval")
	flag.Var(&sources, "source", "source definition as name:path:topic; repeat for each log")
	flag.Parse()

	if *projectID == "" {
		log.Fatal("project is required")
	}
	if len(sources) == 0 {
		log.Fatal("at least one -source is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := pubsub.NewClient(ctx, *projectID)
	if err != nil {
		log.Fatalf("create pubsub client: %v", err)
	}
	defer client.Close()

	state, err := loadState(*statePath)
	if err != nil {
		log.Fatalf("load state: %v", err)
	}

	shipper := &shipper{
		client: client,
		topics: map[string]*pubsub.Topic{},
		state:  state,
	}

	ticker := time.NewTicker(*pollInterval)
	defer ticker.Stop()

	log.Printf("log shipper started with %d sources", len(sources))
	for {
		for _, source := range sources {
			if err := shipper.shipSource(ctx, source); err != nil {
				log.Printf("ship %s: %v", source.Name, err)
			}
		}
		if err := saveState(*statePath, shipper.state); err != nil {
			log.Printf("save state: %v", err)
		}

		select {
		case <-ctx.Done():
			log.Println("log shipper stopping")
			return
		case <-ticker.C:
		}
	}
}

type shipper struct {
	client *pubsub.Client
	topics map[string]*pubsub.Topic
	state  offsetState
}

func (s *shipper) shipSource(ctx context.Context, source sourceDef) error {
	file, err := os.Open(source.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	offset := s.state[source.Path]
	if offset > info.Size() {
		offset = 0
	}

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return err
	}

	reader := bufio.NewReader(file)
	currentOffset := offset
	for {
		line, err := reader.ReadString('\n')
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		nextOffset := currentOffset + int64(len(line))
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			currentOffset = nextOffset
			s.state[source.Path] = currentOffset
			continue
		}

		if err := s.publish(ctx, source, []byte(line)); err != nil {
			return err
		}
		currentOffset = nextOffset
		s.state[source.Path] = currentOffset
	}

	return nil
}

func (s *shipper) publish(ctx context.Context, source sourceDef, data []byte) error {
	topic := s.topic(source.Topic)
	result := topic.Publish(ctx, &pubsub.Message{
		Data: data,
		Attributes: map[string]string{
			"source":     source.Name,
			"log_path":   source.Path,
			"shipped_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	})

	id, err := result.Get(ctx)
	if err != nil {
		return err
	}
	log.Printf("published source=%s topic=%s message_id=%s", source.Name, source.Topic, id)
	return nil
}

func (s *shipper) topic(name string) *pubsub.Topic {
	if topic, ok := s.topics[name]; ok {
		return topic
	}
	topic := s.client.Topic(name)
	s.topics[name] = topic
	return topic
}

func (s *sourceFlags) String() string {
	return fmt.Sprint([]sourceDef(*s))
}

func (s *sourceFlags) Set(value string) error {
	parts := strings.SplitN(value, ":", 3)
	if len(parts) != 3 {
		return fmt.Errorf("source must be name:path:topic")
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return fmt.Errorf("source fields cannot be empty")
	}
	*s = append(*s, sourceDef{Name: parts[0], Path: parts[1], Topic: parts[2]})
	return nil
}

func loadState(path string) (offsetState, error) {
	state := offsetState{}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&state); err != nil {
		return nil, err
	}
	return state, nil
}

func saveState(path string, state offsetState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(state); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}

func getenv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func durationFromEnv(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
