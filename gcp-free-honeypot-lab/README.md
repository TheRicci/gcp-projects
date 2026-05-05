# Cloud-Native Honeypot and Threat Correlation Platform

This project is a low-cost Google Cloud security research lab. It exposes a small intentional attack surface, captures real network traffic with Suricata and Zeek, streams security events through Pub/Sub, and processes those events with Go-based Cloud Functions.

It is meant for learning, research, and portfolio work. It is not a production SOC, a managed SIEM, or a hardened internet service.

## Architecture

```text
INTERNET
   |
   v
GCP free-tier VM
   - Docker Compose
   - HTTP honeypot
   - Suricata
   - Zeek
   - Go log shipper
   |
   v
Pub/Sub topics
   - alerts.suricata
   - events.zeek
   - honeypot.requests
   - events.normalized
   |
   v
Cloud Functions in Go
   - normalize IDS and honeypot events
   - extract indicators
   - emit higher-level security events
   |
   v
Correlation and intelligence layer
   - pattern detection
   - severity scoring
   - future LLM-assisted triage
```

## Repository Layout

```text
.
|-- cmd/
|   |-- honeypot/          # HTTP honeypot service
|   `-- log-shipper/       # VM log tailer that publishes to Pub/Sub
|-- docker/                # Container build files
|-- docs/                  # Architecture and operating runbooks
|-- functions/
|   |-- correlator/        # Go Cloud Function skeleton
|   `-- normalizer/        # Go Cloud Function skeleton and tests
|-- terraform/             # GCP VM, firewall, IAM, Pub/Sub topics
|-- docker-compose.yml     # VM runtime stack
`-- .env.example
```

## Core Principles

- Free tier first: one small VM, no Kubernetes, no managed SIEM.
- Separation of concerns: Terraform provisions cloud infrastructure; Docker Compose runs packet and application sensors.
- Real tools: Suricata for signature alerts and Zeek for network behavior metadata.
- Cloud-native transport: Pub/Sub decouples detection from analysis.
- Go analysis layer: Cloud Functions normalize and correlate event streams.

## Quick Start

1. Create or select a GCP project.
2. Enable the Compute Engine, Pub/Sub, Cloud Functions, Cloud Build, Eventarc, and Artifact Registry APIs.
3. Configure Terraform variables:

   ```powershell
   Copy-Item terraform/terraform.tfvars.example terraform/terraform.tfvars
   ```

4. Deploy the infrastructure:

   ```powershell
   terraform -chdir=terraform init
   terraform -chdir=terraform apply
   ```

5. Copy the runtime files to the VM, create `.env` from `.env.example`, and run:

   ```bash
   docker compose up -d --build
   ```

See [docs/runbook.md](docs/runbook.md) for the full operating flow.

## Go Modules

Each runnable Go component has its own `go.mod`:

- `cmd/honeypot`
- `cmd/log-shipper`
- `functions/normalizer`
- `functions/correlator`

There is no root `go.mod`. That is intentional: each component is built or deployed from its own folder.

See [docs/runtime.md](docs/runtime.md) for the log shipper command format.

## Safety Notes

This lab intentionally attracts unsolicited traffic. Use an isolated GCP project, keep SSH restricted to your IP address, avoid storing secrets on the VM, and monitor billing while you learn. GCP free-tier terms can change, so verify the current free program before leaving the lab running long term.
