# Threat Central

Threat Central is a VM-oriented alert ingestion stack. The Go service receives Wazuh, ModSecurity, and Suricata logs, normalizes them into one alert shape, writes the normalized alerts to Firestore, and exposes Prometheus metrics for Grafana.

## Information Flow

```text
Wazuh / ModSecurity / Suricata
  |
  | POST /logs with Log-Type: wazuh | modsec | suricata
  v
threat-central-go on a VM
  | normalize alert logs
  | write normalized alerts to Firestore
  | expose :2112/metrics
  v
Prometheus on the VM
  |
  v
Grafana on the VM
```

Firestore stores alert records. Prometheus stores metric time series. Grafana reads Prometheus.

## Repository Structure

```text
.
|-- threat-central-go/        # Go receiver, normalizer, Firestore writer, Prometheus exporter
|-- prometheus/               # Prometheus scrape config
|-- grafana/                  # Provisioned datasource and dashboard
|-- terraform/                # Minimal GCP VM, Firestore, source bucket, network, IAM
`-- docker-compose.yml        # VM-local stack
```

## Quick Start

On the VM, attach the Terraform-created service account or otherwise provide Google Application Default Credentials with Firestore access. Then set the project ID and start the stack:

```bash
export GCP_PROJECT_ID=YOUR_GCP_PROJECT_ID
docker compose up --build
```

Then open:

- Grafana: http://VM_IP_OR_TUNNEL:3000
- Prometheus: http://VM_IP_OR_TUNNEL:9090
- Threat Central health: http://VM_IP_OR_TUNNEL:8080/health
- Metrics: http://VM_IP_OR_TUNNEL:2112/metrics

Grafana login:

```text
admin / threatcentral
```

For remote access, prefer an SSH tunnel, VPN, Tailscale, or a TLS reverse proxy instead of exposing Grafana directly to the public internet.

## Send A Test Alert

```bash
curl -X POST http://localhost:8080/logs \
  -H "Log-Type: suricata" \
  -H "Content-Type: application/json" \
  -d '[{
    "timestamp":"2026-05-07T12:00:00.000000-0300",
    "src_ip":"203.0.113.10",
    "dest_port":443,
    "alert":{"signature":"ET TEST suspicious request","severity":2},
    "http":{"url":"/login"}
  }]'
```

Prometheus should then scrape metrics such as:

- `threat_central_alerts_total`
- `threat_central_unique_ips`
- `threat_central_alerts_by_source`
- `threat_central_severity_total`
- `threat_central_tier_total`
- `threat_central_storage_write_errors_total`

The normalized alert should also appear in the Firestore `alerts` collection.

On startup, the Go service reads recent normalized alerts from Firestore and rebuilds its in-memory alert groups before accepting new alerts. This keeps current gauges such as unique IPs and active alert groups useful after a VM or container restart.

## Configuration

The Go service accepts these environment variables and matching flags:

| Name | Default | Purpose |
|---|---:|---|
| `RECEIVER_ADDR` | `:8080` | Alert receiver listen address |
| `METRICS_ADDR` | `:2112` | Prometheus metrics listen address |
| `GCP_PROJECT_ID` | none | GCP project containing Firestore |
| `FIRESTORE_COLLECTION` | `alerts` | Firestore collection for normalized alerts |
| `FIRESTORE_BOOTSTRAP_LIMIT` | `5000` | Recent Firestore alerts used to rebuild runtime state |

## Minimal Cloud Path

Terraform provisions:

- Firestore database
- GCS bundle bucket containing a zipped Compose stack and app sources (built with the `archive` provider, like `gcp-free-honeypot-lab`)
- VPC, subnet, and firewall rules
- VM service account with Firestore, logging, and source-bucket read access
- Compute Engine VM (Ubuntu 24.04 LTS) whose first-boot **cloud-init** `user-data` installs Docker, downloads the zip from GCS, writes runtime env, and runs Docker Compose

Deploy outline:

```bash
cd terraform
terraform init
terraform apply -var-file=terraform.tfvars
```

On **first boot**, cloud-init runs `/usr/local/sbin/threat-central-bootstrap-app.sh` (same delivery pattern as the honeypot lab: metadata `user-data`):

```text
GCS bundle object (zip)
  -> curl + token from metadata downloads into /tmp
  -> unzip into /opt/threat-central
  -> copy /etc/threat-central.env to /opt/threat-central/.env
  -> docker compose up -d --build
```

Useful outputs:

- `grafana_url`
- `receiver_url`
- `vm_external_ip`
- `source_bucket`
- `runtime_bundle_gs_uri`
- `vm_service_account_email`

For a real deployment, restrict `admin_source_ranges` and `receiver_source_ranges` in your tfvars file. Grafana is protected by login, but it should not be left broadly exposed.

## Free Tier Shape

The Terraform defaults are intentionally set for GCP Always Free:

- Compute Engine: one `e2-micro` VM in `us-central1`, `us-east1`, or `us-west1`
- Disk: 30 GB `pd-standard` boot disk
- Cloud Storage: regional `STANDARD` bundle bucket in the same eligible US region as the VM (`us-central1`, `us-east1`, or `us-west1` via `var.region`)
- Firestore: one free Native mode database for normalized alerts

Prometheus stores time-series data on the VM disk. The Compose config keeps 30 days of data and caps Prometheus storage at 10 GB so the VM has room for Docker images, Grafana data, logs, and the OS.

Free tier is still quota-based. You can create charges if alert volume exceeds Firestore free reads/writes/storage, if outbound network traffic grows past the free allowance, if the source bucket grows beyond its free storage/operation limits, or if you change the VM, disk, or region away from the defaults.
