locals {
  network_name = "${var.vm_name}-net"

  subnet_name = "${var.vm_name}-subnet"

  topic_names = {
    suricata   = "alerts.suricata"
    zeek       = "events.zeek"
    honeypot   = "honeypot.requests"
    normalized = "events.normalized"
  }

  repo_root = abspath("${path.module}/..")

  sensor_bundle_excludes = [
    ".cursor",
    ".env",
    ".git",
    "bin",
    "docs",
    "functions",
    "logs",
    "mcps",
    "state",
    "terraform",
  ]
}

# Zip workspace files needed on the VM (Compose + Docker build context).
data "archive_file" "sensor_bundle" {
  type        = "zip"
  output_path = "${path.module}/.terraform-bundle/honeypot-sensor-runtime.zip"

  source_dir = local.repo_root
  excludes   = local.sensor_bundle_excludes
}

resource "google_project_service" "storage_api" {
  project                    = var.project_id
  service                    = "storage.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}

# Private bucket Terraform uses to ship the Compose runtime to first-boot cloud-init on the VM.
resource "google_storage_bucket" "sensor_deploy" {
  project                     = var.project_id
  name                        = "${var.project_id}-honeypot-sensor-bundles"
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true

  labels = var.labels

  depends_on = [google_project_service.storage_api]
}

# VM reads only this single object identity via IAM; no anonymous access is required or recommended.
resource "google_storage_bucket_iam_member" "vm_sensor_bundle_reader" {
  bucket = google_storage_bucket.sensor_deploy.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.vm.email}"
}

resource "google_storage_bucket_object" "sensor_bundle" {
  name   = var.sensor_bundle_object_key
  bucket = google_storage_bucket.sensor_deploy.name
  source = data.archive_file.sensor_bundle.output_path
}

# Look up the latest Ubuntu 24.04 LTS (amd64) image from ubuntu-os-cloud.
# Family ubuntu-2404-lts-amd64 tracks current LTS builds; avoids a hardcoded image self-link.
data "google_compute_image" "ubuntu" {
  family  = "ubuntu-2404-lts-amd64"
  project = "ubuntu-os-cloud"
}

# Private VPC for the lab VM. Using a dedicated network keeps the lab isolated
# from any default network that may already exist in the project.
resource "google_compute_network" "lab" {
  name                    = local.network_name
  auto_create_subnetworks = false
}

# Regional subnet where the VM network interface will live.
resource "google_compute_subnetwork" "lab" {
  name = local.subnet_name

  ip_cidr_range = "10.42.0.0/24"

  region = var.region

  network = google_compute_network.lab.id

  private_ip_google_access = true
}

# Create every Pub/Sub topic in the pipeline. Topics are the boundary between
# VM-based packet/log capture and serverless analysis.
resource "google_pubsub_topic" "pipeline" {
  # One topic resource is created for each name in var.pubsub_topic_names.
  for_each = var.pubsub_topic_names

  # Pub/Sub topic name, for example alerts.suricata.
  name = each.value

  message_retention_duration = "604800s"

  labels = var.labels
}

# Service account attached to the VM. The VM uses this identity when the
# log shipper publishes events to Pub/Sub.
resource "google_service_account" "vm" {
  account_id = "honeypot-lab-vm"

  display_name = "Honeypot lab VM publisher"
}

# Allow the VM service account to publish messages to Pub/Sub topics.
resource "google_project_iam_member" "vm_pubsub_publisher" {
  project = var.project_id

  # Publisher is enough for the VM log shipper; it does not need subscriber/admin access.
  role = "roles/pubsub.publisher"

  # Bind the role to the VM service account.
  member = "serviceAccount:${google_service_account.vm.email}"
}

# Allow the VM service account to write basic logs to Cloud Logging.
resource "google_project_iam_member" "vm_log_writer" {
  # IAM binding is applied at project scope.
  project = var.project_id

  # Lets the guest agent and runtime write logs without broad permissions.
  role = "roles/logging.logWriter"

  # Bind the role to the VM service account.
  member = "serviceAccount:${google_service_account.vm.email}"
}

# Firewall rule for SSH administration.
resource "google_compute_firewall" "ssh" {
  name = "${var.vm_name}-ssh"

  # Apply this rule inside the dedicated lab VPC.
  network = google_compute_network.lab.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # Caller-controlled SSH source ranges. Use your own public IP /32 in practice.
  source_ranges = var.ssh_source_ranges

  # Only VMs with this tag receive the rule.
  target_tags = ["honeypot-lab"]
}

# Firewall rule for the intentional honeypot attack surface.
resource "google_compute_firewall" "honeypot_tcp" {
  name = "${var.vm_name}-honeypot-tcp"

  # Apply this rule inside the dedicated lab VPC.
  network = google_compute_network.lab.name

  # Permit the configured TCP ports to reach the honeypot VM.
  allow {
    protocol = "tcp"
    ports    = var.honeypot_tcp_ports
  }

  # Intentionally internet-facing. This is what lets the lab collect real scans.
  source_ranges = ["0.0.0.0/0"]

  # Only VMs with this tag receive the rule.
  target_tags = ["honeypot-lab"]
}

# The single VM that runs Docker Compose, the honeypot, Suricata, Zeek, and the
# log shipper. Packet visibility requires a VM; Cloud Functions cannot see raw packets.
resource "google_compute_instance" "sensor" {
  name = var.vm_name

  machine_type = var.machine_type

  zone = var.zone

  tags = ["honeypot-lab"]

  labels = var.labels

  # Lets Terraform stop the VM if a future update requires changing immutable fields.
  allow_stopping_for_update = true

  # Boot disk definition.
  boot_disk {
    # Initial disk settings used when Terraform creates the VM.
    initialize_params {
      # Latest Ubuntu 24.04 LTS image resolved by the data source above.
      image = data.google_compute_image.ubuntu.self_link

      size = var.boot_disk_size_gb

      # Standard persistent disk keeps the lab simple and low cost.
      type = "pd-standard"
    }
  }

  # Primary network interface for the VM.
  network_interface {
    # Attach the VM to the dedicated subnet.
    subnetwork = google_compute_subnetwork.lab.id

    # Empty access_config requests an ephemeral external IPv4 address.
    # Avoid reserving a static IP unless you need one, because idle static IPs can cost money.
    access_config {}
  }

  # VM metadata configures OS Login and passes a cloud-init template to the guest.
  metadata = {
    # Use IAM/OS Login for SSH account management instead of static SSH keys in metadata.
    enable-oslogin = "TRUE"

    # Render cloud-init.yaml with Terraform values, then pass it as user-data.
    user-data = templatefile("${path.module}/cloud-init.yaml", {
      # Project ID becomes GCP_PROJECT_ID in /opt/honeypot-lab/.env.
      project_id = var.project_id

      # Interface name used by Suricata and Zeek.
      sensor_interface = var.sensor_interface

      # Topic names passed to Docker Compose through the generated .env file.
      suricata_topic     = local.topic_names.suricata
      zeek_topic         = local.topic_names.zeek
      honeypot_topic     = local.topic_names.honeypot
      normalized_topic   = local.topic_names.normalized
      bundle_bucket      = google_storage_bucket.sensor_deploy.name
      bundle_object_name = google_storage_bucket_object.sensor_bundle.name
    })
  }

  # Attach the least-privilege service account used by the VM runtime.
  service_account {
    # VM identity.
    email = google_service_account.vm.email

    # Cloud-platform scope allows IAM roles to define the real permission boundary.
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  # Bundle object and read IAM must exist before first boot pulls the artifact from Cloud Storage.
  depends_on = [
    google_project_iam_member.vm_pubsub_publisher,
    google_project_iam_member.vm_log_writer,
    google_pubsub_topic.pipeline,
    google_storage_bucket_iam_member.vm_sensor_bundle_reader,
    google_storage_bucket_object.sensor_bundle,
  ]
}
