locals {
  # Repo root one level above terraform/ (Compose, grafana, prometheus, threat-central-go).
  repo_root = abspath("${path.module}/..")

  # Same idea as gcp-free-honeypot-lab: zip the workspace, exclude VCS and Terraform.
  bundle_excludes = [
    ".cursor",
    ".env",
    ".git",
    ".terraform-bundle",
    "terraform",
    "threat-central-go/threat-central",
    "threat-central-go/threat-central.exe",
  ]

  source_bucket_name = lower(var.source_bucket_name != null && var.source_bucket_name != "" ? var.source_bucket_name : "${var.project_id}-threat-central-bundles")
}

# Zip workspace files needed on the VM (Compose + Docker build contexts).
data "archive_file" "source_bundle" {
  type        = "zip"
  output_path = "${path.module}/.terraform-bundle/threat-central-runtime.zip"
  source_dir  = local.repo_root
  excludes    = local.bundle_excludes
}

# Latest Ubuntu 24.04 LTS (amd64); matches gcp-free-honeypot-lab image resolution.
data "google_compute_image" "ubuntu" {
  family  = "ubuntu-2404-lts-amd64"
  project = "ubuntu-os-cloud"
}

resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "firestore.googleapis.com",
    "iam.googleapis.com",
    "storage.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

module "iam" {
  source     = "./modules/iam"
  project_id = var.project_id

  depends_on = [google_project_service.apis]
}

module "firestore" {
  source     = "./modules/firestore"
  project_id = var.project_id
  region     = var.region

  depends_on = [google_project_service.apis]
}

# Private bucket Terraform uses to ship the zipped runtime to first-boot cloud-init on the VM.
resource "google_storage_bucket" "source" {
  project                     = var.project_id
  name                        = local.source_bucket_name
  location                    = var.region
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = var.source_bucket_force_destroy

  labels = {
    app = "threat-central"
  }

  depends_on = [google_project_service.apis]
}

# Single object identity the VM reads via IAM (same pattern as honeypot lab).
resource "google_storage_bucket_object" "source_bundle" {
  name   = var.bundle_object_key
  bucket = google_storage_bucket.source.name
  source = data.archive_file.source_bundle.output_path
}

resource "google_storage_bucket_iam_member" "vm_source_reader" {
  bucket = google_storage_bucket.source.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${module.iam.vm_service_account_email}"
}

resource "google_compute_network" "main" {
  project                 = var.project_id
  name                    = var.network_name
  auto_create_subnetworks = false

  depends_on = [google_project_service.apis]
}

resource "google_compute_subnetwork" "main" {
  project       = var.project_id
  name          = var.subnet_name
  ip_cidr_range = var.subnet_cidr
  network       = google_compute_network.main.id
  region        = var.region

  private_ip_google_access = true
}

resource "google_compute_firewall" "ssh" {
  project = var.project_id
  name    = "${var.network_name}-allow-ssh"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = var.admin_source_ranges
  target_tags   = ["threat-central-vm"]
}

resource "google_compute_firewall" "grafana" {
  project = var.project_id
  name    = "${var.network_name}-allow-grafana"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["3000"]
  }

  source_ranges = var.admin_source_ranges
  target_tags   = ["threat-central-vm"]
}

resource "google_compute_firewall" "receiver" {
  project = var.project_id
  name    = "${var.network_name}-allow-receiver"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }

  source_ranges = var.receiver_source_ranges
  target_tags   = ["threat-central-vm"]
}

resource "google_compute_instance" "threat_central" {
  project      = var.project_id
  name         = var.vm_name
  machine_type = var.vm_machine_type
  zone         = var.zone
  tags         = ["threat-central-vm"]

  boot_disk {
    initialize_params {
      image = data.google_compute_image.ubuntu.self_link
      size  = var.vm_boot_disk_size_gb
      type  = var.vm_boot_disk_type
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.main.id

    access_config {}
  }

  service_account {
    email  = module.iam.vm_service_account_email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  metadata = {
    # OS Login + cloud-init user-data (bootstrap script), same delivery model as gcp-free-honeypot-lab.
    enable-oslogin = var.enable_oslogin ? "TRUE" : "FALSE"
    user-data = templatefile("${path.module}/cloud-init.yaml", {
      project_id            = var.project_id
      firestore_collection  = var.firestore_collection
      bootstrap_limit       = var.firestore_bootstrap_limit
      bundle_bucket         = google_storage_bucket.source.name
      bundle_object_name    = google_storage_bucket_object.source_bundle.name
    })
  }

  allow_stopping_for_update = true

  depends_on = [
    google_storage_bucket_iam_member.vm_source_reader,
    google_storage_bucket_object.source_bundle,
    module.firestore,
  ]
}
