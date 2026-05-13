# Terraform CLI and provider versions. Matches the pattern used in gcp-free-honeypot-lab.
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }

    # Builds the zip artifact uploaded to Cloud Storage before the VM first boot (cloud-init).
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}
