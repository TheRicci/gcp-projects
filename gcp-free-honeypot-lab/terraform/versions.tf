# versions.tf defines the Terraform CLI and provider versions used by this lab.
# Keeping versions explicit makes future runs more predictable.
terraform {
  # Require a modern Terraform version, but do not pin to one exact patch release.
  required_version = ">= 1.5.0"

  # This lab only needs the Google provider because all cloud resources are in GCP.
  required_providers {
    google = {
      # Official HashiCorp Google Cloud provider.
      source = "hashicorp/google"

      # Allow current major versions 5 and 6, while avoiding an automatic jump to 7.
      version = ">= 5.0, < 7.0"
    }

    # Builds the zip artifact uploaded to Cloud Storage before the VM boots.
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

# Default provider configuration. Individual resources inherit these values unless
# they explicitly override project, region, or zone.
provider "google" {
  # GCP project where the lab resources will be created.
  project = var.project_id

  # Default regional location for regional resources such as subnetworks.
  region = var.region

  # Default zonal location for zonal resources such as the VM.
  zone = var.zone
}
