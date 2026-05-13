variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for regional resources. Keep this in an Always Free eligible US region."
  type        = string
  default     = "us-central1"

  validation {
    condition     = contains(["us-central1", "us-east1", "us-west1"], var.region)
    error_message = "Use us-central1, us-east1, or us-west1 to stay inside GCP Always Free eligible regions."
  }
}

variable "zone" {
  description = "GCP zone for the VM. Keep this inside us-central1, us-east1, or us-west1 for Always Free."
  type        = string
  default     = "us-central1-a"

  validation {
    condition     = can(regex("^(us-central1|us-east1|us-west1)-[a-z]$", var.zone))
    error_message = "Use a zone inside us-central1, us-east1, or us-west1 for the Always Free e2-micro VM."
  }
}

variable "vm_name" {
  description = "Threat Central VM name"
  type        = string
  default     = "threat-central-vm"
}

variable "vm_machine_type" {
  description = "Threat Central VM machine type. e2-micro is the Always Free eligible VM size."
  type        = string
  default     = "e2-micro"

  validation {
    condition     = var.vm_machine_type == "e2-micro"
    error_message = "Use e2-micro to stay inside the Compute Engine Always Free VM allowance."
  }
}

variable "vm_boot_disk_size_gb" {
  description = "Boot disk size in GB. Always Free includes up to 30 GB-months of standard persistent disk."
  type        = number
  default     = 30

  validation {
    condition     = var.vm_boot_disk_size_gb > 0 && var.vm_boot_disk_size_gb <= 30
    error_message = "Use 30 GB or less to stay inside the Always Free standard persistent disk allowance."
  }
}

variable "vm_boot_disk_type" {
  description = "Boot disk type. Always Free covers standard persistent disk, not balanced or SSD disk."
  type        = string
  default     = "pd-standard"

  validation {
    condition     = var.vm_boot_disk_type == "pd-standard"
    error_message = "Use pd-standard to stay inside the Compute Engine Always Free disk allowance."
  }
}

variable "network_name" {
  description = "VPC network name"
  type        = string
  default     = "threat-central-net"
}

variable "subnet_name" {
  description = "VPC subnet name"
  type        = string
  default     = "threat-central-subnet"
}

variable "subnet_cidr" {
  description = "CIDR range for the Threat Central subnet"
  type        = string
  default     = "10.30.0.0/24"
}

variable "admin_source_ranges" {
  description = "CIDR ranges allowed to access SSH and Grafana. Restrict this to your IP/CIDR."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "receiver_source_ranges" {
  description = "CIDR ranges allowed to POST logs to the alert receiver on port 8080."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "enable_oslogin" {
  description = "Enable OS Login on the VM"
  type        = bool
  default     = true
}

variable "source_bucket_name" {
  description = "Optional globally unique GCS bucket name for deployment bundles. Defaults to lower(project_id)-threat-central-bundles."
  type        = string
  default     = null
}

variable "bundle_object_key" {
  description = "Cloud Storage object name (may include slashes) for the zipped Compose/runtime archive uploaded on each apply that changes the archive."
  type        = string
  default     = "threat-central/latest.zip"
}

variable "source_bucket_force_destroy" {
  description = "Allow Terraform to delete the source bucket even when it contains objects"
  type        = bool
  default     = true
}

variable "firestore_collection" {
  description = "Firestore collection for normalized alerts"
  type        = string
  default     = "alerts"
}

variable "firestore_bootstrap_limit" {
  description = "Recent Firestore alerts used to rebuild runtime state on VM startup"
  type        = number
  default     = 5000
}
