# variables.tf is the input surface for this Terraform stack.
# Values can be overridden in terraform.tfvars or with -var arguments.

# Required project ID. This should be a dedicated learning/lab project.
variable "project_id" {
  description = "GCP project ID dedicated to the honeypot lab."
  type        = string
}

# Region used for regional resources. Check current GCP free-tier eligibility
# before changing this.
variable "region" {
  description = "GCP region. Pick a region that matches your current free-tier constraints."
  type        = string
  default     = "us-west1"
}

# Zone used for the single Compute Engine VM.
variable "zone" {
  description = "GCP zone for the single VM."
  type        = string
  default     = "us-west1-b"
}

# Name of the sensor VM. Several related resources derive names from this value.
variable "vm_name" {
  description = "Compute Engine VM name."
  type        = string
  default     = "honeypot-lab-dev"
}

# Machine size for the lab VM. e2-micro is intentionally small to keep the
# platform free-tier-oriented.
variable "machine_type" {
  description = "VM machine type. e2-micro is commonly used for free-tier labs where eligible."
  type        = string
  default     = "e2-micro"
}

# Boot disk size for the VM. Keep this modest because logs can grow quickly.
variable "boot_disk_size_gb" {
  description = "Boot disk size in GB."
  type        = number
  default     = 20
}

# SSH access control. The default is intentionally obvious, but you should
# replace it with your own public IP in /32 form before deploying.
variable "ssh_source_ranges" {
  description = "CIDR ranges allowed to SSH to the VM. Replace the default before deploying."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# TCP ports exposed to the internet for the honeypot surface.
variable "honeypot_tcp_ports" {
  description = "Internet-facing TCP ports exposed for the honeypot."
  type        = list(string)
  default     = ["80", "443", "8080"]
}

# Network interface name inside the VM. Suricata and Zeek sniff this interface.
variable "sensor_interface" {
  description = "Linux network interface that Suricata and Zeek should monitor."
  type        = string
  default     = "eth0"
}

# Pub/Sub topics used by the event pipeline. Terraform creates the topics;
# Docker and the Go shipper publish to them later.
variable "pubsub_topic_names" {
  description = "Pub/Sub topics used by the detection pipeline."
  type        = set(string)
  default = [
    "alerts.suricata",
    "events.zeek",
    "honeypot.requests",
    "events.normalized",
  ]
}

# Labels make it easier to identify and clean up lab resources in GCP.
variable "labels" {
  description = "Labels applied to supported resources."
  type        = map(string)
  default = {
    app = "honeypot-lab"
    env = "dev"
  }
}

# Object key for the zipped sensor runtime uploaded on each Terraform apply that changes the archive.
variable "sensor_bundle_object_key" {
  description = "Cloud Storage object name (may include slashes) for the zipped sensor Docker/Compose snapshot."
  type        = string
  default     = "sensor-bundle/latest.zip"
}
