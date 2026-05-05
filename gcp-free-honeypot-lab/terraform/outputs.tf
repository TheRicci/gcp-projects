# outputs.tf prints the values you usually need after apply.

# VM name, useful for gcloud compute ssh/scp commands.
output "vm_name" {
  description = "Compute Engine VM name."
  value       = google_compute_instance.sensor.name
}

# VM zone, also needed by most gcloud compute commands.
output "vm_zone" {
  description = "Compute Engine VM zone."
  value       = google_compute_instance.sensor.zone
}

# Ephemeral public IP that internet scanners will hit.
output "vm_external_ip" {
  description = "Ephemeral external IP attached to the VM."
  value       = google_compute_instance.sensor.network_interface[0].access_config[0].nat_ip
}

# Service account email attached to the VM.
output "vm_service_account" {
  description = "Service account used by the VM runtime."
  value       = google_service_account.vm.email
}

# Pub/Sub topic IDs created for the pipeline.
output "pubsub_topics" {
  description = "Pub/Sub topic resource IDs."
  value = {
    for name, topic in google_pubsub_topic.pipeline : name => topic.id
  }
}
