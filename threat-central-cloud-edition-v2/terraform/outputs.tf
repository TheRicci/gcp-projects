output "vm_name" {
  value = google_compute_instance.threat_central.name
}

output "vm_zone" {
  value = google_compute_instance.threat_central.zone
}

output "vm_external_ip" {
  value = google_compute_instance.threat_central.network_interface[0].access_config[0].nat_ip
}

output "grafana_url" {
  value = "http://${google_compute_instance.threat_central.network_interface[0].access_config[0].nat_ip}:3000"
}

output "receiver_url" {
  value = "http://${google_compute_instance.threat_central.network_interface[0].access_config[0].nat_ip}:8080/logs"
}

output "source_bucket" {
  value = google_storage_bucket.source.name
}

output "runtime_bundle_gs_uri" {
  description = "GCS object URI Terraform uploads when the zipped workspace artifact changes (cloud-init fetches this on first boot)."
  value       = "gs://${google_storage_bucket.source.name}/${google_storage_bucket_object.source_bundle.name}"
}

output "vm_service_account_email" {
  description = "Service account attached to the VM running threat-central."
  value       = module.iam.vm_service_account_email
}

output "firestore_database_name" {
  value = module.firestore.database_name
}
