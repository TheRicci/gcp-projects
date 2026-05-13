variable "project_id" { type = string }

resource "google_service_account" "vm" {
  account_id   = "tc-vm-sa"
  display_name = "threat-central VM service account"
  project      = var.project_id
}

resource "google_project_iam_member" "vm_firestore" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.vm.email}"
}

resource "google_project_iam_member" "vm_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.vm.email}"
}

output "vm_service_account_email" {
  value = google_service_account.vm.email
}
