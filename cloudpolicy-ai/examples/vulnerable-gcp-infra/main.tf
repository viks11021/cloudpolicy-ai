# Intentionally non-compliant GCP infrastructure, used to demonstrate the
# scanner. Do not deploy this — every resource here trips at least one rule.

resource "google_storage_bucket" "data_lake" {
  name     = "acme-data-lake-demo"
  location = "US"
  # No uniform_bucket_level_access -> GCS-001
  # No versioning block -> GCS-003
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.data_lake.name
  role   = "roles/storage.objectViewer"
  member = "allUsers" # -> GCS-002
}

resource "google_compute_firewall" "allow_ssh" {
  name    = "allow-ssh-anywhere"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"] # -> FW-001
}

resource "google_compute_firewall" "allow_everything" {
  name    = "allow-all"
  network = "default"

  allow {
    protocol = "all" # -> FW-002
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_project_iam_member" "broad_access" {
  project = "acme-demo-project"
  role    = "roles/owner" # -> IAM-001
  member  = "serviceAccount:ci-deployer@acme-demo-project.iam.gserviceaccount.com"
}

resource "google_project_iam_member" "public_viewer" {
  project = "acme-demo-project"
  role    = "roles/viewer"
  member  = "allAuthenticatedUsers" # -> IAM-002
}

resource "google_sql_database_instance" "orders_db" {
  name             = "orders-db"
  database_version = "POSTGRES_15"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true # -> SQL-001
    }
    # No backup_configuration -> SQL-002
  }
}
