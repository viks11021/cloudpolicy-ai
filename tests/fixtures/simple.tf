resource "google_storage_bucket" "example" {
  name     = "my-test-bucket"
  location = "US"

  labels = {
    environment = "test"
    owner       = "platform-team"
  }
}

resource "google_compute_firewall" "example" {
  name    = "test-fw"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["10.0.0.0/16"]
}
