# ══════════════════════════════════════════════════════════════════════════════
# terraform/gcp/main.tf — JeiGuard AI Google Cloud GKE Deployment
# Copyright © 2026 Jeiner Tello Nuñez — MIT License
# ══════════════════════════════════════════════════════════════════════════════
#
# Infraestructura en Google Cloud Platform:
#   • GKE Autopilot Cluster (GKE Standard con Autopilot)
#   • Google Cloud Pub/Sub (equivalente Kafka)
#   • Cloud SQL for PostgreSQL 16 (HA)
#   • Memorystore for Redis
#   • Artifact Registry (container registry)
#   • Cloud Armor (WAF + DDoS protection)
#   • Cloud KMS (gestión de claves)
#   • VPC con Private Service Connect
#   • Cloud Monitoring + Cloud Trace (OpenTelemetry)
#   • Binary Authorization (supply chain security)
# ══════════════════════════════════════════════════════════════════════════════

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.15"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.15"
    }
  }

  backend "gcs" {
    bucket = "jeiguard-ai-tfstate"
    prefix = "terraform/state"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

# ── Variables ─────────────────────────────────────────────────────────────────

variable "project_id" {
  type        = string
  description = "Google Cloud Project ID"
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "environment" {
  type    = string
  default = "production"
}

variable "gke_node_count" {
  type    = number
  default = 3
}

variable "gke_machine_type" {
  type    = string
  default = "n2-standard-4"
}

variable "gke_max_nodes" {
  type    = number
  default = 20
}

# ── APIs habilitadas ──────────────────────────────────────────────────────────

locals {
  gcp_services = [
    "container.googleapis.com",
    "sqladmin.googleapis.com",
    "redis.googleapis.com",
    "pubsub.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudkms.googleapis.com",
    "compute.googleapis.com",
    "servicenetworking.googleapis.com",
    "cloudtrace.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
    "binaryauthorization.googleapis.com",
    "secretmanager.googleapis.com",
  ]
  labels = {
    project     = "jeiguard-ai"
    version     = "2-0-0"
    environment = var.environment
    managed-by  = "terraform"
  }
}

resource "google_project_service" "apis" {
  for_each           = toset(local.gcp_services)
  service            = each.value
  disable_on_destroy = false
}

# ── VPC ───────────────────────────────────────────────────────────────────────

resource "google_compute_network" "main" {
  name                    = "jeiguard-vpc-${var.environment}"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "gke" {
  name          = "jeiguard-gke-subnet"
  ip_cidr_range = "10.0.0.0/20"
  region        = var.region
  network       = google_compute_network.main.id

  secondary_ip_range {
    range_name    = "gke-pods"
    ip_cidr_range = "10.16.0.0/12"
  }

  secondary_ip_range {
    range_name    = "gke-services"
    ip_cidr_range = "10.32.0.0/16"
  }

  private_ip_google_access = true
  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_subnetwork" "private" {
  name          = "jeiguard-private-subnet"
  ip_cidr_range = "10.1.0.0/24"
  region        = var.region
  network       = google_compute_network.main.id

  private_ip_google_access = true
}

# NAT Gateway
resource "google_compute_router" "main" {
  name    = "jeiguard-router"
  region  = var.region
  network = google_compute_network.main.id
}

resource "google_compute_router_nat" "main" {
  name                               = "jeiguard-nat"
  router                             = google_compute_router.main.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

# Private Service Access (para Cloud SQL y Redis)
resource "google_compute_global_address" "private_services" {
  name          = "jeiguard-private-services"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.main.id
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.main.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]
  depends_on              = [google_project_service.apis]
}

# ── Artifact Registry ─────────────────────────────────────────────────────────

resource "google_artifact_registry_repository" "main" {
  location      = var.region
  repository_id = "jeiguard-ai-${var.environment}"
  description   = "JeiGuard AI container registry"
  format        = "DOCKER"

  docker_config {
    immutable_tags = true
  }

  labels = local.labels
}

# ── Cloud KMS ─────────────────────────────────────────────────────────────────

resource "google_kms_key_ring" "main" {
  name     = "jeiguard-keyring-${var.environment}"
  location = var.region
}

resource "google_kms_crypto_key" "database" {
  name            = "jeiguard-db-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s" # 90 días
  purpose         = "ENCRYPT_DECRYPT"

  lifecycle {
    prevent_destroy = true
  }
}

# ── GKE Standard Cluster ──────────────────────────────────────────────────────

resource "google_container_cluster" "main" {
  provider           = google-beta
  name               = "jeiguard-gke-${var.environment}"
  location           = var.region
  network            = google_compute_network.main.id
  subnetwork         = google_compute_subnetwork.gke.id
  min_master_version = "1.29"

  remove_default_node_pool = true
  initial_node_count       = 1

  networking_mode = "VPC_NATIVE"
  ip_allocation_policy {
    cluster_secondary_range_name  = "gke-pods"
    services_secondary_range_name = "gke-services"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "0.0.0.0/0"
      display_name = "all"
    }
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  addons_config {
    http_load_balancing {
      disabled = false
    }
    horizontal_pod_autoscaling {
      disabled = false
    }
    gce_persistent_disk_csi_driver_config {
      enabled = true
    }
    gcp_filestore_csi_driver_config {
      enabled = true
    }
  }

  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  monitoring_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "APISERVER",
      "CONTROLLER_MANAGER",
      "SCHEDULER",
      "STORAGE",
      "HPA",
      "POD",
      "DAEMONSET",
      "DEPLOYMENT",
      "STATEFULSET",
    ]
    managed_prometheus {
      enabled = true
    }
  }

  logging_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "WORKLOADS",
    ]
  }

  database_encryption {
    state    = "ENCRYPTED"
    key_name = google_kms_crypto_key.database.id
  }

  resource_labels = local.labels
}

resource "google_container_node_pool" "inference" {
  name       = "inference-pool"
  location   = var.region
  cluster    = google_container_cluster.main.name

  autoscaling {
    min_node_count = 2
    max_node_count = var.gke_max_nodes
    location_policy = "BALANCED"
  }

  node_config {
    machine_type = var.gke_machine_type
    disk_size_gb = 100
    disk_type    = "pd-ssd"
    image_type   = "COS_CONTAINERD"

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    labels = {
      "node-type"        = "inference"
      "jeiguard-pool"    = "ml-inference"
    }

    taint {
      key    = "jeiguard.ai/workload"
      value  = "inference"
      effect = "NO_SCHEDULE"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    oauth_scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring",
      "https://www.googleapis.com/auth/trace.append",
    ]
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }
}

# ── Cloud Pub/Sub (Kafka equivalente) ─────────────────────────────────────────

locals {
  pubsub_topics = {
    "jeiguard-raw-flows"           = { partitions = 4, retention = "86400s" }
    "jeiguard-processed-features"  = { partitions = 4, retention = "86400s" }
    "jeiguard-predictions"         = { partitions = 2, retention = "86400s" }
    "jeiguard-alerts"              = { partitions = 2, retention = "604800s" }
    "jeiguard-dead-letter"         = { partitions = 1, retention = "604800s" }
  }
}

resource "google_pubsub_topic" "topics" {
  for_each = local.pubsub_topics
  name     = each.key
  labels   = local.labels

  message_retention_duration = each.value.retention
  message_storage_policy {
    allowed_persistence_regions = [var.region]
  }
}

resource "google_pubsub_subscription" "subscriptions" {
  for_each = local.pubsub_topics
  name     = "${each.key}-sub"
  topic    = google_pubsub_topic.topics[each.key].name

  message_retention_duration = each.value.retention
  ack_deadline_seconds       = 30
  retain_acked_messages      = false

  retry_policy {
    minimum_backoff = "5s"
    maximum_backoff = "300s"
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.topics["jeiguard-dead-letter"].id
    max_delivery_attempts = 5
  }
}

# ── Cloud SQL for PostgreSQL ──────────────────────────────────────────────────

resource "google_sql_database_instance" "main" {
  name             = "jeiguard-postgres-${var.environment}"
  database_version = "POSTGRES_16"
  region           = var.region

  settings {
    tier              = "db-custom-4-15360"
    availability_type = "REGIONAL"
    disk_size         = 100
    disk_type         = "PD_SSD"
    disk_autoresize   = true

    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 30
        retention_unit   = "COUNT"
      }
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.main.id
      ssl_mode        = "ENCRYPTED_ONLY"
    }

    insights_config {
      query_insights_enabled  = true
      query_string_length     = 1024
      record_application_tags = true
      record_client_address   = false
    }

    database_flags {
      name  = "max_connections"
      value = "200"
    }
  }

  deletion_protection = true
  depends_on          = [google_service_networking_connection.private_services]
}

resource "google_sql_database" "main" {
  name     = "jeiguard_ai"
  instance = google_sql_database_instance.main.name
}

# ── Memorystore for Redis ─────────────────────────────────────────────────────

resource "google_redis_instance" "main" {
  name           = "jeiguard-redis-${var.environment}"
  tier           = "STANDARD_HA"
  memory_size_gb = 4
  region         = var.region

  authorized_network = google_compute_network.main.id
  reserved_ip_range  = "10.3.0.0/29"
  connect_mode       = "PRIVATE_SERVICE_ACCESS"

  redis_version     = "REDIS_7_0"
  display_name      = "JeiGuard AI Redis"
  auth_enabled      = true
  transit_encryption_mode = "SERVER_AUTHENTICATION"

  maintenance_policy {
    weekly_maintenance_window {
      day = "TUESDAY"
      start_time {
        hours   = 3
        minutes = 0
        seconds = 0
        nanos   = 0
      }
    }
  }

  labels = local.labels
}

# ── Cloud Armor (WAF) ─────────────────────────────────────────────────────────

resource "google_compute_security_policy" "main" {
  name = "jeiguard-waf-policy"

  rule {
    action   = "deny(403)"
    priority = 1000
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('sqli-v33-stable')"
      }
    }
    description = "SQL Injection protection"
  }

  rule {
    action   = "deny(403)"
    priority = 1001
    match {
      expr {
        expression = "evaluatePreconfiguredWaf('xss-v33-stable')"
      }
    }
    description = "XSS protection"
  }

  rule {
    action   = "throttle"
    priority = 2000
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = 100
        interval_sec = 60
      }
    }
    description = "Rate limiting 100 req/min por IP"
  }

  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default allow rule"
  }
}

# ── Secret Manager ────────────────────────────────────────────────────────────

resource "google_secret_manager_secret" "jwt_secret" {
  secret_id = "jeiguard-jwt-secret-${var.environment}"
  labels    = local.labels

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }
}

resource "google_secret_manager_secret" "db_password" {
  secret_id = "jeiguard-db-password-${var.environment}"
  labels    = local.labels

  replication {
    user_managed {
      replicas {
        location = var.region
        customer_managed_encryption {
          kms_key_name = google_kms_crypto_key.database.id
        }
      }
    }
  }
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "gke_cluster_name" {
  value = google_container_cluster.main.name
}

output "gke_endpoint" {
  value     = google_container_cluster.main.endpoint
  sensitive = true
}

output "artifact_registry_url" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.main.repository_id}"
}

output "cloud_sql_connection_name" {
  value = google_sql_database_instance.main.connection_name
}

output "redis_host" {
  value     = google_redis_instance.main.host
  sensitive = true
}

output "pubsub_topics" {
  value = { for K, T in google_pubsub_topic.topics : K => T.id }
}
