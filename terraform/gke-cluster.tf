###############################################################################
# gke-cluster.tf — hardened GKE, Artifact Registry front door, deploy gate
#
# Posture (deliberate decisions):
#   * Private regional cluster: nodes have NO public IPs and (per Module 1)
#     no NAT — the cluster cannot reach the internet at all. Every image
#     pull goes to Artifact Registry over the private googleapis VIP;
#     third-party images (Vault, Linkerd) enter ONLY through AR remote
#     (pull-through mirror) repositories declared here.
#   * CMEK end-to-end: etcd application-layer secrets, node boot disks, and
#     Artifact Registry content are all encrypted with keys on the Module 1
#     platform keyring.
#   * Confidential Nodes (AMD SEV): RAM encrypted in use — ledger material
#     is protected at rest, in transit (Linkerd mTLS, Module 3), AND in use.
#   * Workload Identity + GKE metadata server: pods can only obtain the
#     identity explicitly bound to their KSA (workload-identity.tf); the
#     node SA below is minimal (logs, metrics, image pull).
#   * Binary Authorization: default-DENY admission; only images from this
#     project's AR repos (and Google-maintained system images) may run.
#   * Dataplane V2 (eBPF): NetworkPolicy enforcement built in — Module 3
#     manifests ship default-deny policies that this datapath enforces.
###############################################################################

# ===========================================================================
# KMS — GKE secrets (etcd envelope) + node boot disk keys
# ===========================================================================

resource "google_kms_crypto_key" "gke_secrets" {
  name            = "gke-secrets-cmek"
  key_ring        = google_kms_key_ring.platform.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.kms_rotation_period

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "gke_node_disks" {
  name            = "gke-node-disks-cmek"
  key_ring        = google_kms_key_ring.platform.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.kms_rotation_period

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# GKE service agent encrypts/decrypts etcd secrets envelopes.
resource "google_kms_crypto_key_iam_member" "gke_secrets" {
  crypto_key_id = google_kms_crypto_key.gke_secrets.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.this.number}@container-engine-robot.iam.gserviceaccount.com"
}

# Compute service agent attaches CMEK-encrypted boot disks.
resource "google_kms_crypto_key_iam_member" "gke_node_disks" {
  crypto_key_id = google_kms_crypto_key.gke_node_disks.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_project.this.number}@compute-system.iam.gserviceaccount.com"
}

# ===========================================================================
# Artifact Registry — the single front door for ALL container images
#   * images:            first-party (ledger-api, pushed by CI — Module 4)
#   * dockerhub-remote:  pull-through mirror of Docker Hub (Vault image)
#   * l5d-remote:        pull-through mirror of cr.l5d.io (Linkerd images)
# Cluster pull rewrites (used in Modules 2/3 manifests):
#   docker.io/hashicorp/vault:X  → {region}-docker.pkg.dev/{proj}/dockerhub-remote/hashicorp/vault:X
#   cr.l5d.io/linkerd/proxy:X    → {region}-docker.pkg.dev/{proj}/l5d-remote/linkerd/proxy:X
# ===========================================================================

resource "google_project_service_identity" "artifactregistry" {
  provider = google-beta

  project = var.project_id
  service = "artifactregistry.googleapis.com"
}

resource "google_kms_crypto_key" "artifact_registry" {
  name            = "artifact-registry-cmek"
  key_ring        = google_kms_key_ring.platform.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.kms_rotation_period

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "artifact_registry" {
  crypto_key_id = google_kms_crypto_key.artifact_registry.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = google_project_service_identity.artifactregistry.member
}

resource "google_artifact_registry_repository" "images" {
  repository_id = "images"
  location      = var.region
  format        = "DOCKER"
  description   = "First-party ledger platform images (CI-pushed, immutable tags)"
  kms_key_name  = google_kms_crypto_key.artifact_registry.id

  docker_config {
    immutable_tags = true # a published tag can never be repointed
  }

  cleanup_policy_dry_run = false

  cleanup_policies {
    id     = "delete-untagged"
    action = "DELETE"
    condition {
      tag_state  = "UNTAGGED"
      older_than = "1209600s" # 14 days
    }
  }

  cleanup_policies {
    id     = "keep-recent-releases"
    action = "KEEP"
    most_recent_versions {
      keep_count = 50
    }
  }

  depends_on = [google_kms_crypto_key_iam_member.artifact_registry]
}

resource "google_artifact_registry_repository" "dockerhub_remote" {
  repository_id = "dockerhub-remote"
  location      = var.region
  format        = "DOCKER"
  mode          = "REMOTE_REPOSITORY"
  description   = "Pull-through cache of Docker Hub (only sanctioned path for Hub images)"
  kms_key_name  = google_kms_crypto_key.artifact_registry.id

  remote_repository_config {
    description = "Docker Hub upstream"
    docker_repository {
      public_repository = "DOCKER_HUB"
    }
  }

  depends_on = [google_kms_crypto_key_iam_member.artifact_registry]
}

resource "google_artifact_registry_repository" "l5d_remote" {
  repository_id = "l5d-remote"
  location      = var.region
  format        = "DOCKER"
  mode          = "REMOTE_REPOSITORY"
  description   = "Pull-through cache of cr.l5d.io (Linkerd release registry)"
  kms_key_name  = google_kms_crypto_key.artifact_registry.id

  remote_repository_config {
    description = "Linkerd release registry upstream"
    docker_repository {
      custom_repository {
        uri = "https://cr.l5d.io"
      }
    }
  }

  depends_on = [google_kms_crypto_key_iam_member.artifact_registry]
}

# ===========================================================================
# Node service account — minimal: logs, metrics, image pull. Nothing else.
# Repo-scoped AR grants (not project-level reader).
# ===========================================================================

resource "google_service_account" "gke_nodes" {
  account_id   = "${var.project_name}-gke-nodes"
  display_name = "GKE node pool service account (minimal)"
}

resource "google_project_iam_member" "gke_nodes_logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = google_service_account.gke_nodes.member
}

resource "google_project_iam_member" "gke_nodes_metrics" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = google_service_account.gke_nodes.member
}

resource "google_project_iam_member" "gke_nodes_monitoring_viewer" {
  project = var.project_id
  role    = "roles/monitoring.viewer"
  member  = google_service_account.gke_nodes.member
}

resource "google_project_iam_member" "gke_nodes_resource_metadata" {
  project = var.project_id
  role    = "roles/stackdriver.resourceMetadata.writer"
  member  = google_service_account.gke_nodes.member
}

resource "google_artifact_registry_repository_iam_member" "gke_nodes_pull" {
  for_each = {
    images    = google_artifact_registry_repository.images.name
    dockerhub = google_artifact_registry_repository.dockerhub_remote.name
    l5d       = google_artifact_registry_repository.l5d_remote.name
  }

  location   = var.region
  repository = each.value
  role       = "roles/artifactregistry.reader"
  member     = google_service_account.gke_nodes.member
}

# ===========================================================================
# GKE cluster — private, regional, confidential, CMEK-encrypted
# ===========================================================================

resource "google_container_cluster" "ledger" {
  name     = local.cluster_name
  location = var.region

  network    = google_compute_network.ledger.self_link
  subnetwork = google_compute_subnetwork.gke.self_link

  # Dedicated node pool below; the throwaway default pool is removed.
  remove_default_node_pool = true
  initial_node_count       = 1

  networking_mode   = "VPC_NATIVE"
  datapath_provider = "ADVANCED_DATAPATH" # Dataplane V2: eBPF + NetworkPolicy

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = var.enable_private_endpoint
    master_ipv4_cidr_block  = var.master_cidr

    master_global_access_config {
      enabled = false
    }
  }

  master_authorized_networks_config {
    gcp_public_cidrs_access_enabled = false

    dynamic "cidr_blocks" {
      for_each = var.master_authorized_networks
      content {
        cidr_block   = cidr_blocks.value.cidr_block
        display_name = cidr_blocks.value.display_name
      }
    }
  }

  release_channel {
    channel = var.gke_release_channel
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # etcd application-layer secrets envelope encryption (CMEK).
  database_encryption {
    state    = "ENCRYPTED"
    key_name = google_kms_crypto_key.gke_secrets.id
  }

  # Deploy-time gate — policy defined in google_binary_authorization_policy.
  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  # Memory encrypted in use (AMD SEV) — applies to ALL node pools.
  confidential_nodes {
    enabled = var.enable_confidential_nodes
  }

  enable_shielded_nodes = true

  addons_config {
    horizontal_pod_autoscaling {
      disabled = false
    }
    http_load_balancing {
      disabled = false
    }
    gce_persistent_disk_csi_driver_config {
      enabled = true
    }
  }

  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
    managed_prometheus {
      enabled = true # Module 5 collector writes into Managed Prometheus
    }
  }

  security_posture_config {
    mode               = "BASIC"
    vulnerability_mode = "VULNERABILITY_BASIC"
  }

  cost_management_config {
    enabled = true
  }

  maintenance_policy {
    recurring_window {
      start_time = "2026-01-03T03:00:00Z"
      end_time   = "2026-01-03T09:00:00Z"
      recurrence = "FREQ=WEEKLY;BYDAY=SA,SU"
    }
  }

  deletion_protection = true

  resource_labels = {
    component = "ledger-orchestration"
  }

  depends_on = [
    google_project_service.required,
    google_kms_crypto_key_iam_member.gke_secrets,
  ]
}

# ===========================================================================
# Node pool — autoscaled, shielded, CMEK boot disks, GKE metadata server
# ===========================================================================

resource "google_container_node_pool" "general" {
  name     = "general"
  cluster  = google_container_cluster.ledger.name
  location = var.region

  # Regional pool: counts are PER ZONE (3 zones by default).
  autoscaling {
    min_node_count  = var.node_count_min_per_zone
    max_node_count  = var.node_count_max_per_zone
    location_policy = "BALANCED"
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  upgrade_settings {
    max_surge       = 1
    max_unavailable = 0
  }

  node_config {
    machine_type = var.node_machine_type # n2d default → SEV-capable
    image_type   = "COS_CONTAINERD"

    disk_type         = "pd-ssd"
    disk_size_gb      = var.node_disk_size_gb
    boot_disk_kms_key = google_kms_crypto_key.gke_node_disks.id

    service_account = google_service_account.gke_nodes.email
    # Broad scope is safe: effective permissions are the (minimal) IAM
    # roles on the node SA; scopes only cap them.
    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

    tags = [local.gke_node_tag] # firewall targeting (Module 1)

    labels = {
      workload-tier = "general"
    }

    metadata = {
      disable-legacy-endpoints = "true"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    # Pods see ONLY the GKE metadata server → Workload Identity enforced;
    # node credentials are unreachable from workloads.
    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }

  depends_on = [google_kms_crypto_key_iam_member.gke_node_disks]
}

# ===========================================================================
# Binary Authorization — default DENY; only this project's AR repos (plus
# Google-maintained system images via the global policy) are admitted.
# ===========================================================================

resource "google_binary_authorization_policy" "ledger" {
  project = var.project_id

  # Exempts GKE system images (gke.gcr.io etc.) from the deny below.
  global_policy_evaluation_mode = "ENABLE"

  admission_whitelist_patterns {
    name_pattern = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}/*"
  }

  admission_whitelist_patterns {
    name_pattern = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.dockerhub_remote.repository_id}/*"
  }

  admission_whitelist_patterns {
    name_pattern = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.l5d_remote.repository_id}/*"
  }

  default_admission_rule {
    evaluation_mode  = "ALWAYS_DENY"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
  }

  depends_on = [google_project_service.required]
}