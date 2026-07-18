###############################################################################
# outputs.tf — exported values for CI, kubectl setup, application config,
# and downstream tooling. Cluster/registry/CI outputs reference resources
# declared in gke-cluster.tf / workload-identity.tf (Module 2 — same root
# module).
###############################################################################

# --- Networking ---------------------------------------------------------------

output "network_name" {
  description = "VPC network name."
  value       = google_compute_network.ledger.name
}

output "network_id" {
  description = "VPC network self-link ID."
  value       = google_compute_network.ledger.id
}

output "subnet_name" {
  description = "GKE node subnet name."
  value       = google_compute_subnetwork.gke.name
}

output "subnet_self_link" {
  description = "GKE node subnet self link."
  value       = google_compute_subnetwork.gke.self_link
}

output "pods_range_name" {
  description = "Secondary range used for pod IPs."
  value       = "pods"
}

output "services_range_name" {
  description = "Secondary range used for ClusterIP services."
  value       = "services"
}

# --- KMS -----------------------------------------------------------------------

output "kms_keyring_id" {
  description = "Platform KMS keyring (shared: Spanner CMEK here; GKE + Vault keys in Module 2)."
  value       = google_kms_key_ring.platform.id
}

output "spanner_kms_key_id" {
  description = "HSM-backed CMEK protecting the ledger database and its backups."
  value       = google_kms_crypto_key.spanner.id
}

# --- Spanner ---------------------------------------------------------------------

output "spanner_instance_name" {
  description = "Spanner instance name."
  value       = google_spanner_instance.ledger.name
}

output "spanner_database_name" {
  description = "Ledger database name."
  value       = google_spanner_database.ledger.name
}

output "spanner_database_path" {
  description = "Fully-qualified database path — the client connection string for the ledger-api service."
  value       = "projects/${var.project_id}/instances/${google_spanner_instance.ledger.name}/databases/${google_spanner_database.ledger.name}"
}

output "spanner_app_database_role" {
  description = "Fine-grained database role the application MUST assume at session creation (append-only grants; direct table access without this role is denied)."
  value       = "ledger_app"
}

# --- GKE (Module 2 resources) -------------------------------------------------------

output "cluster_name" {
  description = "GKE cluster name."
  value       = google_container_cluster.ledger.name
}

output "cluster_location" {
  description = "GKE cluster location (region — regional control plane)."
  value       = google_container_cluster.ledger.location
}

output "cluster_endpoint" {
  description = "GKE control plane endpoint."
  value       = google_container_cluster.ledger.endpoint
  sensitive   = true
}

output "cluster_ca_certificate" {
  description = "Base64 cluster CA certificate."
  value       = google_container_cluster.ledger.master_auth[0].cluster_ca_certificate
  sensitive   = true
}

output "workload_identity_pool" {
  description = "Workload Identity pool for KSA→GSA bindings."
  value       = "${var.project_id}.svc.id.goog"
}

output "ledger_api_gsa_email" {
  description = "Google service account the ledger-api workload runs as (via Workload Identity)."
  value       = google_service_account.ledger_api.email
}

output "kubeconfig_command" {
  description = "Command to add the cluster to local kubeconfig."
  value       = "gcloud container clusters get-credentials ${google_container_cluster.ledger.name} --region ${var.region} --project ${var.project_id}"
}

# --- Artifact Registry (Module 2 resources) --------------------------------------------

output "artifact_registry_repository_url" {
  description = "Docker repository URL for CI pushes and cluster pulls."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
}

# --- GitHub Actions federation (Module 2 resources; null when CI IAM disabled) ----------

output "github_wif_provider" {
  description = "Full resource name of the GitHub OIDC Workload Identity provider (for google-github-actions/auth). Null if var.github_repository is unset."
  value       = var.github_repository == "" ? null : google_iam_workload_identity_pool_provider.github[0].name
}

output "ci_service_account_email" {
  description = "Service account GitHub Actions impersonates to push images. Null if var.github_repository is unset."
  value       = var.github_repository == "" ? null : google_service_account.ci[0].email
}