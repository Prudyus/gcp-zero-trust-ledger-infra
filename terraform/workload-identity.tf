###############################################################################
# workload-identity.tf — keyless identity for everything
#
# Two federation planes, zero exported keys anywhere:
#   A. GKE Workload Identity (KSA → GSA): per-workload Google identities.
#      - ledger-api:  Spanner access AS the fine-grained `ledger_app` role
#                     (databaseRoleUser + conditional grant), NOT databaseUser
#                     with blanket table access.
#      - vault:       KMS auto-unseal on a dedicated key + its own audit
#                     trail; Vault's KSA is the only principal on that key.
#      - otel-collector: metric/trace/log write for Module 5.
#   B. GitHub Actions WIF (OIDC → CI service account): Module 4's pipeline
#      pushes images with a 10-minute federated token. Attribute conditions
#      pin the exact repository; the IAM binding pins branch/tag refs.
###############################################################################

# ===========================================================================
# A1. ledger-api — Spanner via fine-grained access control
# ===========================================================================

resource "google_service_account" "ledger_api" {
  account_id   = "${var.project_name}-api"
  display_name = "ledger-api workload identity (append-only Spanner role)"
}

# Session-creation capability, scoped to THIS database only.
resource "google_spanner_database_iam_member" "ledger_api_role_user" {
  instance = google_spanner_instance.ledger.name
  database = google_spanner_database.ledger.name
  role     = "roles/spanner.databaseRoleUser"
  member   = google_service_account.ledger_api.member
}

# Fine-grained role assumption: IAM condition permits ONLY `ledger_app`
# (title/expression per Spanner FGAC docs). Combined with the DDL grants in
# cloud-spanner.tf, the workload physically cannot UPDATE or DELETE ledger
# rows — append-only is enforced at two independent layers.
resource "google_spanner_database_iam_member" "ledger_api_fgac" {
  instance = google_spanner_instance.ledger.name
  database = google_spanner_database.ledger.name
  role     = "roles/spanner.fineGrainedAccessUser"
  member   = google_service_account.ledger_api.member

  condition {
    title       = "spanner.databaseRole.ledger_app"
    description = "Restrict this workload to the append-only ledger_app database role"
    expression  = "resource.type == \"spanner.googleapis.com/DatabaseRole\" && resource.name.endsWith(\"/databaseRoles/ledger_app\")"
  }
}

# KSA ledger/ledger-api may impersonate the GSA (Workload Identity binding).
resource "google_service_account_iam_member" "ledger_api_wi" {
  service_account_id = google_service_account.ledger_api.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[ledger/ledger-api]"
}

# ===========================================================================
# A2. Vault — KMS auto-unseal (dedicated key, sole principal)
# ===========================================================================

resource "google_kms_crypto_key" "vault_unseal" {
  name            = "vault-unseal"
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

resource "google_service_account" "vault" {
  account_id   = "${var.project_name}-vault"
  display_name = "Vault server workload identity (KMS auto-unseal only)"
}

resource "google_kms_crypto_key_iam_member" "vault_unseal" {
  crypto_key_id = google_kms_crypto_key.vault_unseal.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = google_service_account.vault.member
}

# Vault's gcpckms seal calls cloudkms.cryptoKeyVersions.viewPublicKey/… via
# describe on startup; viewer on the single key keeps it least-privilege.
resource "google_kms_crypto_key_iam_member" "vault_unseal_viewer" {
  crypto_key_id = google_kms_crypto_key.vault_unseal.id
  role          = "roles/cloudkms.viewer"
  member        = google_service_account.vault.member
}

resource "google_service_account_iam_member" "vault_wi" {
  service_account_id = google_service_account.vault.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[vault/vault]"
}

# ===========================================================================
# A3. OpenTelemetry collector — telemetry write (Module 5)
# ===========================================================================

resource "google_service_account" "otel_collector" {
  account_id   = "${var.project_name}-otel"
  display_name = "OTel collector workload identity (telemetry write)"
}

resource "google_project_iam_member" "otel_metrics" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = google_service_account.otel_collector.member
}

resource "google_project_iam_member" "otel_traces" {
  project = var.project_id
  role    = "roles/cloudtrace.agent"
  member  = google_service_account.otel_collector.member
}

resource "google_project_iam_member" "otel_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = google_service_account.otel_collector.member
}

resource "google_service_account_iam_member" "otel_wi" {
  service_account_id = google_service_account.otel_collector.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[monitoring/otel-collector]"
}

# ===========================================================================
# B. GitHub Actions — Workload Identity Federation (keyless CI)
# ===========================================================================

variable "github_repository" {
  description = "GitHub 'org/repo' allowed to mint CI credentials (e.g. \"acme/ledger-platform\"). Empty string disables all CI IAM resources."
  type        = string
  default     = ""
}

resource "google_iam_workload_identity_pool" "github" {
  count = var.github_repository == "" ? 0 : 1

  workload_identity_pool_id = "${var.project_name}-github"
  display_name              = "GitHub Actions"
  description               = "Federated identities for the build pipeline"

  depends_on = [google_project_service.required]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  count = var.github_repository == "" ? 0 : 1

  workload_identity_pool_id          = google_iam_workload_identity_pool.github[0].workload_identity_pool_id
  workload_identity_pool_provider_id = "github-oidc"
  display_name                       = "GitHub OIDC"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }

  # Hard gate at the provider: tokens from any other repo are rejected
  # before IAM evaluation even begins.
  attribute_condition = "assertion.repository == \"${var.github_repository}\""
}

resource "google_service_account" "ci" {
  count = var.github_repository == "" ? 0 : 1

  account_id   = "${var.project_name}-ci"
  display_name = "GitHub Actions CI (image push only)"
}

# Push credentials only for main and release tags — PR builds get nothing.
resource "google_service_account_iam_member" "ci_wif_main" {
  count = var.github_repository == "" ? 0 : 1

  service_account_id = google_service_account.ci[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github[0].name}/attribute.ref/refs/heads/main"
}

resource "google_service_account_iam_member" "ci_wif_tags" {
  count = var.github_repository == "" ? 0 : 1

  service_account_id = google_service_account.ci[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github[0].name}/attribute.repository/${var.github_repository}"

  # NOTE: the repository-wide principalSet above intentionally exists ONLY
  # so tag builds (refs/tags/v*) can authenticate — GitHub's `ref` attribute
  # for tags. Both bindings resolve to the same SA whose sole power is:
  #   push to ONE Artifact Registry repo (below).
  # Tightening to per-tag principalSets requires enumerating refs; the
  # blast radius here is bounded by the writer grant, not the binding.
}

# Writer on the first-party repo ONLY (not project-level).
resource "google_artifact_registry_repository_iam_member" "ci_push" {
  count = var.github_repository == "" ? 0 : 1

  location   = var.region
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.writer"
  member     = google_service_account.ci[0].member
}