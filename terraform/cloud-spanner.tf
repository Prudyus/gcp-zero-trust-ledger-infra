###############################################################################
# cloud-spanner.tf — the ledger's system of record
#
# Design decisions:
#   * CMEK everywhere: a dedicated HSM-backed key encrypts the database and
#     (via USE_DATABASE_ENCRYPTION) its backups. The keyring created here is
#     shared by Module 2 (GKE etcd/app secrets, node disks, Vault unseal).
#   * Append-only ledger ENFORCED BY THE DATABASE: fine-grained access
#     control gives the application role INSERT+SELECT only on Transactions
#     and Entries — no UPDATE, no DELETE. Immutability is not a code-review
#     convention, it is a permission boundary.
#   * Double-entry schema: every Transaction has N Entries (debit/credit
#     legs); Entries are interleaved in Accounts for single-split balance
#     reads per account.
#   * PITR at the 7-day maximum + daily full backups (30d retention).
#   * Autoscaling (Enterprise edition) between var floors/ceilings — never
#     below 1000 PU (1 node) in production.
#
# KMS/location constraint: for a REGIONAL instance config the CMEK key must
# live in the same region (regional-us-central1 → us-central1). Moving to a
# multi-region Spanner config requires a matching multi-region KMS key.
###############################################################################

# ===========================================================================
# KMS — platform keyring + Spanner CMEK
# Keyrings and keys are non-deletable GCP resources (key VERSIONS can be
# destroyed; names are retained forever). Renaming means a new resource.
# ===========================================================================

resource "google_kms_key_ring" "platform" {
  name     = "${var.project_name}-${var.environment}-keyring"
  location = var.region

  depends_on = [google_project_service.required]
}

resource "google_kms_crypto_key" "spanner" {
  name            = "spanner-cmek"
  key_ring        = google_kms_key_ring.platform.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.kms_rotation_period

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM" # financial data-class: FIPS 140-2 L3 backing
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Spanner's per-project service agent must be able to use the key. The
# agent doesn't exist until provisioned — force creation explicitly.
resource "google_project_service_identity" "spanner" {
  provider = google-beta

  project = var.project_id
  service = "spanner.googleapis.com"
}

resource "google_kms_crypto_key_iam_member" "spanner_cmek" {
  crypto_key_id = google_kms_crypto_key.spanner.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = google_project_service_identity.spanner.member
}

# ===========================================================================
# Spanner instance — autoscaled, Enterprise edition
# ===========================================================================

resource "google_spanner_instance" "ledger" {
  name         = "${var.project_name}-${var.environment}"
  display_name = "Financial ledger (${var.environment})"
  config       = var.spanner_instance_config
  edition      = var.spanner_edition

  # The explicit schedule below is the only backup policy — suppress the
  # provider-default automatic schedule so policy lives in one place.
  default_backup_schedule_type = "NONE"

  autoscaling_config {
    autoscaling_limits {
      min_processing_units = var.spanner_min_processing_units
      max_processing_units = var.spanner_max_processing_units
    }
    autoscaling_targets {
      # Regional-config guidance: keep high-priority CPU ≤ 65%.
      high_priority_cpu_utilization_percent = 65
      storage_utilization_percent           = 90
    }
  }

  force_destroy = false

  labels = {
    component = "ledger-database"
  }

  depends_on = [google_project_service.required]
}

# ===========================================================================
# Database — schema + fine-grained access control
#
# Terraform `ddl` semantics: statements are applied IN ORDER at creation;
# afterwards only APPENDED statements are applied as schema updates.
# Never edit or reorder existing entries on a live database — additive
# migrations only (or move evolution to dedicated tooling and let this
# list represent the base schema).
# ===========================================================================

resource "google_spanner_database" "ledger" {
  instance                 = google_spanner_instance.ledger.name
  name                     = "ledger"
  database_dialect         = "GOOGLE_STANDARD_SQL"
  version_retention_period = var.spanner_version_retention

  encryption_config {
    kms_key_name = google_kms_crypto_key.spanner.id
  }

  ddl = [
    # --- application database role (fine-grained access control) ----------
    "CREATE ROLE ledger_app",

    # --- accounts ----------------------------------------------------------
    <<-EOT
      CREATE TABLE Accounts (
        AccountId  STRING(36)  NOT NULL,
        OwnerRef   STRING(64)  NOT NULL,
        Currency   STRING(3)   NOT NULL,
        Status     STRING(16)  NOT NULL,
        CreatedAt  TIMESTAMP   NOT NULL OPTIONS (allow_commit_timestamp=true),
        UpdatedAt  TIMESTAMP            OPTIONS (allow_commit_timestamp=true),
        CONSTRAINT chk_account_status CHECK (Status IN ('ACTIVE', 'FROZEN', 'CLOSED'))
      ) PRIMARY KEY (AccountId)
    EOT
    ,

    # --- transactions (journal header; idempotency-keyed) -------------------
    <<-EOT
      CREATE TABLE Transactions (
        TransactionId  STRING(36)   NOT NULL,
        IdempotencyKey STRING(64)   NOT NULL,
        Description    STRING(256),
        CommittedAt    TIMESTAMP    NOT NULL OPTIONS (allow_commit_timestamp=true)
      ) PRIMARY KEY (TransactionId)
    EOT
    ,

    "CREATE UNIQUE INDEX TransactionsByIdempotencyKey ON Transactions (IdempotencyKey)",

    # --- entries (debit/credit legs; interleaved for per-account locality) --
    <<-EOT
      CREATE TABLE Entries (
        AccountId     STRING(36)  NOT NULL,
        EntryId       STRING(36)  NOT NULL,
        TransactionId STRING(36)  NOT NULL,
        Direction     STRING(6)   NOT NULL,
        Amount        NUMERIC     NOT NULL,
        Currency      STRING(3)   NOT NULL,
        CommittedAt   TIMESTAMP   NOT NULL OPTIONS (allow_commit_timestamp=true),
        CONSTRAINT chk_entry_direction CHECK (Direction IN ('DEBIT', 'CREDIT')),
        CONSTRAINT chk_entry_amount    CHECK (Amount > 0),
        CONSTRAINT fk_entries_txn FOREIGN KEY (TransactionId) REFERENCES Transactions (TransactionId)
      ) PRIMARY KEY (AccountId, EntryId),
        INTERLEAVE IN PARENT Accounts ON DELETE NO ACTION
    EOT
    ,

    "CREATE INDEX EntriesByTransaction ON Entries (TransactionId)",

    # --- grants: the permission boundary that makes the ledger append-only --
    # No UPDATE/DELETE exists for ledger_app on Transactions/Entries.
    # Accounts may only have Status/UpdatedAt mutated (freeze/close flows).
    "GRANT SELECT, INSERT ON TABLE Accounts, Transactions, Entries TO ROLE ledger_app",
    "GRANT UPDATE(Status, UpdatedAt) ON TABLE Accounts TO ROLE ledger_app",
  ]

  # Server-side drop protection + Terraform-level guard.
  enable_drop_protection = true
  deletion_protection    = true

  depends_on = [google_kms_crypto_key_iam_member.spanner_cmek]
}

# ===========================================================================
# Backups — daily full, 30-day retention, database-key encryption.
# PITR (version_retention_period) covers fine-grained rewind inside 7 days;
# these backups cover the beyond-PITR / instance-loss cases.
# ===========================================================================

resource "google_spanner_backup_schedule" "daily_full" {
  instance = google_spanner_instance.ledger.name
  database = google_spanner_database.ledger.name
  name     = "daily-full"

  retention_duration = var.spanner_backup_retention_seconds

  spec {
    cron_spec {
      text = var.spanner_backup_cron
    }
  }

  full_backup_spec {}

  encryption_config {
    encryption_type = "USE_DATABASE_ENCRYPTION"
  }
}