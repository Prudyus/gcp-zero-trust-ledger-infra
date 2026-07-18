###############################################################################
# providers.tf
# Terraform core, remote state, project API enablement, and provider
# configuration for the GCP financial-ledger platform (zero-trust posture).
#
# NOTE: single root module split across multiple .tf files. The kubernetes/
# helm provider blocks reference google_container_cluster.ledger declared in
# gke-cluster.tf (Module 2) — valid within one root module.
###############################################################################

terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 6.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.38"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 3.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0" # Linkerd trust anchor / issuer generation (Module 3)
    }
  }

  # GCS backend: state locking is native (object generations) — no external
  # lock table. Bucket prerequisites before `terraform init`:
  #   * versioning enabled
  #   * uniform bucket-level access
  #   * public access prevention enforced
  #   * (recommended) CMEK default encryption + lifecycle noncurrent cleanup
  backend "gcs" {
    bucket = "platform-terraform-state-prod" # adjust to your bucket
    prefix = "financial-ledger"
  }
}

# ---------------------------------------------------------------------------
# Project services — everything the stack needs, enabled declaratively.
# disable_on_destroy=false: never rip APIs out from under other workloads.
# ---------------------------------------------------------------------------

locals {
  required_apis = [
    "compute.googleapis.com",             # VPC, firewalls, routes
    "container.googleapis.com",           # GKE
    "spanner.googleapis.com",             # ledger database
    "cloudkms.googleapis.com",            # CMEK + Vault auto-unseal (Module 2)
    "dns.googleapis.com",                 # private googleapis zones
    "artifactregistry.googleapis.com",    # image registry + remote mirrors
    "iam.googleapis.com",                 # service accounts
    "iamcredentials.googleapis.com",      # workload identity federation
    "sts.googleapis.com",                 # GitHub OIDC token exchange (Module 4)
    "binaryauthorization.googleapis.com", # deploy-time image attestation gate
    "logging.googleapis.com",
    "monitoring.googleapis.com",
  ]
}

resource "google_project_service" "required" {
  for_each = toset(local.required_apis)

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

data "google_project" "this" {
  project_id = var.project_id
}

# ---------------------------------------------------------------------------
# Google providers
# ---------------------------------------------------------------------------

provider "google" {
  project = var.project_id
  region  = var.region

  default_labels = merge(local.common_labels, var.additional_labels)
}

provider "google-beta" {
  project = var.project_id
  region  = var.region

  default_labels = merge(local.common_labels, var.additional_labels)
}

# ---------------------------------------------------------------------------
# Kubernetes / Helm providers — short-lived OAuth token from the caller's
# ADC identity, fetched at plan/apply time (never persisted in state).
# ---------------------------------------------------------------------------

data "google_client_config" "default" {}

provider "kubernetes" {
  host                   = "https://${google_container_cluster.ledger.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(google_container_cluster.ledger.master_auth[0].cluster_ca_certificate)
}

provider "helm" {
  kubernetes = {
    host                   = "https://${google_container_cluster.ledger.endpoint}"
    token                  = data.google_client_config.default.access_token
    cluster_ca_certificate = base64decode(google_container_cluster.ledger.master_auth[0].cluster_ca_certificate)
  }
}