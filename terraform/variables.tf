###############################################################################
# variables.tf — input variables and shared locals
###############################################################################

variable "project_id" {
  description = "GCP project ID hosting the ledger platform."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid GCP project ID."
  }
}

variable "project_name" {
  description = "Short name prefix for all resources."
  type        = string
  default     = "ledger"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,15}$", var.project_name))
    error_message = "project_name must start with a letter, lowercase alphanumeric/hyphens, max 16 chars."
  }
}

variable "environment" {
  description = "Deployment environment."
  type        = string
  default     = "production"

  validation {
    condition     = contains(["production", "staging", "development"], var.environment)
    error_message = "environment must be one of: production, staging, development."
  }
}

variable "region" {
  description = "Primary GCP region for network, GKE, and (by default) Spanner."
  type        = string
  default     = "us-central1"
}

# --- Networking (all RFC1918, mutually non-overlapping) ----------------------

variable "subnet_cidr" {
  description = "Primary CIDR for the GKE node subnet."
  type        = string
  default     = "10.10.0.0/20"
}

variable "pods_cidr" {
  description = "Secondary range for pod IPs (VPC-native / alias IPs)."
  type        = string
  default     = "10.16.0.0/14"
}

variable "services_cidr" {
  description = "Secondary range for ClusterIP services."
  type        = string
  default     = "10.20.0.0/20"
}

variable "master_cidr" {
  description = "RFC1918 /28 for the GKE control plane (private endpoint peering)."
  type        = string
  default     = "172.16.0.0/28"

  validation {
    condition     = tonumber(split("/", var.master_cidr)[1]) == 28
    error_message = "master_cidr must be a /28."
  }
}

variable "flow_log_sampling" {
  description = "VPC flow log sampling rate. 1.0 = every flow (financial audit posture); lower to trade completeness for logging cost."
  type        = number
  default     = 1.0

  validation {
    condition     = var.flow_log_sampling > 0 && var.flow_log_sampling <= 1
    error_message = "flow_log_sampling must be in (0, 1]."
  }
}

# --- GKE ----------------------------------------------------------------------

variable "gke_release_channel" {
  description = "GKE release channel."
  type        = string
  default     = "REGULAR"

  validation {
    condition     = contains(["RAPID", "REGULAR", "STABLE"], var.gke_release_channel)
    error_message = "gke_release_channel must be RAPID, REGULAR, or STABLE."
  }
}

variable "enable_private_endpoint" {
  description = "true = control plane reachable ONLY via VPC (strictest; requires in-VPC runner/bastion or Connect Gateway for kubectl AND for this Terraform's kubernetes/helm providers). false = public endpoint stays up but is restricted to master_authorized_networks."
  type        = bool
  default     = false
}

variable "master_authorized_networks" {
  description = "CIDRs allowed to reach the control plane endpoint. MUST be non-empty office/VPN egress ranges when enable_private_endpoint=false. Never 0.0.0.0/0 for a financial platform."
  type = list(object({
    cidr_block   = string
    display_name = string
  }))
  default = []
}

variable "node_machine_type" {
  description = "Node machine type. Default n2d (AMD SEV) so Confidential Nodes can encrypt RAM in use."
  type        = string
  default     = "n2d-standard-4"
}

variable "enable_confidential_nodes" {
  description = "Run nodes as Confidential VMs (memory encryption in use). Requires an N2D/C2D/C3D machine family."
  type        = bool
  default     = true
}

variable "node_count_min_per_zone" {
  description = "Autoscaling floor per zone (regional cluster = 3 zones)."
  type        = number
  default     = 1
}

variable "node_count_max_per_zone" {
  description = "Autoscaling ceiling per zone."
  type        = number
  default     = 4
}

variable "node_disk_size_gb" {
  description = "Node boot disk size (pd-ssd, CMEK-encrypted)."
  type        = number
  default     = 100
}

# --- Spanner --------------------------------------------------------------------

variable "spanner_instance_config" {
  description = "Spanner instance configuration. Regional default; switch to a multi-region config (e.g. nam3) for 99.999% SLA — 5x-ish cost, and keep GKE in a member region."
  type        = string
  default     = "regional-us-central1"
}

variable "spanner_edition" {
  description = "Spanner edition. ENTERPRISE unlocks autoscaling + advanced backup features used below."
  type        = string
  default     = "ENTERPRISE"

  validation {
    condition     = contains(["STANDARD", "ENTERPRISE", "ENTERPRISE_PLUS"], var.spanner_edition)
    error_message = "spanner_edition must be STANDARD, ENTERPRISE, or ENTERPRISE_PLUS."
  }
}

variable "spanner_min_processing_units" {
  description = "Autoscaler floor. 1000 PU = 1 node = the minimum for production SLAs."
  type        = number
  default     = 1000

  validation {
    condition     = var.spanner_min_processing_units >= 1000 && var.spanner_min_processing_units % 1000 == 0
    error_message = "Production floor is >= 1000 processing units, in multiples of 1000."
  }
}

variable "spanner_max_processing_units" {
  description = "Autoscaler ceiling."
  type        = number
  default     = 4000
}

variable "spanner_version_retention" {
  description = "Point-in-time recovery window (max 7d). Financial data: keep the maximum."
  type        = string
  default     = "7d"
}

variable "spanner_backup_cron" {
  description = "Full-backup schedule (UTC cron)."
  type        = string
  default     = "0 2 * * *"
}

variable "spanner_backup_retention_seconds" {
  description = "Backup retention as seconds string. Default 30 days."
  type        = string
  default     = "2592000s"
}

# --- KMS -------------------------------------------------------------------------

variable "kms_rotation_period" {
  description = "CMEK rotation period as seconds string. Default 90 days."
  type        = string
  default     = "7776000s"
}

# --- Labels ------------------------------------------------------------------------

variable "additional_labels" {
  description = "Extra labels merged into provider default_labels."
  type        = map(string)
  default     = {}
}

# --- Shared locals -------------------------------------------------------------------

locals {
  common_labels = {
    project     = var.project_name
    environment = var.environment
    managed-by  = "terraform"
    data-class  = "financial"
  }

  # Applied to node pools (Module 2) and targeted by firewall rules below.
  gke_node_tag = "${var.project_name}-gke-node"

  cluster_name = "${var.project_name}-${var.environment}"

  # private.googleapis.com VIP — the only route out of this VPC.
  private_googleapis_cidr = "199.36.153.8/30"
  private_googleapis_ips  = ["199.36.153.8", "199.36.153.9", "199.36.153.10", "199.36.153.11"]
}