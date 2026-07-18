###############################################################################
# vpc-network.tf — zero-trust network layer
#
# Posture (deliberate decisions):
#   * NO Cloud NAT, NO public node IPs → workloads have no internet path.
#     All Google APIs (Spanner, Artifact Registry, KMS, logging, monitoring)
#     are reached via Private Google Access at the private.googleapis.com
#     VIP. External container images enter ONLY through Artifact Registry
#     remote (pull-through mirror) repositories, defined in Module 2 —
#     which also traverse the VIP. Supply chain has one front door.
#   * Default route is KEPT (VIP traffic and control-plane peering ride it);
#     enforcement is done by an explicitly LOGGED deny-all egress firewall.
#     (Deleting the default route breaks LB return paths and is brittle.)
#   * Explicit logged deny-all ingress mirrors the implied rule solely to
#     produce audit evidence of blocked attempts — implied denies never log.
#   * Firewall model: stateful. Return traffic of established flows is
#     always allowed, so the egress denies do not affect inbound LB traffic.
###############################################################################

resource "google_compute_network" "ledger" {
  name                            = "${var.project_name}-vpc"
  auto_create_subnetworks         = false
  routing_mode                    = "REGIONAL"
  delete_default_routes_on_create = false

  depends_on = [google_project_service.required]
}

resource "google_compute_subnetwork" "gke" {
  name                     = "${var.project_name}-gke-${var.region}"
  region                   = var.region
  network                  = google_compute_network.ledger.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = var.pods_cidr
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = var.services_cidr
  }

  log_config {
    aggregation_interval = "INTERVAL_5_MIN"
    flow_sampling        = var.flow_log_sampling
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# ===========================================================================
# Private Google Access DNS — force *.googleapis.com, *.gcr.io, *.pkg.dev
# to resolve to the private VIP inside this VPC. Three zones because the
# apex domains differ; the A/CNAME pattern per zone is Google's documented
# configuration for private.googleapis.com.
# ===========================================================================

resource "google_dns_managed_zone" "googleapis" {
  name       = "${var.project_name}-private-googleapis"
  dns_name   = "googleapis.com."
  visibility = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.ledger.id
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_dns_record_set" "googleapis_a" {
  managed_zone = google_dns_managed_zone.googleapis.name
  name         = "private.googleapis.com."
  type         = "A"
  ttl          = 300
  rrdatas      = local.private_googleapis_ips
}

resource "google_dns_record_set" "googleapis_cname" {
  managed_zone = google_dns_managed_zone.googleapis.name
  name         = "*.googleapis.com."
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["private.googleapis.com."]
}

resource "google_dns_managed_zone" "gcr" {
  name       = "${var.project_name}-private-gcr"
  dns_name   = "gcr.io."
  visibility = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.ledger.id
    }
  }
}

resource "google_dns_record_set" "gcr_a" {
  managed_zone = google_dns_managed_zone.gcr.name
  name         = "gcr.io."
  type         = "A"
  ttl          = 300
  rrdatas      = local.private_googleapis_ips
}

resource "google_dns_record_set" "gcr_cname" {
  managed_zone = google_dns_managed_zone.gcr.name
  name         = "*.gcr.io."
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["gcr.io."]
}

resource "google_dns_managed_zone" "pkg_dev" {
  name       = "${var.project_name}-private-pkgdev"
  dns_name   = "pkg.dev."
  visibility = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.ledger.id
    }
  }
}

resource "google_dns_record_set" "pkg_dev_a" {
  managed_zone = google_dns_managed_zone.pkg_dev.name
  name         = "pkg.dev."
  type         = "A"
  ttl          = 300
  rrdatas      = local.private_googleapis_ips
}

resource "google_dns_record_set" "pkg_dev_cname" {
  managed_zone = google_dns_managed_zone.pkg_dev.name
  name         = "*.pkg.dev."
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["pkg.dev."]
}

# Explicit route to the VIP: belt-and-braces so Google API reachability
# survives even if someone later deletes/deprioritizes the default route.
resource "google_compute_route" "private_googleapis" {
  name             = "${var.project_name}-private-googleapis"
  network          = google_compute_network.ledger.name
  dest_range       = local.private_googleapis_cidr
  next_hop_gateway = "default-internet-gateway"
  priority         = 900
}

# ===========================================================================
# Firewall — logged default-deny in BOTH directions, then minimal allows.
# ===========================================================================

resource "google_compute_firewall" "deny_all_egress" {
  name      = "${var.project_name}-deny-all-egress"
  network   = google_compute_network.ledger.name
  direction = "EGRESS"
  priority  = 65534

  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "deny_all_ingress" {
  name      = "${var.project_name}-deny-all-ingress"
  network   = google_compute_network.ledger.name
  direction = "INGRESS"
  priority  = 65534

  source_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Egress: Google APIs VIP only (Spanner, AR, KMS, logging/monitoring, STS).
resource "google_compute_firewall" "allow_egress_google_apis" {
  name      = "${var.project_name}-allow-egress-googleapis"
  network   = google_compute_network.ledger.name
  direction = "EGRESS"
  priority  = 1000

  destination_ranges = [local.private_googleapis_cidr]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

# Egress: everything platform-internal (nodes, pods, services, control plane).
resource "google_compute_firewall" "allow_egress_internal" {
  name      = "${var.project_name}-allow-egress-internal"
  network   = google_compute_network.ledger.name
  direction = "EGRESS"
  priority  = 1000

  destination_ranges = [
    var.subnet_cidr,
    var.pods_cidr,
    var.services_cidr,
    var.master_cidr,
  ]

  allow { protocol = "tcp" }
  allow { protocol = "udp" }
  allow { protocol = "icmp" }
}

# Ingress: platform-internal east-west (Linkerd mTLS enforces identity at
# L7 on top of this L3/L4 allowance — Module 3).
resource "google_compute_firewall" "allow_ingress_internal" {
  name      = "${var.project_name}-allow-ingress-internal"
  network   = google_compute_network.ledger.name
  direction = "INGRESS"
  priority  = 1000

  source_ranges = [
    var.subnet_cidr,
    var.pods_cidr,
    var.services_cidr,
  ]

  target_tags = [local.gke_node_tag]

  allow { protocol = "tcp" }
  allow { protocol = "udp" }
  allow { protocol = "icmp" }
}

# Ingress: control plane → nodes for admission/conversion webhooks.
# Ports: kubelet (10250), generic webhook servers (443/8443/9443), and the
# Linkerd control-plane webhooks + tap (8443/8089/4191 — Module 3).
resource "google_compute_firewall" "allow_ingress_master_webhooks" {
  name      = "${var.project_name}-allow-ingress-master-webhooks"
  network   = google_compute_network.ledger.name
  direction = "INGRESS"
  priority  = 1000

  source_ranges = [var.master_cidr]
  target_tags   = [local.gke_node_tag]

  allow {
    protocol = "tcp"
    ports    = ["443", "8443", "9443", "10250", "8089", "4191"]
  }
}

# Ingress: Google health-check ranges → nodes (internal passthrough LB used
# by the ledger-api Service in Module 3). GKE usually auto-creates these
# per-service; declared explicitly so LB health never depends on GKE's
# rule automation.
resource "google_compute_firewall" "allow_ingress_health_checks" {
  name      = "${var.project_name}-allow-ingress-healthchecks"
  network   = google_compute_network.ledger.name
  direction = "INGRESS"
  priority  = 1000

  source_ranges = [
    "130.211.0.0/22",
    "35.191.0.0/16",
  ]

  target_tags = [local.gke_node_tag]

  allow {
    protocol = "tcp"
  }
}