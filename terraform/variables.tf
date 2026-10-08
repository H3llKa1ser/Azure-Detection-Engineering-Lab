variable "subscription_id" {
  description = "Azure subscription ID to deploy the lab into. Use a dedicated sandbox subscription."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F-]{36}$", var.subscription_id))
    error_message = "subscription_id must be a GUID."
  }
}

variable "location" {
  description = "Azure region for all lab resources."
  type        = string
  default     = "westeurope"
}

variable "prefix" {
  description = "Short prefix for resource names (lowercase letters and digits, 3-8 chars)."
  type        = string
  default     = "detlab"

  validation {
    condition     = can(regex("^[a-z0-9]{3,8}$", var.prefix))
    error_message = "prefix must be 3-8 lowercase letters or digits."
  }
}

variable "operator_ip" {
  description = "Public IPv4 of the machine running Terraform and the simulations. Used for Key Vault and Storage firewalls. Leave null to auto-detect."
  type        = string
  default     = null

  validation {
    condition     = var.operator_ip == null || can(regex("^\\d{1,3}(\\.\\d{1,3}){3}$", var.operator_ip))
    error_message = "operator_ip must be a bare IPv4 address (no CIDR suffix)."
  }
}

variable "vm_size" {
  description = "VM size for both victim hosts."
  type        = string
  default     = "Standard_B2als_v2"
}

variable "deploy_windows_vm" {
  description = "Deploy the Windows Server victim host (SecurityEvent telemetry)."
  type        = bool
  default     = true
}

variable "deploy_linux_vm" {
  description = "Deploy the Ubuntu victim host (Syslog telemetry)."
  type        = bool
  default     = true
}

variable "auto_shutdown_time" {
  description = "Daily VM auto-shutdown time, HHMM in auto_shutdown_timezone."
  type        = string
  default     = "1900"
}

variable "auto_shutdown_timezone" {
  description = "Windows timezone ID for auto-shutdown."
  type        = string
  default     = "W. Europe Standard Time"
}

variable "log_retention_days" {
  description = "Log Analytics interactive retention in days (30-730)."
  type        = number
  default     = 30
}

variable "daily_quota_gb" {
  description = "Log Analytics daily ingestion cap in GB. A cost guardrail; -1 disables it."
  type        = number
  default     = 1
}

variable "approved_privileged_callers" {
  description = "UPNs / object IDs allowed to make privileged role assignments without alerting (seeded into a Sentinel watchlist). Do NOT add your own UPN or the role-assignment simulation will be suppressed."
  type        = list(string)
  default     = []
}

variable "detections_path" {
  description = "Path to the detection-as-code YAML directory, relative to this module."
  type        = string
  default     = "../detections"
}

variable "tags" {
  description = "Extra tags applied to all resources."
  type        = map(string)
  default     = {}
}

variable "use_nat_gateway" {
  description = "Give the victim subnet explicit egress through a NAT gateway instead of Azure default outbound access (~$35/month extra)."
  type        = bool
  default     = false
}

variable "enable_entra_id" {
  description = "Stream Entra ID sign-in and audit logs into the workspace and deploy the identity detections, canary accounts and simulation app. Requires Entra ID P1 or P2 and tenant-level admin rights (see README)."
  type        = bool
  default     = false
}

variable "entra_id_p2" {
  description = "Tenant has Entra ID P2: also stream Identity Protection risk logs and deploy the risk-based detection. Requires enable_entra_id = true."
  type        = bool
  default     = false

  validation {
    condition     = !var.entra_id_p2 || var.enable_entra_id
    error_message = "entra_id_p2 requires enable_entra_id = true."
  }
}

variable "enable_flow_logs" {
  description = "Deploy VNet flow logs + Traffic Analytics (NTANetAnalytics table) and the network detections. Adds Traffic Analytics ingestion cost and 10-60 min processing latency."
  type        = bool
  default     = false
}

variable "flow_log_interval_minutes" {
  description = "Traffic Analytics processing interval: 10 (lower detection latency) or 60 (lower cost)."
  type        = number
  default     = 10

  validation {
    condition     = contains([10, 60], var.flow_log_interval_minutes)
    error_message = "flow_log_interval_minutes must be 10 or 60."
  }
}

variable "internal_mgmt_ports" {
  description = "Ports treated as lateral-movement / management ports by NET-003 (east-west scanning)."
  type        = list(number)
  default     = [22, 3389, 5985, 5986, 445, 135, 1433, 3306, 5432, 6379, 27017]
}

variable "enable_sysmon" {
  description = "Install Sysmon on the Windows victim and collect its operational channel into the Event table. Requires deploy_windows_vm = true."
  type        = bool
  default     = false
}

variable "sysmon_config_url" {
  description = "URL to a Sysmon config XML. Empty uses the compact built-in lab config. Point at SwiftOnSecurity/Olaf Hartong for fuller coverage."
  type        = string
  default     = ""
}

variable "enable_response_playbook" {
  description = "Deploy the auto-disable-principal Logic App playbook and the automation rule that runs it on KV-001 / STG-001. Requires enable_entra_id for a user to disable, and tenant rights (see docs)."
  type        = bool
  default     = false
}

variable "playbook_dry_run" {
  description = "Playbook only comments what it WOULD do instead of disabling the principal. Keep true until you trust it."
  type        = bool
  default     = true
}

variable "playbook_auto_run" {
  description = "Create the automation rule that runs the playbook automatically. If false, the playbook is deployed but only run manually from an incident."
  type        = bool
  default     = true
}

variable "playbook_grant_graph" {
  description = "Grant the playbook's managed identity the Graph User.ReadWrite.All app role so it can disable users. Needs Privileged Role Administrator / Global Administrator. Only meaningful when playbook_dry_run = false."
  type        = bool
  default     = false
}
