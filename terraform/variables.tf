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
