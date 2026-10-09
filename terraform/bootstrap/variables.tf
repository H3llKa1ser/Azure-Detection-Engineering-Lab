variable "subscription_id" {
  description = "Subscription the lab deploys into (and where state storage lives)."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F-]{36}$", var.subscription_id))
    error_message = "subscription_id must be a GUID."
  }
}

variable "location" {
  description = "Region for the state storage account."
  type        = string
  default     = "westeurope"
}

variable "prefix" {
  description = "Short prefix for bootstrap resource names (3-8 lowercase letters/digits)."
  type        = string
  default     = "detlab"

  validation {
    condition     = can(regex("^[a-z0-9]{3,8}$", var.prefix))
    error_message = "prefix must be 3-8 lowercase letters or digits."
  }
}

variable "github_owner" {
  description = "GitHub user or organisation that owns the repo."
  type        = string
  default     = "H3llKa1ser"
}

variable "github_repo" {
  description = "Repository name."
  type        = string
  default     = "Azure-Detection-Engineering-Lab"
}

variable "github_environment" {
  description = "GitHub Actions environment that gates apply/destroy (configure required reviewers on it in GitHub)."
  type        = string
  default     = "lab"
}

variable "state_retention_days" {
  description = "Soft-delete retention for state blobs and containers."
  type        = number
  default     = 30
}
