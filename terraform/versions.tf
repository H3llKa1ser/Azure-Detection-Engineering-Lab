terraform {
  required_version = ">= 1.9.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.8"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.10"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }

  # Local state by default. Remote state (azurerm backend, Entra ID auth,
  # versioned + soft-deleted blobs, native blob-lease locking) is opt-in:
  # `make init-remote` locally, or the GitHub Actions deploy workflow, writes a
  # gitignored backend_remote.tf and inits with backend.hcl / repo variables.
  # See docs/remote-state-and-oidc.md. A backend block can't be conditional,
  # which is why it's generated rather than committed.
}
