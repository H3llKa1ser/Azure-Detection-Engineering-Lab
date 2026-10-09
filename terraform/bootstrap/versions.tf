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
  }

  # Bootstrap state stays LOCAL on purpose: this module creates the remote
  # backend, so it can't live in it. It holds no secrets (no client secret -
  # OIDC is secretless) and is small; keep terraform.tfstate somewhere safe or
  # migrate it into the new container afterwards (see docs).
}

provider "azurerm" {
  subscription_id                = var.subscription_id
  storage_use_azuread            = true
  resource_providers_to_register = ["Microsoft.Storage"]
  features {}
}

provider "azuread" {}
