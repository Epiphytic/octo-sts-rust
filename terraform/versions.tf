terraform {
  required_version = ">= 1.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }

  # R2 backend configuration - uncomment when R2 API credentials are available
  # To migrate from local to R2: terraform init -migrate-state
  # backend "s3" {
  #   bucket                      = "octo-sts-terraform-state"
  #   key                         = "octo-sts-rust/terraform.tfstate"
  #   region                      = "auto"
  #   skip_credentials_validation = true
  #   skip_metadata_api_check     = true
  #   skip_region_validation      = true
  #   skip_requesting_account_id  = true
  #   skip_s3_checksum            = true
  #   use_path_style              = true
  #   endpoints = {
  #     s3 = "https://4286a385b1b8466277762d9cf8c61341.r2.cloudflarestorage.com"
  #   }
  # }

  # Local backend for now - state file is gitignored
  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}
