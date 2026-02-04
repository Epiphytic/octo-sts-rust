terraform {
  required_version = ">= 1.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }

  # R2 backend for state storage
  # Requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables
  # See: ~/private-keys/cf-terraform-r2-api-key.sh
  backend "s3" {
    bucket                      = "octo-sts-terraform-state"
    key                         = "octo-sts-rust/terraform.tfstate"
    region                      = "auto"
    skip_credentials_validation = true
    skip_metadata_api_check     = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_s3_checksum            = true
    use_path_style              = true
    endpoints = {
      s3 = "https://4286a385b1b8466277762d9cf8c61341.r2.cloudflarestorage.com"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}
