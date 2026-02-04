variable "cloudflare_api_token" {
  description = "Cloudflare API token with zone and WAF permissions"
  type        = string
  sensitive   = true
}

variable "cloudflare_account_id" {
  description = "Cloudflare account ID"
  type        = string
  default     = "4286a385b1b8466277762d9cf8c61341"
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID for epiphytic.org"
  type        = string
  default     = "10fd631c33d03a16c363505eed0a1ae6"
}

variable "rate_limit_requests_per_minute" {
  description = "Maximum requests per minute per IP for the STS endpoints"
  type        = number
  default     = 60
}

variable "rate_limit_requests_per_minute_exchange" {
  description = "Maximum requests per minute per IP for token exchange endpoints"
  type        = number
  default     = 30
}
