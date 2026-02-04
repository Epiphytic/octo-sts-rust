# Rate limiting rules for octo-sts-rust
# Protects against abuse of the token exchange endpoints

locals {
  sts_hostname = "sts.epiphytic.org"
}

# Rate limit for token exchange endpoints (stricter)
# These are the most sensitive endpoints that generate tokens
resource "cloudflare_rate_limit" "sts_exchange" {
  zone_id = var.cloudflare_zone_id

  threshold = var.rate_limit_requests_per_minute_exchange
  period    = 60

  match {
    request {
      url_pattern = "${local.sts_hostname}/sts/exchange*"
      schemes     = ["HTTPS"]
      methods     = ["POST"]
    }
  }

  action {
    mode    = "ban"
    timeout = 60
    response {
      content_type = "application/json"
      body = jsonencode({
        error   = "rate_limited"
        message = "Too many requests. Please try again later."
      })
    }
  }

  disabled    = false
  description = "Rate limit token exchange endpoints - ${var.rate_limit_requests_per_minute_exchange} req/min"
}

# Rate limit for all STS endpoints (general protection)
resource "cloudflare_rate_limit" "sts_general" {
  zone_id = var.cloudflare_zone_id

  threshold = var.rate_limit_requests_per_minute
  period    = 60

  match {
    request {
      url_pattern = "${local.sts_hostname}/*"
      schemes     = ["HTTPS"]
      methods     = ["_ALL_"]
    }
  }

  action {
    mode    = "ban"
    timeout = 60
    response {
      content_type = "application/json"
      body = jsonencode({
        error   = "rate_limited"
        message = "Too many requests. Please try again later."
      })
    }
  }

  disabled    = false
  description = "General rate limit for STS - ${var.rate_limit_requests_per_minute} req/min"
}

# WAF custom rule for additional protection against suspicious patterns
resource "cloudflare_ruleset" "sts_waf" {
  zone_id     = var.cloudflare_zone_id
  name        = "octo-sts-waf"
  description = "WAF rules for octo-sts-rust"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  # Block requests with suspicious path traversal attempts
  rules {
    action      = "block"
    expression  = "(http.host eq \"${local.sts_hostname}\" and http.request.uri.query contains \"..\")"
    description = "Block path traversal attempts in query params"
    enabled     = true
  }

  # Block requests with overly long query strings (potential DoS)
  rules {
    action      = "block"
    expression  = "(http.host eq \"${local.sts_hostname}\" and len(http.request.uri.query) > 2048)"
    description = "Block excessively long query strings"
    enabled     = true
  }

  # Challenge requests with suspicious user agents
  rules {
    action      = "managed_challenge"
    expression  = "(http.host eq \"${local.sts_hostname}\" and http.user_agent eq \"\")"
    description = "Challenge requests with empty user agent"
    enabled     = true
  }
}
