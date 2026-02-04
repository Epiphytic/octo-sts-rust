# Rate limiting and WAF rules for octo-sts-rust
# Protects against abuse of the token exchange endpoints

locals {
  sts_hostname = "sts.epiphytic.org"
}

# Rate limiting ruleset using the modern cloudflare_ruleset resource
# Note: Free plan allows only 1 rate limit rule, so we use a single rule
# that covers all STS endpoints with the stricter limit
resource "cloudflare_ruleset" "sts_rate_limiting" {
  zone_id     = var.cloudflare_zone_id
  name        = "octo-sts-rate-limiting"
  description = "Rate limiting rules for octo-sts-rust"
  kind        = "zone"
  phase       = "http_ratelimit"

  # Rate limit for all STS endpoints (uses the stricter exchange limit)
  rules {
    action = "block"
    action_parameters {
      response {
        status_code  = 429
        content_type = "application/json"
        content = jsonencode({
          error   = "rate_limited"
          message = "Too many requests. Please try again later."
        })
      }
    }
    ratelimit {
      characteristics     = ["cf.colo.id", "ip.src"]
      period              = 10
      requests_per_period = 5  # 5 requests per 10 seconds = ~30 req/min
      mitigation_timeout  = 10 # Free plan requires 10 second timeout
    }
    expression  = "(http.host eq \"${local.sts_hostname}\")"
    description = "Rate limit STS endpoints - 5 req/10sec per IP (~30 req/min)"
    enabled     = true
  }
}

# WAF custom rules for additional protection
resource "cloudflare_ruleset" "sts_waf" {
  zone_id     = var.cloudflare_zone_id
  name        = "octo-sts-waf"
  description = "WAF rules for octo-sts-rust"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  # Block requests with path traversal attempts in query params
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
