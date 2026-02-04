output "rate_limit_exchange_id" {
  description = "ID of the exchange endpoint rate limit rule"
  value       = cloudflare_rate_limit.sts_exchange.id
}

output "rate_limit_general_id" {
  description = "ID of the general rate limit rule"
  value       = cloudflare_rate_limit.sts_general.id
}

output "waf_ruleset_id" {
  description = "ID of the WAF ruleset"
  value       = cloudflare_ruleset.sts_waf.id
}
