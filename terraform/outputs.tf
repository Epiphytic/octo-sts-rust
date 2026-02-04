output "rate_limiting_ruleset_id" {
  description = "ID of the rate limiting ruleset"
  value       = cloudflare_ruleset.sts_rate_limiting.id
}

output "waf_ruleset_id" {
  description = "ID of the WAF ruleset"
  value       = cloudflare_ruleset.sts_waf.id
}
