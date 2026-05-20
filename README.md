# lazuli-plugin-ip-reputation

Lazuli `@plugin/ip-reputation` provides IP risk scoring for adaptive
rate-limit + bot detection.

## Status

- Go server adapter: in development.
- Default vendor: AbuseIPDB.
- Cloudflare Radar and Project Honey Pot are declared as future vendor
  stubs.

This plugin is not closing a specific audit finding. It is a
defense-in-depth adapter for production hardening.

## Configuration

Set `ABUSEIPDB_API_KEY` for the default AbuseIPDB adapter. Optional
`IP_REPUTATION_VENDOR` defaults to `abuseipdb`.

The v0.1 adapter keeps a 30-minute in-memory TTL cache. Adopters that
need shared cache behavior can pair deployments with
`@plugin/ratelimit-redis` indirectly at the rate-limit layer.
