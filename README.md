# IoC-Feeds

Curated IPv4 Indicator of Compromise feeds for SonicWall SonicOS 8 (Gen8, 8.2.1+),
built hourly by GitHub Actions from public threat intelligence sources.

Maintained by Markley Technologies.

## Feeds

| File | Use on | Notes |
|---|---|---|
| `feeds/c2.txt` | LAN -> WAN rules | Verified botnet C2 (outbound) |
| `feeds/inbound-tz.txt` | WAN -> LAN rules, TZ / NSv | c2 + this file fit under the 25,000 IP device limit |
| `feeds/inbound-nsa.txt` | WAN -> LAN rules, NSa | c2 + this file fit under the 50,000 IP device limit |
| `feeds/manifest.json` | Monitoring | Build time, per-source status and counts |
| `feeds/allowlist-hits.txt` | Review | IPs the feeds wanted to block but the allowlist protected |

Each file ends with the canary `192.0.2.1` (TEST-NET-1, never routed on the internet).
Look it up with **Diagnostics > Check IoC IP Addresses** to confirm a file loaded.

SonicWall URL Name format (no `https://`):

```
raw.githubusercontent.com/chadmark/IoC-Feeds/main/feeds/c2.txt
```

## Vetting pipeline

1. Download each source; strip comments, headers, ports, extra columns
2. Keep single IPv4 only (drop IPv6, CIDR ranges, malformed lines)
3. Drop private / reserved / bogon space
4. If a source fails or returns fewer than `minEntries`, reuse last good copy (max 72h old)
5. Remove allowlisted IPs (`config/allowlist.txt` + live Microsoft 365 IPv4 ranges)
6. Rank inbound IPs by number of agreeing sources; trim to model budget
7. Refuse to publish if an inbound list shrinks by more than 50% versus the last run

## Changing sources

Edit `config/feed-config.json`. Roles: `c2` (outbound) or `inbound`.
Run locally first: `./scripts/Build-SonicWallIoCFeed.ps1 -DryRun`

Client-specific exclusions go in each firewall's IoC **Exclusion Object**, not in this public repo.
