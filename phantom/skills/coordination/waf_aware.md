---
name: waf-aware
description: Coordination playbook for targets with WAF/bot protection (Cloudflare, Imunify360, mod_security)
---

# WAF-Aware Scanning Coordination

Use this coordination playbook when the target has active WAF or bot protection (Cloudflare, Akamai, Imunify360, mod_security, AWS WAF, etc.). The goal is to complete a thorough assessment without triggering IP bans that halt the entire scan.

## Core Principles

1. **Throttle aggressively** — 5-10 seconds between requests minimum
2. **Detect blocks early** — recognize WAF signatures and back off before a ban
3. **Serialize, don't swarm** — one active testing agent at a time, not parallel
4. **Avoid triggering payloads** — no time-based SQLi (`SLEEP`), no obvious attack signatures
5. **Recon first, exploit later** — map the surface with passive/low-noise methods before active testing

## WAF Detection Signatures

Train agents to recognize these block indicators and STOP immediately:

**Cloudflare:**
- "One moment, please..." challenge page
- `Server: cloudflare` with 403/503
- `cf-ray` header present on error pages
- JavaScript challenge (`__cf_chl_jschl_tk__`)
- `wssplashchk` cookie set

**Imunify360 / CSF (cPanel):**
- Connection timeout (SYN dropped, no RST)
- Sudden 403 on all endpoints after being fine
- "Access denied" or "Your IP has been blocked"

**LiteSpeed / mod_security:**
- 403 "Access to this resource on the server is denied!"
- 406 Not Acceptable
- Empty response body with 403

**Generic WAF:**
- Sudden HTTP 429 (rate limit)
- All requests timing out after a burst
- Caido proxy returning 502 Timeout

## Upstream Proxy for IP Rotation

If `PHANTOM_UPSTREAM_PROXY` is set in the environment, use it for requests to spread them across multiple IPs:

```bash
# Check if upstream proxy is available
if [ -n "$PHANTOM_UPSTREAM_PROXY" ]; then
  curl -x "$PHANTOM_UPSTREAM_PROXY" https://target.com/endpoint
  httpx -proxy "$PHANTOM_UPSTREAM_PROXY" -l urls.txt
  nuclei -proxy "$PHANTOM_UPSTREAM_PROXY" -t templates/ -u https://target.com
fi
```

Even with proxy rotation, still throttle and detect blocks — aggressive scanning can get entire proxy ranges banned.

## Request Throttling Strategy

Instruct ALL subagents to throttle requests:

```
IMPORTANT: This target has WAF protection. You MUST:
1. Wait at least 5 seconds between HTTP requests
2. After any 403/429/timeout, wait 30 seconds before retrying
3. If you see a Cloudflare challenge or WAF block, STOP and report back
4. Do NOT use SLEEP-based SQL injection payloads
5. Do NOT run aggressive fuzzing tools (ffuf, dirsearch) with default settings
```

For shell commands, use throttled presets:
- `ffuf -rate 5` (5 requests/second max, prefer 1-2)
- `nuclei -rl 2 -c 1` (2 req/sec, 1 concurrent)
- `httpx -rl 60` (60 requests/minute = 1/sec)
- `katana -d 2 -rl 30` (shallow crawl, throttled)

## Agent Serialization

Instead of spawning parallel vulnerability agents, serialize them:

**DO NOT:**
```
create_agent("SQLi testing", ...)
create_agent("XSS testing", ...)  # Runs in parallel!
create_agent("IDOR testing", ...)  # All hit target simultaneously
```

**DO:**
```
# Phase 1: Recon (single agent)
create_agent("Reconnaissance & mapping", ...)
wait_for_agents()

# Phase 2: One vuln class at a time
create_agent("Authentication testing", ...)
wait_for_agents()

create_agent("Injection testing", ...)
wait_for_agents()

# ... continue sequentially
```

## Payload Adaptation

Avoid payloads that trigger WAF signatures:

**SQL Injection:**
- AVOID: `' OR SLEEP(5)-- -`, `WAITFOR DELAY`, `BENCHMARK()`
- USE: Boolean-based only (`' OR '1'='1`, `' AND '1'='2`)
- USE: Error-based if errors are returned
- USE: UNION-based with column enumeration

**XSS:**
- AVOID: `<script>alert(1)</script>` (heavily signatured)
- USE: Event handlers (`<img src=x onerror=alert(1)>`)
- USE: SVG vectors (`<svg/onload=alert(1)>`)
- USE: Encoding bypasses (HTML entities, unicode)

**Command Injection:**
- AVOID: `; cat /etc/passwd`
- USE: `$(id)`, `` `id` ``, `| id`
- USE: Time-based only as last resort with long delays

**Directory/File Discovery:**
- AVOID: Large wordlists, aggressive fuzzing
- USE: Targeted paths based on technology fingerprint
- USE: robots.txt, sitemap.xml, known CMS paths

## Backoff Protocol

When a block is detected:

1. **First block (403/challenge):** Wait 60 seconds, then retry ONE request
2. **Second block:** Wait 5 minutes, switch to different endpoint/path
3. **Third block:** Assume IP is banned, report to parent agent
4. **Connection timeout:** Assume IP ban, stop all testing

Implement exponential backoff in agent tasks:
```
If request fails with WAF signature:
  - Log the block
  - Wait (attempt_number * 30) seconds
  - If attempt > 3, abort and report
```

## Recon Adjustments

For WAF-protected targets, adjust reconnaissance:

**Subdomain enumeration:**
- Prefer passive sources (crt.sh, SecurityTrails, Shodan)
- Avoid active DNS brute-forcing (triggers some WAFs)

**Port scanning:**
- Use slow timing (`nmap -T2` or `-T1`)
- Scan fewer ports (top 100 instead of 1000)
- Add delays between hosts

**Content discovery:**
- Skip aggressive directory bruteforce
- Use technology-specific wordlists only
- Rely on spider/crawler output instead

## Reporting WAF Blocks

When an agent detects a WAF block, it should:

1. Create a note documenting the block type and timestamp
2. Report to parent agent with `send_message_to_agent`
3. Stop all active testing
4. Parent decides whether to wait, pivot, or finish

Example note:
```
WAF BLOCK DETECTED
Time: 2026-08-22 14:30 UTC
Type: Cloudflare JS challenge
Last successful request: /api/users
Blocked request: /api/users?id=1' OR '1'='1
Action: Stopped testing, waiting for parent guidance
```

## Completion Criteria

A WAF-aware scan is complete when:
1. All serialized testing phases have run OR
2. A persistent block prevents further testing OR
3. Budget/time limit reached

If blocked before completion, document:
- What was tested successfully
- What could not be tested due to blocks
- Recommendations for manual follow-up
