---
title: "Scanning WAF-Protected Targets"
description: "Best practices for penetration testing targets with Cloudflare, Imunify360, or other WAF protection"
---

# Scanning WAF-Protected Targets

When testing targets behind Cloudflare, Akamai, AWS WAF, Imunify360, or similar protections, aggressive automated scanning will trigger IP bans that halt your assessment. This guide covers two complementary strategies: **behavior adaptation** (WAF-aware skill) and **infrastructure** (rotating proxies).

## Strategy 1: WAF-Aware Behavior

Load the `waf_aware` coordination skill to make agents throttle requests, detect blocks, and avoid triggering payloads.

### Enable via CLI

```bash
# Quick mode already throttles somewhat; combine with waf_aware
phantom --target https://waf-protected-site.com --scan-mode quick

# For interactive mode, the root agent can load the skill dynamically
# In the TUI, instruct the agent to "load the waf_aware skill"
```

### Enable via Agent Task

When creating subagents, include the skill:

```python
create_agent(
    name="Injection Testing",
    task="Test for SQL injection on login endpoints",
    skills="waf_aware,sql_injection"  # WAF-aware + vuln skill
)
```

### What the Skill Does

1. **Throttles requests** — minimum 5-10 seconds between requests
2. **Detects blocks** — recognizes Cloudflare challenges, 403s, timeouts
3. **Serializes agents** — one active tester at a time, not parallel swarm
4. **Adapts payloads** — avoids `SLEEP()` SQLi, uses event-handler XSS

## Strategy 2: Rotating Proxies

Spread requests across multiple IPs so no single IP accumulates enough hits to trigger a ban.

### Option A: Upstream Proxy Environment Variable

Set `PHANTOM_UPSTREAM_PROXY` before running Phantom. This URL is passed to the sandbox and available for tools to use:

```bash
# Set the rotating proxy URL
export PHANTOM_UPSTREAM_PROXY="http://user:pass@rotating-proxy.example.com:8080"

# Run the scan
phantom --target https://waf-protected-site.com --scan-mode quick
```

**How it works:**
- The `PHANTOM_UPSTREAM_PROXY` environment variable is injected into the sandbox container
- Tools can read this and use it with their `--proxy` flags
- Example: `curl -x $PHANTOM_UPSTREAM_PROXY https://target.com`
- The `waf_aware` skill instructs agents to use this proxy for requests

**Note:** Traffic still flows through Caido (internal proxy) for capture. The upstream proxy is an additional hop for IP rotation, used by tools that explicitly support it.

### Option B: Rotating Proxy Service

Popular rotating proxy providers:

| Provider | Use Case | Pricing |
|----------|----------|---------|
| [Bright Data](https://brightdata.com) | Residential IPs, best for Cloudflare | $$$ |
| [Oxylabs](https://oxylabs.io) | Datacenter + residential | $$ |
| [ScraperAPI](https://scraperapi.com) | Simple HTTP API | $ |
| [IPRoyal](https://iproyal.com) | Budget residential | $ |

### Option C: Self-Hosted Rotation

Deploy your own rotating proxy with multiple VPS IPs:

```bash
# Example with mitmproxy + IP rotation script
# (Requires multiple egress IPs on your server)
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/rotation.py:/rotation.py \
  mitmproxy/mitmproxy mitmdump -s /rotation.py
```

### Option D: Tor (Last Resort)

Tor provides IP rotation but is very slow and often blocked by WAFs:

```bash
# Route through Tor (not recommended for production scans)
export PHANTOM_UPSTREAM_PROXY="socks5://127.0.0.1:9050"
```

## Strategy 3: Whitelist Your IP

If you control the WAF configuration (or can request it from the client):

### Cloudflare

1. Client logs into Cloudflare dashboard
2. Security → WAF → Tools → IP Access Rules
3. Add your scanning IP with "Allow" action

### Imunify360 / CSF (cPanel)

```bash
# On the server (requires root)
csf -a YOUR_SCANNING_IP "Authorized penetration test"
```

### AWS WAF

Add your IP to an IP Set with Allow action in the WebACL.

## Combined Best Practice

For maximum reliability, use **all three**:

1. **Whitelist** (if possible) — eliminates the problem at source
2. **Rotating proxy** — spreads risk across IPs
3. **WAF-aware skill** — smart behavior even with rotation

Example scan setup:

```bash
# 1. Configure rotating proxy
export PHANTOM_UPSTREAM_PROXY="http://user:pass@proxy.brightdata.com:22225"

# 2. Run with WAF-aware mode
phantom --target https://protected-site.com --scan-mode quick

# 3. In the TUI, tell the root agent:
#    "Load the waf_aware skill. This target has Cloudflare.
#     Throttle all requests and serialize subagents."
```

## Detecting and Recovering from Blocks

### Signs You're Blocked

- All requests return Cloudflare challenge (5-second page)
- Caido shows 502 Timeout for all requests
- `curl` to target times out but other sites work
- Server returns 403 on previously-working endpoints

### Recovery Steps

1. **Stop all agents** — further requests make it worse
2. **Wait 15-30 minutes** — many WAFs auto-expire bans
3. **Check from different IP** — confirm target is still up
4. **Request whitelist** — contact client if testing is authorized
5. **Switch to rotating proxy** — if wait doesn't help

### Documenting Incomplete Coverage

If blocked before completing the assessment:

```markdown
## Incomplete Testing Due to WAF Block

The following areas could not be tested due to WAF IP blocking:
- SQL injection on /api/v2/* endpoints
- IDOR testing on user objects
- File upload validation

Recommendation: Whitelist the testing IP or provide VPN access
to complete the assessment.
```

## Troubleshooting

### "All my requests timeout after a few minutes"

Your IP was banned. Options:
1. Wait 30-60 minutes for auto-unban
2. Switch to a different egress IP
3. Use a rotating proxy

### "Cloudflare challenge on every request"

The WAF's bot detection triggered. Options:
1. Use `agent_browser` (real Chrome) instead of `curl`
2. Add realistic headers (User-Agent, Accept, etc.)
3. Reduce request rate significantly

### "I can browse the site manually but Phantom is blocked"

The WAF is fingerprinting automated tools. Options:
1. Load `waf_aware` skill for throttling
2. Use browser-based testing only
3. Whitelist the scanning IP

### "My rotating proxy still gets blocked"

The target may be blocking entire proxy provider ranges. Try:
1. Residential proxies instead of datacenter
2. Different provider with cleaner IP reputation
3. Self-hosted VPS in a different region
