### Overview

To help make Phantom better for everyone, we collect anonymized data that helps us understand how to better improve our AI security agent for our users, guide the addition of new features, and fix common errors and bugs. This feedback loop is crucial for improving Phantom's capabilities and user experience.

We use [PostHog](https://posthog.com), an open-source analytics platform, for data collection and analysis, along with [Scarf](https://scarf.sh). Our telemetry implementation is fully transparent - you can review the source code ([posthog.py](https://gitlab.3s.com.tn/internships/audit-tower/blob/main/phantom/telemetry/posthog.py), [scarf.py](https://gitlab.3s.com.tn/internships/audit-tower/blob/main/phantom/telemetry/scarf.py)) to see exactly what we track.

### Telemetry Policy

Privacy is our priority. All collected data is anonymized by default. Each session gets a random UUID that is not persisted or tied to you. Your code, scan targets, vulnerability details, and findings always remain private and are never collected.

### What We Track

We collect only very **basic** usage data including:

**Session Errors:** Duration and error types (not messages or stack traces)\
**System Context:** OS type, architecture, Phantom version\
**Scan Context:** Scan mode (quick/standard/deep), scan type (whitebox/blackbox)\
**Model Usage:** Which LLM model is being used and whether it runs via an API key or a model subscription (not prompts or responses)\
**Feature Usage:** Which built-in skills are loaded\
**Aggregate Metrics:** Vulnerability counts by severity and weakness category (CWE)

### What We **Never** Collect

- Usernames, or any identifying information
- Scan targets, file paths, target URLs, or domains
- Vulnerability details, descriptions, or code
- LLM requests and responses

### Local-only by default (opt-in)

Telemetry is **off by default**. Phantom runs in local mode out of the box: it
sends no anonymous analytics, and it skips the PyPI update check as well, so an
airgapped or on-prem deployment makes no outbound requests other than to your
configured LLM and the authorized target.

To opt in to anonymous usage analytics (and update notifications):

```bash
export PHANTOM_TELEMETRY=1
```

Regardless of this setting, your code, scan targets, vulnerability details, and
findings are **never** collected. To keep the update check on while leaving
telemetry off, that isn't supported by design — opting out of telemetry keeps
Phantom fully local.
