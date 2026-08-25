# Phantom Architecture

## Overview

Phantom is the next-generation offensive security agent built on Phantom's foundation, fixing the coordination issues observed in production runs and adding deeper vulnerability coverage.

## Core Problems Solved

| Phantom Issue | Phantom Solution |
|-------------|------------------|
| Flat agent tree (all children under root) | Enforced hierarchical chains |
| Missing validation phase | Mandatory validation gate before reporting |
| No attack chain analysis | Post-discovery chain analyzer |
| Agent sprawl (22 agents, 1 finding) | Budget-aware spawning with ROI estimation |
| No cross-run learning | Technique effectiveness memory |

---

## Agent Hierarchy: The 4-Phase Chain

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            ROOT ORCHESTRATOR                                │
│  Role: Decompose scope, spawn Phase-1 agents, track coverage, final report │
│  Tools: create_agent, view_coverage, finish_scan                            │
│  NEVER: touches target, runs payloads, files vulnerability reports          │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
┌─────────────────────────┐ ┌─────────────────────────┐ ┌─────────────────────────┐
│   PHASE 1: RECON        │ │   PHASE 1: RECON        │ │   PHASE 1: RECON        │
│   Asset Discovery       │ │   Tech Fingerprinting   │ │   Attack Surface Map    │
│   Skills: asset_discovery│ │   Skills: httpx, nmap   │ │   Skills: katana, ffuf  │
└─────────────────────────┘ └─────────────────────────┘ └─────────────────────────┘
            │                           │                           │
            └───────────────────────────┼───────────────────────────┘
                                        ▼
                              [Shared Attack Surface Graph]
                                        │
          ┌─────────────────────────────┼─────────────────────────────┐
          ▼                             ▼                             ▼
┌─────────────────────────┐ ┌─────────────────────────┐ ┌─────────────────────────┐
│   PHASE 2: DISCOVERY    │ │   PHASE 2: DISCOVERY    │ │   PHASE 2: DISCOVERY    │
│   SQLi Hunter           │ │   XSS Hunter            │ │   Auth Tester           │
│   Skills: sql_injection │ │   Skills: xss           │ │   Skills: auth_jwt      │
│   Parent: Recon Agent   │ │   Parent: Recon Agent   │ │   Parent: Recon Agent   │
└─────────────────────────┘ └─────────────────────────┘ └─────────────────────────┘
            │                           │                           │
            │ finding                   │ finding                   │ finding
            ▼                           ▼                           ▼
┌─────────────────────────┐ ┌─────────────────────────┐ ┌─────────────────────────┐
│   PHASE 3: VALIDATION   │ │   PHASE 3: VALIDATION   │ │   PHASE 3: VALIDATION   │
│   SQLi Validator        │ │   XSS Validator         │ │   Auth Bypass Validator │
│   Task: Prove with PoC  │ │   Task: Confirm in DOM  │ │   Task: Verify ATO      │
│   Parent: SQLi Hunter   │ │   Parent: XSS Hunter    │ │   Parent: Auth Tester   │
│   + SKEPTIC (adversary) │ │   + SKEPTIC (adversary) │ │   + SKEPTIC (adversary) │
└─────────────────────────┘ └─────────────────────────┘ └─────────────────────────┘
            │                           │                           │
            │ confirmed                 │ confirmed                 │ confirmed
            ▼                           ▼                           ▼
┌─────────────────────────┐ ┌─────────────────────────┐ ┌─────────────────────────┐
│   PHASE 4: REPORTING    │ │   PHASE 4: REPORTING    │ │   PHASE 4: REPORTING    │
│   SQLi Report Agent     │ │   XSS Report Agent      │ │   Auth Report Agent     │
│   + Fix (if whitebox)   │ │   + Fix (if whitebox)   │ │   + Fix (if whitebox)   │
│   Parent: SQLi Valid.   │ │   Parent: XSS Valid.    │ │   Parent: Auth Valid.   │
└─────────────────────────┘ └─────────────────────────┘ └─────────────────────────┘
                                        │
                                        ▼
                              [Chain Analyzer runs]
                                        │
                                        ▼
                              [Final Report with Chains]
```

---

## Enforced Spawning Rules

```python
SPAWN_RULES = {
    "root": {
        "can_spawn": ["recon", "coordinator"],
        "cannot_spawn": ["discovery", "validation", "reporting"],
        "reason": "Root orchestrates, doesn't hunt"
    },
    "recon": {
        "can_spawn": ["discovery"],
        "cannot_spawn": ["validation", "reporting"],
        "reason": "Recon feeds discovery agents"
    },
    "discovery": {
        "can_spawn": ["validation"],
        "cannot_spawn": ["recon", "reporting"],
        "reason": "Findings need validation before reporting"
    },
    "validation": {
        "can_spawn": ["reporting"],
        "cannot_spawn": ["recon", "discovery"],
        "reason": "Only confirmed findings get reported"
    },
    "reporting": {
        "can_spawn": [],
        "cannot_spawn": ["*"],
        "reason": "Terminal agent - files report and exits"
    }
}
```

---

## Validation Gate: The Skeptic Pattern

Every finding must survive adversarial verification:

```
┌─────────────────────┐
│   Discovery Agent   │
│   "Found SQLi in    │
│   /api/users?id=1"  │
└─────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────┐
│              VALIDATION CHAMBER                      │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌─────────────┐         ┌─────────────┐           │
│  │  CONFIRMER  │         │   SKEPTIC   │           │
│  │  "Build PoC │         │  "Try to    │           │
│  │   that      │   VS    │   disprove  │           │
│  │   works"    │         │   with WAF/ │           │
│  │             │         │   false pos │           │
│  └─────────────┘         └─────────────┘           │
│         │                       │                   │
│         ▼                       ▼                   │
│  ┌─────────────────────────────────────────────┐   │
│  │           CONFIDENCE SCORE                   │   │
│  │  confirmed_by_poc: true                      │   │
│  │  skeptic_disproved: false                    │   │
│  │  confidence: 0.95                            │   │
│  │  verdict: CONFIRMED                          │   │
│  └─────────────────────────────────────────────┘   │
│                                                      │
└─────────────────────────────────────────────────────┘
           │
           ▼ (only if confidence >= 0.8)
┌─────────────────────┐
│   Reporting Agent   │
│   Files vuln report │
└─────────────────────┘
```

---

## Attack Chain Analysis

Post-scan phase that combines isolated findings:

```python
CHAIN_PATTERNS = [
    {
        "name": "Unauthenticated ATO",
        "pattern": ["unauth_input", "stored_xss", "session_in_storage"],
        "combined_severity": "critical",
        "description": "Unauth user injects XSS → steals admin session"
    },
    {
        "name": "SSRF to Cloud Metadata",
        "pattern": ["ssrf", "cloud_metadata_accessible"],
        "combined_severity": "critical",
        "description": "SSRF reaches 169.254.169.254 → IAM credentials"
    },
    {
        "name": "Auth Bypass + Privilege Escalation",
        "pattern": ["auth_bypass", "idor_write"],
        "combined_severity": "critical",
        "description": "Bypass auth → modify other users' data"
    },
    {
        "name": "Prototype Pollution to XSS",
        "pattern": ["prototype_pollution", "gadget_sink"],
        "combined_severity": "high",
        "description": "Pollute Object.prototype → trigger XSS gadget"
    }
]
```

---

## Skill Categories (Expanded)

### Core Vulnerability Skills (`phantom/skills/vulnerabilities/`)

| Skill | Focus |
|-------|-------|
| `sql_injection.md` | UNION, blind, error-based, ORM bypass |
| `xss.md` | Reflected, stored, DOM, mXSS |
| `ssrf.md` | Cloud metadata, internal services, protocol smuggling |
| `cache_poisoning.md` | **NEW** Web cache deception, DNS rebinding, CDN confusion |
| `websocket_security.md` | **NEW** CSWSH, message injection, origin bypass |
| `api_abuse.md` | **NEW** Rate limiting, batch attacks, GraphQL depth |
| `oauth_oidc_deep.md` | **NEW** PKCE bypass, token theft, redirect chains |
| `prototype_pollution_chains.md` | **NEW** Gadget hunting, AST injection |
| `deserialization_gadgets.md` | **NEW** Java/PHP/Python/Ruby gadget chains |
| `timing_attacks.md` | **NEW** User enum, crypto oracle, race conditions |

### Technology Skills (`phantom/skills/technologies/`)

| Skill | Focus |
|-------|-------|
| `mobile_api_security.md` | **NEW** Cert pinning bypass, API extraction |
| `payment_integrations.md` | **NEW** Stripe, PayPal, crypto wallets |
| `ai_ml_security.md` | **NEW** Prompt injection, model theft, training poisoning |
| `kubernetes_attack.md` | **NEW** Unauthenticated kubelet, etcd, RBAC escalation |
| `cloudflare_origin.md` | **NEW** Origin IP discovery, WAF bypass |

### Coordination Skills (`phantom/skills/coordination/`)

| Skill | Focus |
|-------|-------|
| `root_orchestrator.md` | How root decomposes and delegates |
| `validation_methodology.md` | **NEW** How to validate findings properly |
| `attack_chain_building.md` | **NEW** How to combine findings |
| `skeptic_methodology.md` | **NEW** How to adversarially verify |

---

## Budget-Aware Spawning

```python
class BudgetAwareSpawner:
    """
    Before spawning an agent, estimate ROI:
    - What's the expected finding rate for this skill/target combo?
    - How much budget would this agent consume?
    - Are there higher-priority untested surfaces?
    """
    
    def should_spawn(self, task: str, skills: list[str], budget_remaining: float) -> bool:
        estimated_cost = self.estimate_cost(task, skills)
        expected_findings = self.predict_findings(task, skills)
        
        roi = expected_findings / estimated_cost
        
        # Don't spawn if ROI is poor or budget is tight
        if roi < 0.1 or estimated_cost > budget_remaining * 0.25:
            return False
            
        # Check if higher-priority work exists
        untested = self.coverage.get_untested_high_priority()
        if untested and self.is_lower_priority(task, untested):
            return False
            
        return True
```

---

## Directory Structure

```
phantom/
├── phantom/
│   ├── agents/
│   │   ├── factory.py          # Agent builder (with spawn rules)
│   │   ├── prompt.py           # System prompt renderer
│   │   ├── phases.py           # NEW: Phase definitions and rules
│   │   └── prompts/
│   │       └── system_prompt.jinja
│   │
│   ├── core/
│   │   ├── agents.py           # AgentCoordinator
│   │   ├── chains.py           # NEW: Attack chain analyzer
│   │   ├── coverage.py         # NEW: Coverage tracker
│   │   ├── validation.py       # NEW: Validation gate
│   │   └── runner.py           # Scan runner
│   │
│   ├── skills/
│   │   ├── vulnerabilities/
│   │   │   ├── cache_poisoning.md      # NEW
│   │   │   ├── websocket_security.md   # NEW
│   │   │   ├── api_abuse.md            # NEW
│   │   │   ├── oauth_oidc_deep.md      # NEW
│   │   │   ├── prototype_pollution_chains.md  # NEW
│   │   │   ├── deserialization_gadgets.md     # NEW
│   │   │   ├── timing_attacks.md       # NEW
│   │   │   └── ... (existing)
│   │   │
│   │   ├── technologies/
│   │   │   ├── mobile_api_security.md  # NEW
│   │   │   ├── payment_integrations.md # NEW
│   │   │   ├── ai_ml_security.md       # NEW
│   │   │   ├── kubernetes_attack.md    # NEW
│   │   │   ├── cloudflare_origin.md    # NEW
│   │   │   └── ... (existing)
│   │   │
│   │   └── coordination/
│   │       ├── root_orchestrator.md
│   │       ├── validation_methodology.md  # NEW
│   │       ├── attack_chain_building.md   # NEW
│   │       ├── skeptic_methodology.md     # NEW
│   │       └── ... (existing)
│   │
│   └── tools/
│       ├── agents_graph/
│       │   └── tools.py        # create_agent with spawn rules
│       ├── coverage/           # NEW
│       │   └── tools.py        # view_coverage, claim_endpoint
│       └── chains/             # NEW
│           └── tools.py        # analyze_chains, link_findings
```

---

## Implementation Priority

1. **Phase 1: Fix Agent Coordination** (Critical)
   - Add phase tracking to `create_agent`
   - Enforce spawn rules
   - Add validation gate

2. **Phase 2: New Skills** (High)
   - `cache_poisoning.md`
   - `websocket_security.md`
   - `api_abuse.md`
   - `timing_attacks.md`
   - `oauth_oidc_deep.md`

3. **Phase 3: Chain Analysis** (Medium)
   - Post-scan chain detection
   - Combined severity scoring

4. **Phase 4: Coverage Tracking** (Medium)
   - Shared attack surface graph
   - Endpoint claiming

5. **Phase 5: Budget Awareness** (Lower)
   - ROI estimation
   - Dynamic reallocation
