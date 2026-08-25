# 📚 Phantom Skills

## 🎯 Overview

Skills are specialized knowledge packages that enhance Phantom agents with deep expertise in specific vulnerability types, technologies, and testing methodologies. Each skill provides advanced techniques, practical examples, and validation methods that go beyond baseline security knowledge.

---

## 🏗️ Architecture

### How Skills Work

When an agent is created, it can load up to 5 specialized skills relevant to the specific subtask and context at hand:

```python
# Agent creation with specialized skills
create_agent(
    task="Test authentication mechanisms in API",
    name="Auth Specialist",
    skills="authentication_jwt,business_logic"
)
```

The skills are dynamically injected into the agent's system prompt, allowing it to operate with deep expertise tailored to the specific vulnerability types or technologies required for the task at hand.

---

## 📁 Skill Categories

| Category | Purpose |
|----------|---------|
| **`/vulnerabilities`** | Advanced testing techniques for core vulnerability classes like authentication bypasses, business logic flaws, and race conditions |
| **`/frameworks`** | Specific testing methods for popular frameworks e.g. Django, Express, FastAPI, and Next.js |
| **`/technologies`** | Specialized techniques for third-party services such as Supabase, Firebase, Auth0, and payment gateways |
| **`/protocols`** | Protocol-specific testing patterns for GraphQL, WebSocket, OAuth, and other communication standards |
| **`/tooling`** | Command-line playbooks for core sandbox tools (nmap, nuclei, httpx, ffuf, subfinder, naabu, katana, sqlmap) |
| **`/cloud`** | Cloud provider security testing for AWS, Azure, GCP, and Kubernetes environments |
| **`/reconnaissance`** | Advanced information gathering and enumeration techniques for comprehensive attack surface mapping |
| **`/custom`** | Community-contributed skills for specialized or industry-specific testing scenarios |

Notable coordination skills:
- `source_aware_whitebox` (coordination): white-box orchestration playbook
- `waf_aware` (coordination): throttling and block detection for WAF-protected targets (Cloudflare, Imunify360, mod_security)

Notable source-aware skills:
- `source_aware_sast` (custom): semgrep/AST/secrets/supply-chain static triage workflow
- `dependency_cve_scanning` (custom): trivy-based SCA workflow for reporting known dependency CVEs via `create_dependency_report`
- `npx_confusion` (custom): npx/npm exec/bunx fallback and adjacent package-runner identity confusion, with runner-specific registry and reporting gates
- `semantic_confusion` (vulnerabilities): cross-boundary parser, normalization, and representation mismatch analysis
- `agentic_system_security` (vulnerabilities): effective-authority and MCP/tool ecosystem security testing
- `browser_security` (vulnerabilities): browsing-context, postMessage, XS-Leaks, service-worker, and cross-origin state-machine testing
- `azure` (cloud): Azure and Microsoft Entra privilege, PIM, workload identity, and cross-plane escalation analysis
- `infrastructure_lifecycle` (reconnaissance): abandoned or mutable external dependencies such as update endpoints, MX, storage, and control domains
- `argument_injection` (vulnerabilities): shell-free CLI option smuggling, secondary argument-file parsing, and platform-specific argv transformation boundaries
- `electron_desktop_apps` (technologies): Electron renderer-to-native trust boundaries, preload/IPC exposure, and navigation analysis

Notable LLM security skills:
- `llm_applications` (technologies): end-to-end OWASP 2026 LLM01-LLM10 coverage across models, RAG, vectors, agents, tools, outputs, supply chain, and resource controls
- `llm_prompt_injection` (vulnerabilities): deep direct, indirect, multimodal, memory, and tool-result prompt-injection testing

Notable offensive/payload skills:
- `web_payload_crafting` (vulnerabilities): context-aware web payloads (SQLi,
  XSS, SSTI, XXE, SSRF, command injection) with escalation to the scoped
  `payload_crafter` agent type for a concrete web hypothesis

**Note:** The `payload_crafter` agent type provides the web-specific
authorization gate, platform selection, detection pairing, ATT&CK mapping,
cleanup, and validator handoff. Lab-only host tooling remains an exceptional
platform-specific path; phishing, persistence, C2, process injection, EDR
evasion, and supply-chain work are outside this agent's lane. Spawn with:
```python
create_agent(
    name="Web Payload Crafter",
    task="Craft a bounded payload mutation set for this confirmed in-scope web input. Include the baseline request, parser context, oracle, ATT&CK mapping, detection pairing, cleanup, and validator handoff.",
    skills=["web_payload_crafting", "xss"],
    agent_type="payload_crafter",
)
```

For confirmed candidates, the focused on-demand pipeline is:

```text
candidate → web_validator → payload_crafter (if context-specific mutations are needed)
          → reporting_analyst → attack_path_analyst
```

The validator supplies independent evidence, the reporting analyst files the
structured finding once, and the attack-path analyst separates demonstrated
chains from theoretical pivots.

---

## 🎨 Creating New Skills

### What Should a Skill Contain?

A good skill is a structured knowledge package that typically includes:

- **Advanced techniques** - Non-obvious methods specific to the task and domain
- **Practical examples** - Working payloads, commands, or test cases with variations
- **Validation methods** - How to confirm findings and avoid false positives
- **Context-specific insights** - Environment and version nuances, configuration-dependent behavior, and edge cases
- **YAML frontmatter** - `name` and `description` fields for skill metadata

Skills focus on deep, specialized knowledge to significantly enhance agent capabilities. They are dynamically injected into agent context when needed.

---

## 🤝 Contributing

Community contributions are more than welcome — contribute new skills via [pull requests](https://gitlab.3s.com.tn/internships/audit-tower/-/merge_requests) or [GitHub issues](https://gitlab.3s.com.tn/internships/audit-tower/-/issues) to help expand the collection and improve extensibility for Phantom agents.

---

> [!NOTE]
> **Work in Progress** - We're actively expanding the skills collection with specialized techniques and new categories.
