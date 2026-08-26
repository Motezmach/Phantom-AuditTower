---
name: web_payload_crafting
description: Context-aware web payload design for exploitation and post-exploitation handoffs in authorized penetration tests
---

# Web Payload Crafting

Use this skill when a specialist has identified a concrete web input, parser,
sink, or vulnerability hypothesis and needs carefully selected request
mutations. It is the web-facing playbook for the `payload_crafter` agent type;
host-level artifact generation is outside this skill's normal lane and must
remain an explicitly authorized, isolated lab handoff.

**Authorization requirement:** Only use against explicitly authorized targets with written scope.

## Mission

Craft the smallest useful test input for an in-scope endpoint, observe a meaningful oracle, and hand promising candidates to an independent validator. Prefer one-variable mutations and response differentials over large blind sprays.

## Required Context

Before crafting anything, collect:

- In-scope origin, endpoint, method, and exact parameter location
- Authentication principal and authorization level used for the request
- A clean baseline request and response
- Suspected vulnerability class and parser/rendering context
- Content type, encoding layers, gateway/WAF behavior, and rate limits
- Allowed impact level, callback policy, and stop conditions

If the endpoint, principal, or scope is unclear, stop and ask the parent agent for the missing context.

## Payload Ladder

Progress only when the previous step produces a meaningful signal:

1. **Baseline** — replay the original request and record status, size, headers, timing, redirects, and body markers.
2. **Unique canary** — insert a harmless, per-test marker such as `PHANTOM_CANARY_<id>` to locate reflection, storage, transformation, or parser behavior.
3. **Context probe** — apply the minimum syntax needed to test the suspected parser context: HTML, attribute, JavaScript, URL, JSON, XML, template, SQL, NoSQL, path, or command argument.
4. **Encoding matrix** — test only relevant transport encodings: URL encoding, JSON escaping, Unicode normalization, form vs JSON, multipart, or one alternate content type.
5. **Parser differential** — test duplicate keys, scalar/array/object changes, method override, and normalization only when the target uses that parser or gateway path.
6. **Impact probe** — use a controlled, non-destructive oracle such as a deterministic response change, a scoped canary callback, or a bounded proof of unauthorized state/data access.
7. **Handoff** — send the smallest reproducible candidate, baseline comparison, and expected oracle to a validator agent.

Do not skip directly to broad fuzzing or destructive execution. A payload is useful only when its context and expected signal are known.

## Context Selection

| Context | Crafting focus | Minimum evidence |
|---|---|---|
| HTML/attribute/URL | reflection, encoding, browser-side canary | DOM or rendered-response location plus execution evidence |
| JSON/API | type changes, duplicate keys, nested objects, unknown fields | parser behavior and authorization/business-impact diff |
| SQL/NoSQL | type/operator handling and differential probes | repeatable data/logic differential, not only an error string |
| SSRF/URL fetch | scheme, host, redirect, and parser normalization | controlled callback or demonstrable fetch behavior |
| XML/SOAP | entity/configuration behavior and parser errors | file read/callback oracle |
| Template | expression evaluation in the identified engine/context | deterministic evaluation result and engine fingerprint |
| Path/file | normalization, separators, encoding, and root-boundary checks | read/write or clear boundary violation |
| WebSocket | message schema, channel, identity, and replay variations | per-message authorization or state-change evidence |
| Command injection | shell metacharacters, argument injection, env vars | out-of-band callback or observable side effect |
| Deserialization | gadget chains, type confusion, polyglot payloads | RCE or SSRF via gadget |

## Bounded Web Mutation Guidance

Keep examples abstract until the parent supplies the exact endpoint, parser,
principal, authorization decision, and allowed impact. The agent should emit a
small mutation set rather than a reusable exploit corpus:

| Hypothesis | Safe first mutation | Required oracle |
|---|---|---|
| Reflection/XSS | Unique inert marker in the identified output context | Location and encoding, followed by controlled browser evidence only when authorized |
| SQL/NoSQL behavior | One type/operator boundary mutation | Repeatable data or logic differential with the same principal |
| SSRF/URL fetch | Approved canary URL or local interaction monitor | Confirmed server-side request and destination class |
| Template/parser boundary | Harmless expression or malformed-input probe | Deterministic parser evaluation/error tied to the identified engine |
| XML/entity handling | Non-sensitive, non-destructive parser probe | Parser behavior or approved canary interaction |
| File/path boundary | Normalization-only variant | Clear root-boundary or access-control differential without reading secrets |
| Command/execution hypothesis | Parent-approved inert marker or local test harness | Bounded server-side execution evidence; no shell, persistence, or C2 |
| Deserialization | Framework/type fingerprint and inert object-shape probe | Reproducible parser behavior before any impact validation |

Do not include credential theft, destructive file operations, reverse shells,
uncontrolled callbacks, cloud metadata access, internal-service targeting,
web-shell installation, or broad gadget/loader corpora in this skill. If a
test requires any of those, stop and return the authorization decision and a
structured handoff instead of generating the content.

## Candidate Output

Return a structured handoff for each candidate:

```text
Candidate: <stable short name>
Class: <vulnerability class>
Request location: <method, path, parameter/header/message>
Context: <parser or rendering context>
Baseline: <status, size, key headers/body markers>
Mutation: <sanitized request description or exact bounded value>
Expected oracle: <what would prove the hypothesis>
Observed signal: <what changed>
Safety: <read-only | canary | controlled state change>
Stop condition: <when to stop testing>
Validator handoff: <what must be independently reproduced>
```

Never claim a vulnerability from reflection, an error page, a scanner label, or a blocked request alone.

## Coordination

- Spawn this specialist only after recon or a vulnerability agent identifies a concrete input surface.
- Load this skill with one context skill, such as `xss`, `sql_injection`, `ssrf`, `oauth`, or `websocket_security`.
- The payload crafter designs candidates; the validator proves exploitability; the reporting agent files the finding.
- Do not duplicate the work of an existing vulnerability specialist or validator.

## Scope and Escalation

- Stay inside the declared target and request budget.
- Use synthetic identifiers and canaries for initial probing.
- Stop after repeated blocks, instability, or unexpected state changes; report the condition to the parent.
- **Concrete web hypothesis?** Spawn a `payload_crafter` agent type for a
  bounded, platform-specific web payload handoff. Include the baseline
  request, parser/rendering context, principal, oracle, scope limits, and
  cleanup requirements. The agent returns a small mutation set and detection
  pairing for validation.
- After a candidate is identified, spawn the `web_validator` agent type for
  independent reproduction before the `reporting_analyst` files a finding.
  The reporting handoff must carry validation status, demonstrated impact
  tags, attack-path steps, and evidence-backed ATT&CK mappings.
- Do not use this handoff for reverse shells, persistence, phishing, C2,
  process injection, EDR evasion, or supply-chain delivery. Those are outside
  Phantom's web-payload lane and must be refused or handed off to an explicitly
  authorized specialist.

## False Positives

- A marker is reflected but safely encoded in the relevant output context.
- A parser accepts an unusual type but authorization and business invariants remain intact.
- A callback came from a test harness or proxy rather than the target.
- A response difference is caused by caching, rate limiting, or an unstable backend and cannot be reproduced from a clean baseline.
- A WAF block is treated as proof of a vulnerability.

## Summary

Good web payload crafting is context selection plus controlled iteration. Start
with canaries, escalate only after reproducible differentials, and spawn a
`payload_crafter` agent for a concrete in-scope web hypothesis. The agent must
return detection content, ATT&CK mapping, cleanup, and a validator handoff.

## Web Payload Handoff

**Workflow:**
```
Recon → Input surface identified → web_payload_crafting (this skill)
    → Context probe → Reproducible hypothesis?
        → YES: dispatch_required_discovery or create_agent(name="Web Payload Crafter", task="...", skills=["web_payload_crafting", "<context>"], agent_type="payload_crafter")
               → bounded mutation set + ATT&CK + detection + validator handoff
        → NO: Continue discovery or report the negative result
```
