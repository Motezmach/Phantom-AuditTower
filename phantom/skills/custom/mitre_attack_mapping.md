---
name: mitre_attack_mapping
description: MITRE ATT&CK mapping guidance for web application findings, attack paths, evidence, and defensive coverage
---

# MITRE ATT&CK Mapping

Use MITRE ATT&CK as a behavior and attack-path lens alongside OWASP, CWE, and CVSS. Do not force a vulnerability into a technique when the observed behavior does not support the mapping.

## Mapping Rules

1. Map observed attacker behavior, not the product name or scanner rule.
2. Prefer the most specific Enterprise technique/sub-technique supported by evidence.
3. Record the phase, technique ID, technique name, evidence reference, and confidence.
4. Use one primary mapping and optional secondary mappings; avoid long speculative lists.
5. Keep vulnerability classification separate: CWE/OWASP describe the weakness, ATT&CK describes adversary behavior.
6. Mark a mapping as inferred when the evidence supports the behavior but not every ATT&CK prerequisite.

## Web-Focused Examples

| Observed behavior | Common mapping direction | Evidence required |
|---|---|---|
| Active scanning or endpoint enumeration | Discovery / active scanning | requests, scope, discovered assets |
| Exploitation of an exposed web application | Initial Access / public-facing application exploitation | reproducible request and demonstrated impact |
| Valid stolen or misused credentials/tokens | Credential Access or Valid Accounts | token/principal evidence and authorized access proof |
| Command execution through an application | Execution / command interpreter | bounded execution proof and process/log evidence |
| Transfer of a tool or artifact through the application | Command and Control / ingress tool transfer | file/request evidence and controlled artifact identity |
| Collection of sensitive application data | Collection / relevant data source | exact records accessed and authorization comparison |

Verify the current ATT&CK catalog and version before finalizing IDs in a report.

## Attack-Path Mapping

For a chain, map each demonstrated step separately:

```text
public endpoint
  → authorization failure
  → sensitive object access
  → token or workflow impact
```

Attach evidence to each edge. Do not map the final impact to an upstream technique unless the chain actually reached it.

## Reporting Fields

For each finding or chain, provide:

- ATT&CK tactic/phase
- Technique/sub-technique ID and name
- Mapping confidence: confirmed, probable, or contextual
- Evidence IDs or request/response references
- Preconditions and scope
- Detection opportunities and relevant logs
- CWE/OWASP/CVSS classification separately

## False Positives

- A tool ran but did not reach the target.
- A scanner signature exists without a reproduced behavior.
- A vulnerability class is being confused with an ATT&CK technique.
- A theoretical follow-on action is reported as completed.
- A generic technique list is attached without evidence links.

## Summary

ATT&CK improves attack-path communication when every mapping is evidence-backed. Use OWASP/CWE/CVSS for the weakness and severity; use ATT&CK for what an adversary demonstrably did.
