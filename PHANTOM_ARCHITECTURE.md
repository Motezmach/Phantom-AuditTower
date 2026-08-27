# Phantom architecture

This document describes the implementation in this repository. Phantom is a local-first, root-led multi-agent security-testing application. It is not a hosted service and it does not use a separate coordinator process.

## Runtime flow

```text
CLI / TUI
   │  target, instructions, scan mode, configuration
   ▼
Run setup and scope normalization
   │  creates phantom_runs/<run-name>/ and mounts the run workspace
   ▼
Root agent
   │  plans work, tracks todos/coverage, and creates child agents
   ├──────────────► Reconnaissance and attack-surface work
   ├──────────────► Vulnerability and business-logic testing
   ├──────────────► Payload Crafter (on demand)
   ├──────────────► Web Validator (when a finding needs proof)
   ├──────────────► Attack Path Analyst (when findings can form a chain)
   └──────────────► Reporting Analyst (when structured output needs review)
                         │
                         ▼
                 Shared run workspace and evidence
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
       Report finalization       Local viewer + PDF
```

The runtime intentionally does not enforce a hard-coded phase DAG. The root agent decides which work is useful from the target, scope, discovered surface, and current coverage. Deterministic tooling still validates report structure, evidence, severity consistency, attack-path data, and applicable MITRE mappings.

## Root agent and child agents

The root is built by `phantom/agents/factory.py` and receives the root orchestration prompt plus common scan-mode and tool guidance. It has the agent-graph tools to:

- create, message, wait for, inspect, and stop child agents;
- plan and record coverage;
- load skills for the current surface;
- collect notes and todos;
- review reports and finish the scan.

The root itself is the coordinator. A child agent is a normal Phantom agent with a bounded task, the trusted target scope, the selected skills, and the shared run workspace. Recon and vulnerability-testing children are created dynamically from the root’s plan; there is no fixed list of one child per vulnerability class.

The explicit specialized agent types are registered in `phantom/agents/factory.py`:

| Agent type | Responsibility |
| --- | --- |
| `payload_crafter` | Create authorized, web-focused payload material for a specific input, platform, or sink. It requires an authorization gate, detection pairing, OPSEC notes, and report handoff. |
| `web_validator` | Re-test a candidate finding and preserve the smallest evidence-backed proof of impact. |
| `attack_path_analyst` | Connect independently supported findings into ordered, evidence-backed attack paths. |
| `reporting_analyst` | Review structured finding data and produce clear report-ready conclusions. |

These types are requested through the `create_agent` tool with `agent_type`. They are available on demand; the tool does not blindly spawn all four for every target.

## Skills

Skills are Markdown playbooks loaded into an agent prompt. `phantom/skills/` contains the following groups:

- `reconnaissance/` — target discovery and attack-surface mapping.
- `vulnerabilities/` — SQL injection, XSS, SSRF, IDOR, authorization, business logic, file handling, deserialization, WebSocket, API abuse, timing, and related testing.
- `protocols/` — OAuth, GraphQL, and WebSocket guidance.
- `technologies/` — payment systems, Firebase, Supabase, Auth0, LLM applications, and other platform-specific guidance.
- `coordination/` — root orchestration, white-box, and WAF-aware guidance.
- `tooling/` and `scan_modes/` — execution/tool-use guidance and quick, standard, or deep scan behavior.

Every agent receives the selected scan-mode guidance and common browser/Python guidance. Additional skills are chosen from the task and target evidence; the loader deduplicates them before rendering the prompt.

## Evidence, validation, and reporting

Agents work in the mounted run workspace and submit structured reports through Phantom’s reporting tools. Finalization writes the main report, individual findings, the coverage ledger, and machine-readable exports.

For a finding, Phantom checks:

1. target and endpoint identity;
2. description, impact, and reproduction evidence;
3. validation status and false-positive limitations;
4. CVSS/severity consistency;
5. attack-path steps when a chain is claimed; and
6. MITRE ATT&CK mappings when the demonstrated behavior supports a technique.

MITRE is evidence-aware. Phantom can infer high-confidence web mappings such as exploitation of a public-facing application, but it does not invent a technique for every application weakness. A finding may therefore say that no direct ATT&CK technique was recorded when the evidence describes a control or configuration defect rather than adversary behavior. Mappings are stored with the structured finding and rendered in reports where present.

## Docker sandbox

The default image is `phantom-sandbox:1.3.0`, built from `containers/Dockerfile` on `kalilinux/kali-rolling`. The LLM runs on the host/provider; the sandbox is for agent tools and target interaction.

Runtime facts:

- The default process runs as the non-root user `pentester`.
- `pentester` is in the sudo group and has passwordless sudo. This is therefore not a strict no-root boundary.
- The container receives `NET_ADMIN` and `NET_RAW`; Nmap also receives the required file capabilities during image build.
- `/workspace` is mounted from the run workspace. Extra workspace files are read-only mounts.
- `host.docker.internal` is mapped to the Docker host so an authorized local app can be reached.
- Caido is started inside the image for proxy capture and its exposed port is normally `48080`.
- CPU and memory are unlimited by Docker unless configured. Set `PHANTOM_SANDBOX_CPUS` and `PHANTOM_SANDBOX_MEM_LIMIT` for cgroup limits.
- Container logs are capped by default at `50m` × `3` files. PIDs, shared memory, network, and log settings can be configured with the variables documented in `docs/advanced/configuration.mdx`.

Build the image locally with:

```text
docker build -f containers/Dockerfile -t phantom-sandbox:1.3.0 .
```

## Local viewer

`phantom/interface/viewer/server.py` serves the committed SPA and reads run files directly from disk. The browser receives a per-process local session capability before it can read run data. The viewer provides run history, transcript/agent activity, findings, Markdown report content, and `/api/report/pdf` for local PDF generation.

The local viewer has no required account, email verification, encrypted-email delivery, cloud upgrade flow, or hosted dashboard dependency.

## Source map

| Area | Implementation |
| --- | --- |
| CLI and setup | `phantom/interface/main.py`, `phantom/interface/cli_args.py` |
| Agent construction | `phantom/agents/factory.py`, `phantom/agents/prompt.py` |
| Orchestration tools | `phantom/tools/agents_graph/`, `phantom/tools/coverage/` |
| Runtime backend | `phantom/runtime/`, `containers/Dockerfile` |
| Run storage | `phantom/core/paths.py`, `phantom/report/state.py` |
| Report and quality checks | `phantom/report/` |
| Local dashboard and PDF | `phantom/interface/viewer/` |
