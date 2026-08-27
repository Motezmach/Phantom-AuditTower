# Contributing to Phantom

Phantom is maintained in the 3S GitLab repository. Keep changes focused and preserve the working scan, sandbox, viewer, and reporting paths.

## Development setup

Requirements:

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- Docker Desktop or Docker Engine
- Git
- Go only when changing or packaging the TUI sidecar

Clone and install:

```bash
git clone https://gitlab.3s.com.tn/internships/audit-tower.git
cd audit-tower
uv sync
```

PowerShell uses the same Git and uv commands. Configure a test model in the current terminal, then use an explicitly authorized test target:

```powershell
$env:PHANTOM_LLM="provider/model"
$env:LLM_API_KEY="your-api-key"
uv run phantom --target "https://authorized.example" --scan-mode quick
```

## Working on the viewer

The source is in `phantom/interface/viewer/frontend/`; the committed bundle is in `phantom/interface/viewer/static/`.

```bash
cd phantom/interface/viewer/frontend
npm ci
npm run build
```

Commit the regenerated static bundle with the source change.

## Working on the sandbox

```bash
docker build -f containers/Dockerfile -t phantom-sandbox:1.3.0 .
```

The runtime container defaults to the `pentester` user, but currently retains passwordless sudo and network capabilities. Do not describe it as a strict no-root boundary.

## Adding a skill or agent type

Skills live under `phantom/skills/` and are Markdown playbooks loaded into agent prompts. Keep a skill focused on one testing family or technology and include:

- scope and authorization assumptions;
- practical testing workflow;
- evidence and validation requirements;
- false-positive limits;
- remediation/reporting notes.

Specialized agent types are registered in `phantom/agents/factory.py`. Add a prompt under `phantom/agents/prompts/` and update the registry and tests when adding one.

## Checks before a merge request

```bash
uv run pytest -q
git diff --check
git status
```

Review the staged file list manually. Never commit API keys, credentials, private target data, generated `phantom_runs/`, virtual environments, or build caches.

Use a focused branch and explain the behavior change, tests run, and any documentation updates in the merge request.
