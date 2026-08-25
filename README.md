# Phantom

Phantom is a local-first agentic AI penetration-testing tool for authorized web applications, APIs, and source code.

It combines a coordinating root agent, focused reconnaissance and testing agents, a Docker execution sandbox, structured evidence, and a local report viewer.

## What Phantom provides

- Guided reconnaissance and attack-surface mapping.
- Specialized agents for vulnerability testing, validation, reporting, and payload crafting.
- Evidence-backed findings with severity, impact, reproduction steps, and MITRE ATT&CK context where relevant.
- Local run artifacts under `phantom_runs/`.
- A local dashboard with Markdown, JSON, CSV, SARIF, and PDF report downloads.

Use Phantom only against systems you own or are explicitly authorized to test.

## Requirements

- Python 3.12 or newer.
- [uv](https://docs.astral.sh/uv/).
- Docker Desktop or Docker Engine.
- Either a cloud LLM endpoint and API key, or a compatible local LLM server.

## Install

```bash
git clone <your-gitlab-repository-url>
cd phantom
uv sync
```

The public command and Python package are both named `phantom`.

## Configure

Choose one model provider. The Docker sandbox is independent of the model provider
and only needs to be built once on each machine.

Cloud provider example:

PowerShell:

```powershell
$env:PHANTOM_LLM="deepseek/deepseek-chat"
$env:LLM_API_KEY="your-api-key"
$env:PHANTOM_IMAGE="phantom-sandbox:1.3.0"
$env:PHANTOM_RUNTIME_BACKEND="docker"
```

Bash:

```bash
export PHANTOM_LLM="deepseek/deepseek-chat"
export LLM_API_KEY="your-api-key"
export PHANTOM_IMAGE="phantom-sandbox:1.3.0"
export PHANTOM_RUNTIME_BACKEND="docker"
```

Local Ollama example:

PowerShell:

```powershell
$env:PHANTOM_LLM="ollama/qwen3-vl"
$env:LLM_API_BASE="http://localhost:11434"
$env:PHANTOM_IMAGE="phantom-sandbox:1.3.0"
$env:PHANTOM_RUNTIME_BACKEND="docker"
```

Bash:

```bash
export PHANTOM_LLM="ollama/qwen3-vl"
export LLM_API_BASE="http://localhost:11434"
export PHANTOM_IMAGE="phantom-sandbox:1.3.0"
export PHANTOM_RUNTIME_BACKEND="docker"
```

For LM Studio, vLLM, or another OpenAI-compatible local server, use a model name
such as `openai/local-model` and set `LLM_API_BASE` to that server's URL. Most local
servers do not need `LLM_API_KEY`; use one only when the server requires it. See
`docs/llm-providers/local.mdx` for tool-calling requirements.

Optional sandbox limits:

```text
PHANTOM_SANDBOX_CPUS=2
PHANTOM_SANDBOX_MEM_LIMIT=4g
```

The local configuration file is `~/.phantom/cli-config.json`. See [Configuration](docs/advanced/configuration.mdx) for all supported settings.

## Build the sandbox

From the repository root:

```bash
bash scripts/docker.sh 1.3.0
```

PowerShell users can build it directly:

```powershell
docker build -f containers/Dockerfile -t phantom-sandbox:1.3.0 .
```

The default image is `phantom-sandbox:1.3.0`. Build it once per machine. Switching
between cloud and local LLMs only changes the environment variables; it does not
require rebuilding the sandbox image.

## Run a scan

Only scan an authorized target:

```bash
uv run phantom --target "http://demo.testfire.net/" --scan-mode quick
```

Other useful commands:

```bash
uv run phantom --help
uv run phantom view
uv run phantom view <run-name>
uv run phantom --resume <run-name>
```

## Results

Each run is saved below:

```text
phantom_runs/<run-name>/
```

Important artifacts include:

- `run.json` — run metadata and status.
- `phantom.log` — runtime and orchestration log.
- `penetration_test_report.md` — primary report.
- `vulnerabilities/` — individual finding reports.
- JSON, CSV, and SARIF exports when generated.

Run `uv run phantom view <run-name>` to open the local viewer. The viewer can download a PDF for the selected run.

## How it works

The root agent understands the engagement scope, creates a plan, and assigns bounded work to specialized child agents. Agents use the available skills and sandbox tools, write evidence to the run workspace, and return structured results. Validation and reporting consolidate those results into the final report.

## Documentation

- [Quickstart](docs/quickstart.mdx)
- [CLI reference](docs/usage/cli.mdx)
- [Configuration](docs/advanced/configuration.mdx)
- [Sandbox guide](docs/tools/sandbox.mdx)
- [Reports](docs/reports.mdx)
- [Troubleshooting](docs/troubleshooting.mdx)
- [Agent and skill development](docs/advanced/skills.mdx)
- [Developer guide](docs/development.mdx)

## Development

Run the test suite with:

```bash
uv run pytest -q
```

Do not commit API keys, private target data, or generated `phantom_runs/` artifacts.

## License

Apache License 2.0. See [LICENSE](LICENSE).
