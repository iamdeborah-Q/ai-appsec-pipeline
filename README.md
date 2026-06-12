# ai-appsec-pipeline

AI-powered AppSec pipeline: Semgrep SAST with LLM-based triage (Claude), EPSS-prioritized vulnerability reports, hardened golden Docker images, and security gates for CI/CD and AI coding agents.

# ai-appsec-pipeline

An AI-powered application security pipeline: Semgrep SAST with LLM-based triage
(Claude), a hardened "golden" Docker base image, and the foundations for
security gates in CI/CD and AI-assisted development.

This project demonstrates two ideas from modern AppSec:

1. **AI-enabled triage** — pattern-matching scanners find _suspects_; an LLM
   reasons about _exploitability_ to cut false-positive noise.
2. **Secure-from-the-start** — a pre-hardened golden image teams build `FROM`,
   so security is the default rather than an afterthought.

## What's built

### 1. LLM vulnerability triage (`scanner/triage.py`)

Runs Semgrep on a target, then for each finding sends the surrounding code to
Claude, which decides whether attacker-controlled input can actually reach the
dangerous operation (true positive) or not (false positive), and suggests a fix.
A ranked Markdown report is produced.

Features built and debugged along the way:

- **Deduplication** — collapses multiple rules hitting the same file+line.
- **Line-number anchoring** — the code context includes real line numbers and
  marks the flagged line, so the model reports correct positions.
- **Constant-detection** — findings buried inside very long data constants are
  labeled as demo data, preventing a class of false positive.
- **Taint-source signal** — flags findings where user input (`params[...]`)
  reaches the flagged line, used to prioritize (never to silently drop).

Result on DSVW (Damn Small Vulnerable Web): **9/9 findings correctly triaged**
— 8 true positives (SQL injection, command injection, insecure deserialization,
SSRF, code execution) and 1 correctly identified false positive. Notably, on the
login query the triage spots a partial-mitigation bug: the username is sanitized
but the password is concatenated raw — a nuance pure pattern-matching misses.

A sample report is in `examples/sample-report.md`.

### 2. Golden image (`golden-image/Dockerfile`)

A hardened Python 3.12 base image:

- Pinned, slim base (`python:3.12-slim-bookworm`) for reproducibility and a
  smaller attack surface.
- OS security patches applied; attacker tools (e.g. wget) removed.
- Runs as a **non-root** user (CIS Docker Benchmark).
- Secure environment defaults; pip upgraded to patch known pip CVEs.
- Scanned with Trivy: **0 fixable vulnerabilities** at any severity.

`golden-image/build-and-scan.sh` builds the image and fails if any fixable
HIGH/CRITICAL CVE is present — the "gate" pattern.

## How to run

Prerequisites: Python 3.12, Docker, Semgrep, Trivy, and an Anthropic API key.

```bash
# Set up
python3 -m venv .venv && source .venv/bin/activate
pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...

# Triage: scan a target, then triage with Claude
semgrep scan --config auto --json --quiet target-apps/DSVW > findings.json
python3 scanner/triage.py          # writes report.md

# Golden image: build + scan
./golden-image/build-and-scan.sh
```

## Key lessons and Observations

- **Prompt calibration is a trade-off.** Too lenient and the triage rubber-stamps
  everything; too strict and it dismisses a real SQL injection (a false negative,
  the more dangerous error). The prompt biases toward flagging when uncertain.
- **An LLM is only as good as its context.** A persistent false positive turned
  out to be a context-extraction bug: findings inside a 9,800-character constant
  gave the model misleading input. Fixing the extractor fixed the verdict.
- **Total CVEs ≠ actionable CVEs.** The golden image showed 142 total CVEs but 0
  _fixable_ ones — most were unfixable upstream Debian issues. Gating on fixable
  HIGH/CRITICAL avoids alert noise, the exact problem this project fights.



  - **Scanners over-report by design.** Of 10 raw Semgrep findings on DSVW, two
  were the same line flagged by different rules and one was demo data — so the
  real signal was ~8 unique issues. Deduplication and triage are what turn raw
  output into an actionable list.
- **Even official base images carry CVEs.** The "secure" python:slim image
  reported 142 vulnerabilities out of the box. Hardening reduces them, but some
  are inherited from upstream and can't be removed — which is why continuous
  scanning, not one-time hardening, is the real practice.
- **Order matters in a Dockerfile.** Upgrading pip *after* dropping to a non-root
  user left the old vulnerable pip in place (installed into the user's local
  folder). Moving the upgrade before the user switch replaced the system pip
  cleanly — a reminder that security fixes can silently no-op if sequenced wrong.

## Roadmap

- EPSS scoring to prioritize findings by real-world exploit probability
- CI pipeline: scan + triage on every PR, post report, gate on criticals
- Agentic security: secure-coding rules file + pre-commit hook
- MCP server exposing a scan tool to AI coding agents

## Test targets

- `DSVW` — tiny single-file app, used to validate triage correctness
- `PyGoat` — realistic Django app, used for noisier real-world demos
  (Both are cloned into `target-apps/`, which is gitignored.)
