# AppSec Demon - Secure Pipeline Lab

A hands-on lab for building a secure CI/CD pipeline with GitHub Actions, two self-hosted runners in local VMs, and an **intentionally vulnerable** Flask file manager as the target.

> [!WARNING]
> `myprj/app.py` contains deliberate vulnerabilities (path traversal, XSS) for the scanners to find. Never expose the prod VM to the internet.

## High-Level Diagram

```mermaid
flowchart LR
    dev([Developer]) -- "git push / PR" --> gh[GitHub]
    gh -- "PR + push: scans, build, tests" --> hosted[GitHub-hosted runner]
    hosted -- "push to prod: SHA-tagged images" --> hub[(Docker Hub)]
    gh -- "deploy job" --> prod[Prod VM<br/>runner: prod-deploy]
    hub -- "docker compose pull" --> prod
    gh -- "DAST job" --> ci[CI/CD VM<br/>runner: ci-cd]
    ci -- "ZAP full scan" --> prod
    hosted -. "SARIF" .-> sec[GitHub Security tab]
    ci -. "DAST report artifact" .-> appsec([AppSec engineer])
    sec -.-> appsec
```

## Low-Level Diagram

```mermaid
flowchart TD
    subgraph hosted["GitHub-hosted (every PR and push to dev/prod)"]
        secrets["Secret scan<br/>gitleaks, full history"]:::block
        sast["SAST<br/>semgrep + bandit"]:::report
        sca["SCA<br/>pip-audit on hashed lockfile"]:::block
        lint["Dockerfile lint<br/>hadolint"]:::block
        build["Build images, unit tests, CycloneDX SBOM,<br/>trivy + VEX → KEV/EPSS gate"]:::block
        secrets & sast & sca & lint --> build
    end
    build -- "prod only" --> push["Push app-SHA / nginx-SHA to Docker Hub"]
    push --> deploy["Deploy (prod-deploy runner, environment: prod)<br/>docker compose pull + up"]
    deploy --> dast["DAST (ci-cd runner)<br/>ZAP full scan of appsec.demon.lab"]:::report

    classDef block fill:#fde2e2,stroke:#c0392b,color:#000
    classDef report fill:#e2ecfd,stroke:#2c5aa0,color:#000
```

Red jobs **fail the pipeline**. Blue jobs are **report-only**, because the app is vulnerable on purpose; their results land in the Security tab (SAST) and in a downloadable artifact (DAST).

| Control | Tool | Blocks? |
|---|---|---|
| Secret scanning | gitleaks (full git history) | Yes |
| SAST | Semgrep (`p/python`, `p/flask`), Bandit → Security tab | No (report) |
| SCA / dependency check | pip-audit against `requirements.txt` (hash-pinned) | Yes |
| Dockerfile lint | hadolint (warning and above) | Yes |
| Container scanning | Trivy, all severities, with VEX applied | via the gate below |
| Vulnerability prioritisation | `scripts/vuln_gate.py`: CISA KEV + FIRST EPSS risk policy ([details](#vulnerability-triage-and-vex)) | Yes, risk-based |
| Risk acceptance | `security/risk-acceptances.json`, expiring, code-owner reviewed; required for HIGH/CRITICAL with no fix | Yes, until accepted |
| VEX | VEX Hub + `security/vex/appsec-demon.openvex.json` | n/a (suppresses with justification) |
| SBOM | Trivy CycloneDX, uploaded as `sbom` artifact | n/a |
| DAST | OWASP ZAP full scan, uploaded as `dast-report` artifact | No (report) |
| Version pinning | Base images and tool images by digest, Actions by commit SHA, Python deps by hash; Dependabot keeps pip, Dockerfiles and Actions current | n/a |

## Requirements
- A will to learn :)
- 4GB of Memory
- 4 CPU cores
- 80GB of storage
- Internet connection
- Git
- Oracle VirtualBox
- Vagrant, plus the `vagrant-env` plugin (`vagrant plugin install vagrant-env`)
- GitHub account
- Docker Hub account

## Setup

### 1. Fork and clone

Fork the repository. **Untick "Copy the `dev` branch only"**, because the pipeline deploys from the `prod` branch. Then clone your fork:

```bash
git clone https://github.com/<YOUR_GITHUB_USERNAME>/appsec-demon.git
cd appsec-demon
```

### 2. Lock down Actions on your fork

The self-hosted runners execute jobs directly on your VMs. On a public repository, anyone can open a pull request that edits the workflow, so require approval before outside code runs:

**Settings → Actions → General → Approval for running fork pull request workflows from contributors → "Require approval for all external contributors"**

> 📸 _Screenshot to add: `images/ACTIONS_GENERAL.png` (this setting selected)_

### 3. Add Docker Hub credentials

Create a Docker Hub repository and an access token (`https://app.docker.com/settings/personal-access-tokens`, Read & Write). Then go to **Settings → Secrets and variables → Actions**:

- **Secrets** tab → `DOCKER_HUB_ACCESS_TOKEN`: the access token
- **Variables** tab → `DOCKER_HUB_USERNAME`: your Docker Hub username
- **Variables** tab → `DOCKER_HUB_REPOSITORY`: the repository name

> 📸 _Screenshot to add: `images/SECRETS.png` (Actions secrets and variables page)_

### 4. Create the `prod` environment

**Settings → Environments → New environment → `prod`**. Under *Deployment branches and tags*, choose **Selected branches** and add `prod`. Optionally add yourself as a **Required reviewer** so every deploy waits for your approval.

> 📸 _Screenshot to add: `images/ENVIRONMENT.png` (prod environment rules)_

### 5. (Recommended) Protect the `prod` branch

**Settings → Rules → Rulesets → New branch ruleset**, target `dev` and `prod`, enable:

- **Require a pull request before merging**, with **Require review from Code Owners** (so [risk acceptances](#accepting-a-risk-that-has-no-fix) and changes to the gate get reviewed)
- **Require status checks to pass**: select `Secret scan (gitleaks)`, `SAST (semgrep, bandit)`, `Dependency scan (pip-audit)`, `Lint and policy tests` and `Build, test, scan images` after their first run

### 6. Configure and start the VMs

Copy `env.sample` to `.env` and fill it in:

```bash
cd virtual_machines
cp env.sample .env
```

- **GITHUB_REPOSITORY**: your fork as `owner/appsec-demon`
- **GITHUB_TOKEN**: a [fine-grained personal access token](https://github.com/settings/personal-access-tokens/new) scoped to *only* your fork, with **Repository permissions → Administration: Read and write**. It is only used to get runner registration tokens; revoke it once both runners show up.
- **CI_CD_SERVER_IP** / **PROD_SERVER_IP**: two free addresses in your subnet
- **NIC**: host network interface with internet access

```bash
vagrant up
```

> [!NOTE]
> If you already have VirtualBox VMs named `ci_cd_server` or `prod_server`, rename them in `virtual_machines/Vagrantfile` first.

### 7. Check the runners

**Settings → Actions → Runners** should list `ci-cd-server` (label `ci-cd`) and `prod-server` (label `prod-deploy`) as **Idle**.

> 📸 _Screenshot to add: `images/RUNNERS.png` (both runners Idle)_

### 8. Trigger a deployment

Open a pull request from `dev` to `prod`. The scan jobs run on the PR. Merge it to run the full pipeline including build, deploy and DAST:

```bash
gh pr create --base prod --head dev --title "Deploy" --body "Trigger pipeline"
gh pr merge --merge
```

Or run it by hand: **Actions → pipeline → Run workflow → Branch: prod**.

### 9. Watch the pipeline

**Actions → pipeline** shows each job. If you set a required reviewer on `prod`, approve the deployment when prompted.

> 📸 _Screenshot to add: `images/PIPELINE.png` (a successful prod run, all jobs)_

Code findings appear under **Security → Code scanning**. The ZAP report and SBOMs are under **Artifacts** at the bottom of the run summary.

> 📸 _Screenshot to add: `images/CODE_SCANNING.png` (Semgrep/Bandit alerts)_

### 10. Open the application

Browse to the prod server's IP (see `virtual_machines/.env`):

![APPLICATION](images/APPLICATION.png)

## Vulnerability triage and VEX

Severity alone is a poor signal: a typical base image has hundreds of "HIGH" CVEs, almost none of which are exploited. The image gate (`scripts/vuln_gate.py`) enriches every Trivy finding with the [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog and [FIRST EPSS](https://www.first.org/epss/) scores, then applies this policy (first match wins):

| # | Condition | Action |
|---|---|---|
| 1 | In CISA KEV, any severity, fixed or not | **Block** |
| 2 | KEV or EPSS unreachable, fixable HIGH/CRITICAL | **Block** (fail safe to severity-only) |
| 3 | Fixable CRITICAL | **Block** |
| 4 | Fixable HIGH, EPSS ≥ `EPSS_THRESHOLD` (default 10%) | **Block** |
| 5 | Fixable HIGH, no EPSS score yet | **Block** |
| 6 | Fixable HIGH, EPSS below threshold | Warn |
| 7 | HIGH/CRITICAL, no fix available, covered by an unexpired [risk acceptance](#accepting-a-risk-that-has-no-fix) | Warn |
| 8 | HIGH/CRITICAL, no fix available, no acceptance or acceptance expired | **Block** |
| 9 | Anything else | Info |

The result is written to the job summary, with blocking findings as error annotations, and to the `vuln-reports` artifact (raw Trivy JSON plus `vuln-gate.json`). Against the original, unhardened app image, severity-only gating blocked **717** findings; this policy blocks **58** (13 distinct CVEs). It also catches a LOW-severity `openssh-client` CVE that is in KEV, which severity-only gating let through.

Run the tests with `python3 -m unittest discover -s scripts -v`.

### Recording a "not affected" decision

When a finding is reviewed and does not apply, record it as an [OpenVEX](https://openvex.dev) statement in `security/vex/appsec-demon.openvex.json` instead of ignoring it. Trivy applies it (along with upstream statements from [VEX Hub](https://github.com/aquasecurity/vexhub)), and the job summary still lists it under *Suppressed by VEX*. For example:

```json
{
  "vulnerability": { "name": "CVE-2024-34069" },
  "products": [{ "@id": "pkg:pypi/werkzeug@2.3.7" }],
  "status": "not_affected",
  "justification": "vulnerable_code_not_in_execute_path",
  "impact_statement": "The Werkzeug debugger is never enabled; the app runs under gunicorn.",
  "timestamp": "2026-11-26T00:00:00Z"
}
```

- Use the package URL (`purl`) **with the exact version**, so the statement stops applying as soon as the package changes.
- `justification` must be one of the [OpenVEX values](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-justifications), and `impact_statement` must explain why, in terms a reviewer can check.
- Bump the document's `version` and `timestamp`, and land it through a PR so the decision is reviewed and stays in history.

### Accepting a risk that has no fix

A HIGH or CRITICAL finding with no fixed version blocks the pipeline until someone reviews it. If the package is *not affected*, record that in VEX (above). If it is affected but the risk is acceptable until a fix ships, add an entry to `security/risk-acceptances.json`:

```json
{
  "id": "CVE-2026-119373",
  "packages": ["libsqlite3-0"],
  "reason": "SQLite FTS5 heap overflow. The app uses no database and sqlite3 is not loaded under gunicorn (checked). No Debian fix yet.",
  "expires": "2027-02-25"
}
```

- `expires` can be **at most 90 days** out; after that the finding blocks again until it is re-reviewed. The gate warns 14 days before expiry and flags acceptances that no longer match anything.
- An acceptance never overrides a KEV entry or a finding that has a fix: once Debian ships a fix, the normal rules apply and you just rebuild.
- `.github/CODEOWNERS` covers `security/`, `scripts/` and `.github/`, so with **Require review from Code Owners** on, every acceptance needs an approving review. That PR review is the approval record.

> [!NOTE]
> GitHub does not let you approve your own PR. On a single-maintainer fork, either add a second collaborator as a code owner or add yourself to the ruleset's bypass list and treat the merge as the approval.

## Updating pinned versions

Dependabot opens weekly PRs for Python packages, Dockerfile base images and GitHub Actions. The scanner images in `.github/workflows/pipeline.yml` (`env:` block) and the runner version in the `Vagrantfile` are pinned by hand; update the tag **and** digest/checksum together.

To change Python dependencies, edit `myprj/requirements.in` and regenerate the lockfile:

```bash
cd myprj
uv pip compile requirements.in --python-version 3.13 --generate-hashes --upgrade -o requirements.txt
```
