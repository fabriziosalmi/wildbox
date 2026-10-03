# GitHub Actions workflows

Every workflow that runs in this repository is a `.yml` file in this
directory. GitHub does not run workflow files in subdirectories, so nothing
in [`archived/`](#archived) runs (see below).

"Required" means the job's check name is a required status check of `main`'s
branch protection, so a pull request cannot merge until it passes. Only a
check that runs on **every** pull request can be required: a required check
that a path filter skips never reports, and the pull request waits for it
forever.

## Pull requests and `main`

| Workflow | Triggers | Jobs (check names) | What it gates | Required |
| --- | --- | --- | --- | --- |
| [`pr-validation.yml`](pr-validation.yml) | PR to `main`/`develop` | Validate Docker Compose; Validate Project Structure; Dependency Integrity; Python Code Quality (one per service); **PR Validation Summary** | Compose renders with generated secrets; critical files exist; every `requirements.txt` matches its `requirements.in` (`scripts/compile_requirements.sh --check`); flake8 correctness and complexity per service. The summary fails if any of the others did. | PR Validation Summary |
| [`test.yml`](test.yml) | PR and push to `main`/`develop`, dispatch | **Unit Tests (3.11, _service_)** x8; Shared Package Unit Tests; **E2E Tests (Playwright)** (frontend-only smoke); Dashboard Lint / Format / Types; **Security Scanning**; Code Quality; Build Docker Images (push to `main` only) | Unit tests per service and for `open-security-shared` and `scripts/`; the dashboard's build, smoke specs, ESLint, Prettier and `tsc`; Trivy and Bandit (below); flake8/black/isort tiers. On `main`, builds each image, writes its SBOM, checks dependency licenses and pushes to GHCR. | Unit Tests for identity, tools, data, guardian, responder, agents, cspm; E2E Tests (Playwright); Security Scanning |
| [`integration-tests.yml`](integration-tests.yml) | PR to `main`/`develop`, push to `main`, dispatch | **Run Integration Tests**; **Security Validation** | `tests/integration/` against the whole compose stack, through the gateway over HTTPS; `security_validation_v2.sh`, no hardcoded compose passwords, digest-pinned base images. | Both |
| [`e2e-fullstack.yml`](e2e-fullstack.yml) | PR to `main`/`develop`, push to `main`, dispatch | E2E Full-Stack (login flows) | The backend-dependent Playwright specs against identity and the gateway. | No |
| [`gateway-tests.yml`](gateway-tests.yml) | PR to `main`/`develop`, push to `main`, dispatch | Gateway Auth Tests | The gateway's authentication behavior against a mock identity service, including a gateway with the wrong proof-of-origin secret. | No |
| [`secret-scan.yml`](secret-scan.yml) | PR to `main`/`develop`, push to `main`, dispatch | Gitleaks | No new secret in the working tree (`.gitleaks.toml`). | No |
| [`docker-build-validation.yml`](docker-build-validation.yml) | PR touching a Dockerfile, `requirements.txt`, service code, the shared package or a compose file | Build _service_ image x9 | Every service image still builds (never pushed). | No (path-filtered) |
| [`production-stack.yml`](production-stack.yml) | PR touching the compose files, the gateway's nginx config or the scripts it runs; dispatch | Production stack and network segmentation | `docker-compose.yml` + `docker-compose.prod.yml` start; network segmentation and Redis settings hold, rendered and at runtime; the integration suite passes against it. | No (path-filtered) |
| [`gateway-lint.yml`](gateway-lint.yml) | PR and push to `main` touching the gateway's Lua or `.luacheckrc`; dispatch | Luacheck (OpenResty Lua) | luacheck over `open-security-gateway/nginx/lua`. | No (path-filtered) |
| [`documentation-quality.yml`](documentation-quality.yml) | PR and push to `main` touching Markdown or `docs/` | Markdown Linting; Spell Check; Link Validation; Image Alt Text Validation; Documentation Security Scan; Prose Quality; and two advisory jobs | markdownlint, cspell, links in `README.md`, image alt text, three secret patterns in Markdown (gitleaks allowlists `docs/` and README files), and proselint 0.16.0 over the tracked Markdown with code masked (`scripts/check_prose.py`, rules in `.proselintrc.json`). Inclusive Language and Documentation Coverage report only. | No (path-filtered) |

Code scanning adds three more checks to a pull request: **Trivy** and
**Bandit**, created from the SARIF files that Security Scanning uploads, and
**CodeQL** from the repository's default CodeQL set-up (it has no workflow
file here). Trivy is required.

### Security scanning

Trivy and Bandit run once per pull request, in Security Scanning (`test.yml`):

- Trivy reports every finding to code scanning, category `trivy-fs`.
- On a pull request it then fails on a critical advisory with a released fix
  that the pull request introduces (`scripts/critical_advisories.sh new`).
  Advisories already on `main` are tracked by `main-advisories.yml` instead.
- Bandit reports findings of medium severity and confidence and up to code
  scanning, category `bandit`. It does not gate.

## Scheduled and manual

| Workflow | Triggers | What it does |
| --- | --- | --- |
| [`main-advisories.yml`](main-advisories.yml) | Daily 06:00 UTC, push to `main`, dispatch | Scans `main` for critical advisories with a fix and keeps one issue, "Critical advisories on main", in step: opened, updated, closed when empty. |
| [`pip-security-upgrades.yml`](pip-security-upgrades.yml) | Mondays 05:00 UTC, dispatch | Moves only the pip packages with a known advisory, re-locks with uv and opens or refreshes one pull request. Replaces Dependabot for pip (`.github/dependabot.yml`). |
| [`chaos-and-load.yml`](chaos-and-load.yml) | Daily 03:00 UTC, dispatch (`all`, `chaos` or `load`) | Fault injection against the running stack (`tests/chaos/`) and a search-latency baseline (`tests/perf/`). |

## Conventions

- **Timeouts.** Every job has `timeout-minutes`, about three times the
  longest successful run observed, with a floor of 10 minutes; dependency
  installs, browser installs and stack start-up also have step limits. The
  comment next to each limit gives the observation it is based on.
- **Concurrency.** A new push to a pull request cancels that pull request's
  run in progress. Runs on `main`, scheduled runs and dispatches are never
  cancelled.
- **Caches.** `setup-python` caches pip keyed on the `requirements.txt` the
  job installs, `setup-node` caches npm keyed on the dashboard's
  `package-lock.json`, and `setup-uv` caches by default. Integration Tests
  and the production stack build their images through the Actions cache
  (`.github/compose.ci-cache.yml`), in the scopes `docker-build-validation`
  also uses.
- **Permissions.** Each workflow starts from `contents: read`; a job that
  needs more asks for it.
- **Lint.** `actionlint` passes on every file here; `.github/actionlint.yaml`
  holds its one, explained, exception.

## Archived

`archived/` holds 36 data-ingestion workflows (`ingest-*.yml`), moved there
in November 2025. They are dead:

- GitHub runs only workflow files at the top level of this directory, so none
  of them can be triggered.
- `archived/README.md` points to a consolidated `ingest-threat-feeds.yml`,
  but that file was itself only ever committed under `archived/`.
- 35 of them write to a `datalake/` directory that does not exist in the
  repository, and nothing outside `archived/` refers to them.

They are kept for reference only. Nothing depends on them, so they can be
deleted whenever that reference is no longer wanted.
