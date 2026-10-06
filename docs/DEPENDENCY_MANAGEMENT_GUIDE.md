# Dependency Management

This page describes how the Python services pin their dependencies today. It
replaces an earlier pip-tools implementation plan; the plan was carried out
with `uv` instead of `pip-compile`, and the Makefile targets and CI jobs it
proposed exist under different names, listed below.

## Layout

Each Python service (`agents`, `cspm`, `data`, `guardian`, `identity`,
`responder`, `sensor`, `tools`, under `open-security-<service>/`) has two
files:

- `requirements.in`: the direct dependencies, edited by hand, with version
  ranges.
- `requirements.txt`: the lock, generated from `requirements.in`. It pins every
  package, including transitive ones, to an exact version with SHA-256 hashes.
  Do not edit it by hand.

Every service Dockerfile installs the lock with
`pip install --no-cache-dir --require-hashes --no-build-isolation -r requirements.txt`,
so a build fails if a downloaded file does not match its hash or if a package
is missing from the lock. The installer is the pip of the digest-pinned base
image: no Dockerfile upgrades pip, setuptools or wheel, because that would
install whatever PyPI serves at build time, without a hash, and then run it.
`--no-build-isolation` keeps pip from downloading build dependencies for a
package that the lock holds only as a source distribution; it is built with
the base image's setuptools. A package whose build needs anything else fails
the build, and needs a wheel or a different pin.

Local paths are installed with `pip install --no-index --no-build-isolation
<path>`: with `--no-index` pip cannot reach PyPI, neither for a dependency nor
for the build backend.

## The Shared Package

`open-security-shared` has no dependency of its own. Its
`pyproject.toml` defines one extra per group of modules (`fastapi`, `auth`,
`metrics`, `events`) and a table, `[tool.wildbox.module-extras]`,
that says which module needs which. A service's Dockerfile installs the
package after the lock, with the extras of the modules the service imports and
without `--no-deps`:

```dockerfile
RUN pip install --no-cache-dir --no-index --no-build-isolation \
        "/tmp/open-security-shared[fastapi,metrics]" \
    && pip check
```

pip resolves the requirements of those extras, and offline it can only find
them in what `requirements.txt` installed. The build fails when the lock
lacks one of them or pins it below the floor the shared package declares, and
`pip check` fails it for any other requirement the environment does not meet.
The six FastAPI services install `fastapi` and `metrics`; Guardian and the
sensor install the package without an extra.

When a service starts importing a shared module that needs another extra, add
the extra to that line, add the packages it requires to the service's
`requirements.in`, and run `make lock`. When a floor in `pyproject.toml`
rises, raise the range in the `requirements.in` of every service that uses the
extra and compile with `--upgrade`.

`scripts/check_container_hygiene.py`, run by the Code Quality job, fails on a
`pip install` in a Dockerfile that has neither form. It also fails on a base
image without a digest and on a download that nothing verifies; a `curl` or
`wget` in a `RUN` needs a `sha256sum -c` in the same instruction.

The same check reads how an image installs OS packages and binaries:

- `apt-get install` needs `--no-install-recommends`, and the `RUN` that runs
  `apt-get update` ends with `rm -rf /var/lib/apt/lists/*`; `apk add` needs
  `--no-cache`. Name every package the image needs: a recommended one is no
  longer installed with it. `gcc` is the case to remember, since the C library
  headers (`libc6-dev`) are only a recommendation of it.
- A downloaded binary is chosen by the platform the image is built for. A URL
  that names one architecture (`Linux-64bit`, `amd64`, `arm64`) must be in a
  `RUN` that reads `TARGETARCH` or `dpkg --print-architecture`, with a checksum
  for each architecture and a failure for any other. The tools image does this
  for Trivy and the sensor image for osquery.

The dashboard uses `package-lock.json` and `npm ci`. To move a transitive
package, run `npm update <package>` in `open-security-dashboard`: it rewrites
the lock within the ranges the parents declare. An entry under `overrides` in
`package.json` is for the case where no release of the parent accepts the
version that is needed, and it stays until one does:

- `seroval` and `seroval-plugins` at `^1.6.3`. solid-js 1.9.15, which
  `@tanstack/react-query-devtools` brings in, declares `~1.5.4` for both, and
  the two advisories of October 2026 (GHSA-p6vx-979v-rg4c, GHSA-jp82-f5mq-hwhp)
  are fixed from 1.6.2 and 1.6.3 only. The two packages are released together,
  so they are overridden together. Remove both entries when
  `npm view solid-js dependencies` shows a range that admits `seroval` 1.6.3
  or later, or when the devtools no longer depend on solid-js 1.x, then run
  `npm install` and check `npm ls seroval`.

## Compiling the Locks

`make lock` runs `scripts/compile_requirements.sh`, which compiles every
service with `uv pip compile --generate-hashes`, for Python 3.11 on Linux (the
platform the images run on, whatever machine you compile from). `uv` must be
installed.

```bash
make lock                                       # every service
./scripts/compile_requirements.sh data tools    # selected services
./scripts/compile_requirements.sh --upgrade     # ignore the current pins
./scripts/compile_requirements.sh --check       # fail if a lock is stale
```

Without `--upgrade`, `uv` keeps an existing pin when it still satisfies
`requirements.in`, so a one-line change does not move the whole tree. After
widening a range on purpose, compile with `--upgrade`, or the old pin stays.

Commit `requirements.in` and `requirements.txt` together.

## The CI Tools

`tests/ci-tools/requirements.in` names the tools the workflows install: the
test runner (pytest, pytest-asyncio, pytest-cov), the clients the integration
suites use (httpx, requests, python-dotenv, psycopg2-binary, pyyaml,
packaging) and the linters (black, flake8, isort, mypy), each at an exact
version. `requirements.txt` next to it is the hash-pinned lock:

```bash
./scripts/compile_requirements.sh ci-tools
```

A job that starts from a clean interpreter installs the lock with
`pip install --require-hashes -r tests/ci-tools/requirements.txt`. Unit Tests
and Python Code Quality install a tool on top of a service's own lock, which
this lock would move, so they name the tool with the version the file gives it
(`pip install pytest==...`). To move a tool, change the version in
`requirements.in`, compile, and change the same version in those two workflows:
`scripts/check_workflow_pins.py` fails while they differ.

## Security Upgrades

`make lock-security` runs `scripts/upgrade_vulnerable_requirements.sh`. It
audits each lock, the CI tools lock included, with `pip-audit` (OSV database) and moves only the packages
with a known advisory to the newest version `requirements.in` allows, using the
same `uv` invocation as `compile_requirements.sh`. An advisory whose fix lies
outside the allowed range is listed in the summary, not forced: widening a
constraint is a decision for a person.

The **Pip Security Upgrades** workflow
(`.github/workflows/pip-security-upgrades.yml`) runs the same script every
Monday and opens or refreshes one pull request on the
`deps/pip-security-upgrades` branch.

## Dependabot

Dependabot handles GitHub Actions, npm, the base images of the Dockerfiles
(`docker`) and the images the Compose files run without building them
(`docker-compose`): PostgreSQL, Redis, n8n, Prometheus, Alertmanager, nginx,
curl and alpine. Those are pinned by tag and by the digest of the image index,
and Dependabot proposes the new digest when a tag is published again, and
newer minor and patch tags. A new major is ignored there and decided by hand,
as is a minor of Prometheus, which stays on its long-term support line.

It does **not** handle pip: `.github/dependabot.yml` has no `pip` entry, because Dependabot
regenerates the lock with `pip-compile` rather than the `uv` command above, and
its pull requests could never pass the Dependency Integrity check (#420).

## CI Checks

- **Dependency Integrity** (`.github/workflows/pr-validation.yml`) runs
  `./scripts/compile_requirements.sh --check` on every pull request, so a
  `requirements.in` change without a recompiled lock fails. The same job runs
  `scripts/check_shared_dependencies.py`: it fails when a Dockerfile installs
  the shared package with other extras than the modules its service imports
  need, with `--no-deps` or without `pip check`, when a lock does not pin a
  requirement of those extras at a version the package accepts, and when a
  shared module imports something its extras do not require.
- **Docker Build Validation**
  (`.github/workflows/docker-build-validation.yml`) builds every image on a
  pull request that touches one. The build runs the offline install and
  `pip check` described above, so it fails when an image's environment does
  not satisfy what is installed in it.
- **Code Quality** (`.github/workflows/test.yml`) runs
  `scripts/check_workflow_pins.py`: it fails on a workflow that installs a pip
  or global npm package without an exact version, at a version other than the
  CI tools lock's, on a download that is unverified or piped to a shell, and
  on an action that is not at a version tag or a commit.
- **Validate Docker Compose** (`.github/workflows/pr-validation.yml`) runs
  `scripts/check_compose_files.py`: every tracked Compose file renders, alone
  or with the files it overlays, and each build context, Dockerfile stage and
  bind-mount source it names exists.
- **Security Scanning** (`.github/workflows/test.yml`) fails a pull request
  that introduces a critical advisory with a released fix
  (`scripts/critical_advisories.sh new`). Advisories already on `main` are
  tracked by `.github/workflows/main-advisories.yml`.

## Updating One Dependency

```bash
# 1. Change the range in requirements.in
$EDITOR open-security-identity/requirements.in

# 2. Recompile that service, with --upgrade if you widened the range
./scripts/compile_requirements.sh --upgrade identity

# 3. Rebuild and test
docker compose build identity
docker compose up -d identity
```

## References

- [uv pip compile](https://docs.astral.sh/uv/pip/compile/)
- [pip-audit](https://pypi.org/project/pip-audit/)
- [SLSA Framework](https://slsa.dev/)
