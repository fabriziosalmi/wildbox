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

The shared package and other local paths are installed with
`pip install --no-index --no-deps --no-build-isolation <path>`: with
`--no-index` pip cannot reach PyPI, neither for a dependency nor for the build
backend.

`scripts/check_container_hygiene.py`, run by the Code Quality job, fails on a
`pip install` in a Dockerfile that has neither form. It also fails on a base
image without a digest and on a download that nothing verifies; a `curl` or
`wget` in a `RUN` needs a `sha256sum -c` in the same instruction.

The dashboard uses `package-lock.json` and `npm ci`.

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

## Security Upgrades

`make lock-security` runs `scripts/upgrade_vulnerable_requirements.sh`. It
audits each lock with `pip-audit` (OSV database) and moves only the packages
with a known advisory to the newest version `requirements.in` allows, using the
same `uv` invocation as `compile_requirements.sh`. An advisory whose fix lies
outside the allowed range is listed in the summary, not forced: widening a
constraint is a decision for a person.

The **Pip Security Upgrades** workflow
(`.github/workflows/pip-security-upgrades.yml`) runs the same script every
Monday and opens or refreshes one pull request on the
`deps/pip-security-upgrades` branch.

## Dependabot

Dependabot handles GitHub Actions, npm and Docker base images. It does **not**
handle pip: `.github/dependabot.yml` has no `pip` entry, because Dependabot
regenerates the lock with `pip-compile` rather than the `uv` command above, and
its pull requests could never pass the Dependency Integrity check (#420).

## CI Checks

- **Dependency Integrity** (`.github/workflows/pr-validation.yml`) runs
  `./scripts/compile_requirements.sh --check` on every pull request, so a
  `requirements.in` change without a recompiled lock fails.
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
