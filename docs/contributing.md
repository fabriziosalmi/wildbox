---
# Front matter is required here: jekyll-optional-front-matter skips files
# named like CONTRIBUTING, so without it this page would be copied raw.
permalink: /contributing/
---

# Contributor Docs

Engineering notes for people working on Wildbox itself. They live in the
repository under `docs/` and are not published as pages of this site, so the
links below go to GitHub. Several are working notes from earlier phases of the
project; when one disagrees with the code, the code is right.

Start with
[CONTRIBUTING.md](https://github.com/fabriziosalmi/wildbox/blob/main/CONTRIBUTING.md).

## Engineering

- [Engineering standards](https://github.com/fabriziosalmi/wildbox/blob/main/docs/ENGINEERING_STANDARDS.md),
  referenced by `SECURITY.md` and the security validation script
- [Architecture decision records](https://github.com/fabriziosalmi/wildbox/blob/main/docs/ARCHITECTURE_DECISIONS.md)
- [Architecture stack evaluation](https://github.com/fabriziosalmi/wildbox/blob/main/docs/ARCHITECTURE_STACK_JUSTIFICATION.md)
- [Service lifecycle](https://github.com/fabriziosalmi/wildbox/blob/main/docs/SERVICE_LIFECYCLE.md)
- [Testing strategy](https://github.com/fabriziosalmi/wildbox/blob/main/docs/TESTING_STRATEGY.md)
- [Dependency management](https://github.com/fabriziosalmi/wildbox/blob/main/docs/DEPENDENCY_MANAGEMENT_GUIDE.md)
- [Pre-commit hooks](https://github.com/fabriziosalmi/wildbox/blob/main/docs/PRE_COMMIT_HOOKS.md)
- [Error handling](https://github.com/fabriziosalmi/wildbox/blob/main/docs/ERROR_HANDLING_REFACTORING.md)
- [Observability roadmap](https://github.com/fabriziosalmi/wildbox/blob/main/docs/OBSERVABILITY_ROADMAP.md)

## Security

- [Gateway authentication pattern](https://github.com/fabriziosalmi/wildbox/blob/main/docs/GATEWAY_AUTHENTICATION_GUIDE.md),
  referenced by `SECURITY.md`
- [Secrets rotation](https://github.com/fabriziosalmi/wildbox/blob/main/docs/SECURITY_SECRETS_ROTATION.md)
- [Git history security audit](https://github.com/fabriziosalmi/wildbox/blob/main/docs/GIT_SECURITY_AUDIT.md)

## Documentation

- [Documentation style guide](https://github.com/fabriziosalmi/wildbox/blob/main/docs/DOCUMENTATION_STYLE_GUIDE.md)

This site is the only documentation stack. GitHub Pages builds it from `docs/`
on `main` with Jekyll and the `github-pages` gem: Markdown pages are rendered
through `docs/_layouts/doc.html`, the sidebar and sitemap come from
`docs/_data/docs_nav.yml`, and `docs/_config.yml` decides what is published.
The Docusaurus site that used to live in `website/` has been removed from the
repository; a `website/` directory in a local checkout is a leftover and is
ignored by git.

To add a page, write it under `docs/guides/`, `docs/security/` or `docs/api/`
and add an entry to `docs/_data/docs_nav.yml`. CI runs markdownlint, cspell and
a link check on every Markdown file.
