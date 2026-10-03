#!/usr/bin/env python3
"""Run proselint over Markdown prose and report findings as annotations.

The proselint CLI reads Markdown as plain text, so shell commands and
code samples (``python -m venv venv``, ``make\\nmake``) trip prose rules
such as lexical_illusions. This wrapper blanks out fenced code blocks,
inline code spans and HTML comments before linting, and marks blank
lines so that no match runs from one Markdown block into the next. Line
and column numbers still point at the original file.

It also differs from the CLI in two ways the CI job relies on:
  * findings carry the path relative to the repository root, printed as
    GitHub Actions annotations when GITHUB_ACTIONS is set;
  * a file that proselint cannot lint is an error, not a silent skip.

Usage: check_prose.py [--config .proselintrc.json] FILE...
Exit status: 0 when no findings, 1 otherwise.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

from proselint.checks import __register__
from proselint.config import load_from
from proselint.registry import CheckRegistry
from proselint.tools import LintFile

# A character that is neither a word character nor whitespace, so masked
# text can never join the words around it into a new match.
MASK = "·"

FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})")
INLINE_CODE = re.compile(r"(`+)(?!`).+?(?<!`)\1(?!`)", re.DOTALL)
HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
BLANK_LINE = re.compile(r"^[ \t]*$", re.MULTILINE)


def _blank(text: str) -> str:
    """Replace every character but newlines with the mask character."""
    return "".join(ch if ch == "\n" else MASK for ch in text)


def mask_code(markdown: str) -> str:
    """Blank code and comments out of Markdown, preserving positions."""
    lines = markdown.splitlines(keepends=True)
    fence: str | None = None
    for i, line in enumerate(lines):
        if fence is not None:
            stripped = line.strip()
            if stripped.startswith(fence) and set(stripped) == {fence[0]}:
                fence = None
            lines[i] = _blank(line)
            continue
        match = FENCE_OPEN.match(line)
        if match:
            fence = match.group(1)
            lines[i] = _blank(line)
    text = "".join(lines)
    for pattern in (HTML_COMMENT, INLINE_CODE):
        text = pattern.sub(lambda m: _blank(m.group(0)), text)
    # A blank line ends a Markdown block, so no phrase runs across it: a
    # heading such as "## Passwords" followed by "Passwords are hashed"
    # is not a repeated word. Marking blank lines keeps checks that match
    # across whitespace (lexical_illusions) inside one block, and adds no
    # line, so line and column numbers are unchanged.
    return BLANK_LINE.sub(MASK, text)


def _escape(value: str) -> str:
    """Escape a value for a GitHub Actions workflow command."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, default=Path(".proselintrc.json"))
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args()

    config = load_from(args.config)
    CheckRegistry().register_many(__register__)
    annotate = os.environ.get("GITHUB_ACTIONS") == "true"

    findings = 0
    for path in args.files:
        try:
            content = mask_code(path.read_text(encoding="utf-8"))
            results = LintFile(str(path), content).lint(config) if content else []
        except Exception as err:  # noqa: BLE001 - report and fail, never skip
            findings += 1
            message = f"proselint could not lint this file: {err}"
            if annotate:
                print(f"::error file={path}::{_escape(message)}")
            else:
                print(f"{path}: {message}")
            continue
        for result in results:
            findings += 1
            line, col = result.pos
            check = result.check_result.check_path
            message = result.check_result.message
            if annotate:
                print(
                    f"::error file={path},line={line},col={col},"
                    f"title=proselint {check}::{_escape(message)}"
                )
            else:
                print(f"{path}:{line}:{col}: {check}: {message}")

    print(f"proselint: {findings} finding(s) in {len(args.files)} file(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
