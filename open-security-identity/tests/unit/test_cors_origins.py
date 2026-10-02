"""identity reads CORS_ORIGINS as a JSON list or as a comma-separated string (#531).

cors_origins is a list[str], which pydantic-settings decodes from the
environment as JSON only. The comma-separated form that .env carries, and that
every other service parses, made identity exit at import ("error parsing value
for field cors_origins") and restart forever under the production overlay.
"""

import os
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SECRET_KEY", "a" * 32)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.config import Settings  # noqa: E402

DEFAULT = [
    "http://localhost:3000",
    "https://wildbox.local",
    "https://dashboard.wildbox.local",
]
A = "https://wildbox.example.com"
B = "https://dashboard.example.com"


def origins_from_env(monkeypatch, value):
    monkeypatch.setenv("CORS_ORIGINS", value)
    # _env_file=None: read the process environment only, not a stray .env.
    return Settings(_env_file=None).cors_origins


@pytest.mark.parametrize(
    "value",
    [
        f"{A},{B}",
        f"{A}, {B}",
        f" {A} ,\t{B} ",
        f"{A},{B},",
        f"{A},,{B}",
    ],
    ids=["comma", "comma-space", "padded", "trailing-comma", "empty-item"],
)
def test_comma_separated(monkeypatch, value):
    assert origins_from_env(monkeypatch, value) == [A, B]


def test_single_origin(monkeypatch):
    assert origins_from_env(monkeypatch, A) == [A]


@pytest.mark.parametrize(
    "value",
    [f'["{A}", "{B}"]', f'  ["{A}","{B}"]  '],
    ids=["json", "json-padded"],
)
def test_json_list(monkeypatch, value):
    assert origins_from_env(monkeypatch, value) == [A, B]


def test_empty_json_list(monkeypatch):
    assert origins_from_env(monkeypatch, "[]") == []


@pytest.mark.parametrize(
    "value", ["", "   ", ","], ids=["empty", "blank", "comma-only"]
)
def test_empty_value_allows_no_cross_origin(monkeypatch, value):
    # The production overlay passes CORS_ORIGINS=${CORS_ORIGINS}, which is an
    # empty string when the variable is unset. That must start, with no
    # cross-origin access, not crash and not fall back to localhost origins.
    assert origins_from_env(monkeypatch, value) == []


def test_unset_keeps_the_default(monkeypatch):
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    assert Settings(_env_file=None).cors_origins == DEFAULT


def test_invalid_json_is_a_validation_error(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", f'["{A}",')
    with pytest.raises(ValidationError, match="cors_origins"):
        Settings(_env_file=None)


def test_json_that_is_not_a_list_of_strings_is_rejected(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "[1, {}]")
    with pytest.raises(ValidationError, match="cors_origins"):
        Settings(_env_file=None)


def test_python_list_is_accepted_unchanged():
    assert Settings(_env_file=None, cors_origins=[A, B]).cors_origins == [A, B]


def test_the_production_env_example_value(monkeypatch):
    # The value .env.example ships and the production overlay passes through.
    root = Path(__file__).resolve().parents[3]
    line = next(
        ln
        for ln in (root / ".env.example").read_text().splitlines()
        if ln.startswith("CORS_ORIGINS=")
    )
    value = line.split("=", 1)[1]
    assert origins_from_env(monkeypatch, value) == [o.strip() for o in value.split(",")]


def test_the_app_applies_the_parsed_origins(monkeypatch):
    # End to end: the CORS middleware of the imported app gets the list.
    import importlib

    monkeypatch.setenv("CORS_ORIGINS", f"{A},{B}")
    import app.config as config

    importlib.reload(config)
    import app.main as main

    main = importlib.reload(main)
    cors = [m for m in main.app.user_middleware if m.cls.__name__ == "CORSMiddleware"]
    assert len(cors) == 1
    assert cors[0].kwargs["allow_origins"] == [A, B]
