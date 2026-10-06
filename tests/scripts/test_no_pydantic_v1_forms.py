"""No pydantic v1 form is left in the services (#727, #665).

Every service runs pydantic 2. Four v1 forms were still written in them:

* ``Field(env="REDIS_URL")`` on a settings field, 48 times in the responder
  and cspm. pydantic-settings v2 **ignores** it and reads the field from the
  variable of the field's own name: it worked while the two matched, and
  would have stopped, silently, for a field renamed without its variable.
  agents had the same, fixed in #727;
* a nested ``class Config``, in 21 models and four settings classes;
* ``@validator``, 13 times;
* ``Field(example=...)``, 30 times in the tools' schemas.

The last three still work in pydantic 2 and are announced to go in 3. They
are rewritten as ``model_config``, ``@field_validator`` and
``json_schema_extra``, with the JSON schema of every model unchanged. This
reads the source, so it needs none of the services installed.
"""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SKIPPED = {"node_modules", "venv", ".venv", "build", "__pycache__", "migrations"}
V1_DECORATORS = {"validator", "root_validator"}
V1_FIELD_ARGUMENTS = {"env", "example"}
V1_CONFIG_KEYS = {
    "schema_extra",
    "orm_mode",
    "allow_population_by_field_name",
    "allow_mutation",
    "anystr_strip_whitespace",
    "validate_all",
}


def service_directories():
    return sorted(
        path
        for path in ROOT.glob("open-security-*")
        if (path / "requirements.txt").exists() or path.name == "open-security-shared"
    )


def python_sources(directory):
    for path in sorted(directory.rglob("*.py")):
        if not SKIPPED & set(path.relative_to(directory).parts[:-1]):
            yield path


def _name(node):
    return getattr(node, "id", getattr(node, "attr", ""))


def v1_forms(tree):
    """[(line, what)] for each pydantic v1 form in one parsed module."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for inner in node.body:
                if isinstance(inner, ast.ClassDef) and inner.name == "Config":
                    found.append((inner.lineno, f"class Config in {node.name}"))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                name = _name(getattr(decorator, "func", decorator))
                if name in V1_DECORATORS:
                    found.append((decorator.lineno, f"@{name} on {node.name}"))
        if isinstance(node, ast.Call) and _name(node.func) == "Field":
            for keyword in node.keywords:
                if keyword.arg in V1_FIELD_ARGUMENTS:
                    found.append((node.lineno, f"Field({keyword.arg}=...)"))
        if isinstance(node, ast.Call) and _name(node.func) in (
            "ConfigDict",
            "SettingsConfigDict",
        ):
            for keyword in node.keywords:
                if keyword.arg in V1_CONFIG_KEYS:
                    found.append((node.lineno, f"{keyword.arg} in model_config"))
        if isinstance(node, ast.Assign) and _name(node.targets[0]) == "model_config":
            if isinstance(node.value, ast.Dict):
                for key in node.value.keys:
                    if getattr(key, "value", None) in V1_CONFIG_KEYS:
                        found.append((node.lineno, f"{key.value} in model_config"))
    return sorted(found)


# --- the check works -----------------------------------------------------------


def test_the_services_are_found():
    names = {path.name for path in service_directories()}

    assert {
        "open-security-identity",
        "open-security-tools",
        "open-security-data",
        "open-security-guardian",
        "open-security-responder",
        "open-security-agents",
        "open-security-cspm",
        "open-security-sensor",
        "open-security-shared",
    } <= names
    assert any(
        path.name == "config.py"
        for path in python_sources(ROOT / "open-security-responder")
    )


@pytest.mark.parametrize(
    "source, what",
    [
        (
            'class S(BaseSettings):\n    redis_url: str = Field(default="x", env="REDIS_URL")\n',
            "Field(env=...)",
        ),
        (
            'class M(BaseModel):\n    url: str = Field(..., example="https://example.com")\n',
            "Field(example=...)",
        ),
        (
            "class M(BaseModel):\n    class Config:\n        from_attributes = True\n",
            "class Config in M",
        ),
        (
            "class M(BaseModel):\n    @validator('x')\n    def check(cls, v):\n        return v\n",
            "@validator on check",
        ),
        (
            "class M(BaseModel):\n    @root_validator(pre=True)\n    def check(cls, v):\n        return v\n",
            "@root_validator on check",
        ),
        (
            "class M(BaseModel):\n    model_config = ConfigDict(schema_extra={'example': 1})\n",
            "schema_extra in model_config",
        ),
        (
            "class M(BaseModel):\n    model_config = {'orm_mode': True}\n",
            "orm_mode in model_config",
        ),
    ],
)
def test_a_v1_form_is_found(source, what):
    assert [found for _, found in v1_forms(ast.parse(source))] == [what]


def test_the_v2_forms_are_not_taken_for_v1():
    source = (
        "class S(BaseSettings):\n"
        "    model_config = SettingsConfigDict(env_file='.env', env_prefix='APP_')\n"
        "    redis_url: str = Field(default='x', alias='REDIS', description='d')\n"
        "    url: str = Field(..., json_schema_extra={'example': 'https://e.com'})\n"
        "    tags: list = Field(default=[], examples=[['a']])\n"
        "    @field_validator('redis_url')\n"
        "    @classmethod\n"
        "    def check(cls, v):\n"
        "        return v\n"
        "    @model_validator(mode='after')\n"
        "    def whole(self):\n"
        "        return self\n"
        "class M(BaseModel):\n"
        "    model_config = ConfigDict(from_attributes=True, json_schema_extra={})\n"
        "class Config:\n"  # a class of that name which is not nested in a model
        "    debug = False\n"
        "result = subprocess.run(['true'], env={'A': 'b'})\n"
    )

    assert v1_forms(ast.parse(source)) == []


# --- the tree -------------------------------------------------------------------


@pytest.mark.parametrize("directory", service_directories(), ids=lambda path: path.name)
def test_a_service_has_no_pydantic_v1_form(directory):
    found = []
    for path in python_sources(directory):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for line, what in v1_forms(tree):
            found.append(f"{path.relative_to(ROOT)}:{line}: {what}")

    assert found == []
