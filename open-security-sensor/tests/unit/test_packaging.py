"""setup.py declares no command it does not package (#665).

It declared ``security-sensor`` and ``ossensor`` as ``main:main``. main.py is
a file beside the package, not part of it (``find_packages()`` finds
``sensor`` only), so after ``pip install .`` both commands failed with
``ModuleNotFoundError: No module named 'main'``. They answered only in the
image, where an editable install puts /app on the path, and nothing there
ran them: the image starts ``python main.py``.

A console script, if one is ever added, has to name a module the
distribution installs.
"""

import ast
from pathlib import Path

SENSOR_ROOT = Path(__file__).resolve().parents[2]


def setup_keywords():
    tree = ast.parse((SENSOR_ROOT / "setup.py").read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "setup"
    ]
    assert len(calls) == 1
    return {keyword.arg: keyword.value for keyword in calls[0].keywords}


def console_scripts(keywords):
    entry_points = keywords.get("entry_points")
    if entry_points is None:
        return []
    return ast.literal_eval(entry_points).get("console_scripts", [])


def test_every_console_script_names_a_module_that_is_installed():
    keywords = setup_keywords()
    py_modules = (
        ast.literal_eval(keywords["py_modules"]) if "py_modules" in keywords else []
    )
    for script in console_scripts(keywords):
        module = script.split("=", 1)[1].split(":", 1)[0].strip()
        top = module.split(".", 1)[0]
        packaged = top in py_modules or (SENSOR_ROOT / top / "__init__.py").is_file()
        assert packaged, (
            f"{script!r}: {module} is not installed by setup.py (it packages "
            "the `sensor` package only), so the command fails after "
            "`pip install .` with ModuleNotFoundError."
        )


def test_the_check_sees_the_scripts_that_were_removed():
    # What setup.py declared: main.py is not a package and was not listed.
    tree = ast.parse(
        "setup(entry_points={'console_scripts': ['security-sensor=main:main']})"
    )
    keywords = {k.arg: k.value for k in tree.body[0].value.keywords}
    assert console_scripts(keywords) == ["security-sensor=main:main"]
    assert not (SENSOR_ROOT / "main" / "__init__.py").exists()
    assert (SENSOR_ROOT / "main.py").is_file()


def test_no_extra_names_a_package_the_sensor_does_not_import():
    # `windows` and `macos` named pywin32, wmi and pyobjc; the sensor reads
    # those systems' logs by running their own commands.
    assert "extras_require" not in setup_keywords()
