"""The queries the sensor issues must reference columns osquery actually has.

The Linux services query asked for `name, status, pid, path` from
`systemd_units` and filtered on `type = 'service'`. That table has none of those
five columns, so every collection cycle ended in

    osquery query failed: Error: no such column: name

logged at ERROR and otherwise ignored. The service inventory was permanently
empty on the platform this sensor is deployed on, and had been since the
collector was written -- nothing failed loudly enough to notice.

A SQL string is not checked by anything until it runs against a real osquery, on
a real host, with the right platform. This test moves the check to build time
for the one table whose schema is pinned below.
"""

import re
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SERVICE_ROOT))

COLLECTOR = SERVICE_ROOT / "sensor" / "collectors" / "osquery_manager.py"

# osquery 5.x, verified by running
#   osqueryi --json "PRAGMA table_info(systemd_units);"
# inside the sensor image. Update this list from that command, never from
# memory: getting it wrong is the defect this test exists to catch.
SYSTEMD_UNITS_COLUMNS = {
    "id",
    "description",
    "load_state",
    "active_state",
    "sub_state",
    "unit_file_state",
    "following",
    "object_path",
    "job_id",
    "job_type",
    "job_path",
    "fragment_path",
    "user",
    "source_path",
}

SQL_KEYWORDS = {
    "select", "from", "where", "as", "and", "or", "not", "like", "in", "is",
    "null", "limit", "order", "by", "group", "having", "union", "join", "on",
    "left", "inner", "outer", "distinct", "case", "when", "then", "else", "end",
}


def _linux_services_query() -> str:
    source = COLLECTOR.read_text()
    start = source.index("def _get_services_query")
    linux = source.index("if is_linux():", start)
    macos = source.index("elif is_macos():", linux)
    match = re.search(r"'''(.*?)'''", source[linux:macos], re.S)
    assert match, "could not find the Linux services query"
    return match.group(1)


def _referenced_columns(query: str) -> set:
    """Bare identifiers in the query, minus keywords, aliases and literals."""
    without_strings = re.sub(r"'[^']*'", " ", query)
    # An alias introduced with AS is a name we invent, not one we read.
    aliases = set(re.findall(r"\bAS\s+([A-Za-z_][A-Za-z0-9_]*)", without_strings, re.I))
    words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", without_strings))
    return {w for w in words if w.lower() not in SQL_KEYWORDS} - aliases - {"systemd_units"}


def test_the_query_is_still_the_one_we_check():
    assert "systemd_units" in _linux_services_query()


def test_linux_services_query_uses_columns_that_exist():
    referenced = _referenced_columns(_linux_services_query())
    unknown = referenced - SYSTEMD_UNITS_COLUMNS
    assert not unknown, (
        f"systemd_units has no column(s) {sorted(unknown)}; "
        f"it has {sorted(SYSTEMD_UNITS_COLUMNS)}"
    )


@pytest.mark.parametrize("column", ["name", "status", "pid", "path", "type"])
def test_the_columns_that_never_existed_are_not_read_back(column):
    """Named individually so a regression says which one came back."""
    query = _linux_services_query()
    # They may appear as aliases -- `id AS name` is the point -- but never as
    # something read from the table.
    read = _referenced_columns(query)
    assert column not in read, f"{column!r} is read from systemd_units, which has no such column"


def test_the_alias_names_the_pipeline_expects_are_produced():
    """Downstream reads name/status/path; the aliases keep that shape."""
    query = _linux_services_query()
    aliases = {a.lower() for a in re.findall(r"\bAS\s+([A-Za-z_][A-Za-z0-9_]*)", query, re.I)}
    assert {"name", "status", "path", "service_type"} <= aliases
