"""A check category has one spelling, and the filter finds it by either (#778).

The catalog spelled two categories two ways: ``Logging & Monitoring`` on two
CloudTrail checks and ``Logging and Monitoring`` on the third; ``Identity and
Access Management`` on two IAM checks and ``Identity & Access Management``
on the third. ``GET /api/v1/checks`` listed both spellings in ``categories``,
and its ``category`` filter gave the checks of the spelling asked for and
left the others out.

The category of a check is in the catalog and nowhere else: a scan's report
and the team's findings do not carry it, so nothing stored holds a spelling.
What can hold one is a client, which took it from an earlier answer: the
filter matches by ``utils.category_key``, so that value still finds its
checks.
"""

from collections import defaultdict

import pytest
from app import main
from app.utils import category_key
from route_probes import HEADERS


def _catalog():
    return main.check_runner.get_available_checks()


def _checks(world, **params):
    response = world.client.get("/api/v1/checks", params=params, headers=HEADERS)
    assert response.status_code == 200, response.text
    return response.json()


def test_no_two_categories_of_the_catalog_differ_only_in_spelling():
    spellings = defaultdict(set)
    for check in _catalog():
        spellings[category_key(check["category"])].add(check["category"])

    assert len(spellings) > 5, "the catalog was not loaded"
    assert {
        key: sorted(found) for key, found in spellings.items() if len(found) > 1
    } == {}


def test_a_category_is_written_as_it_is_meant_to_be_read():
    """No ampersand, which ends a query parameter's value, and no stray
    space: what ``categories`` lists can be given back as the filter."""
    for check in _catalog():
        category = check["category"]
        assert "&" not in category, check["check_id"]
        assert category == " ".join(category.split()), check["check_id"]


@pytest.mark.parametrize(
    "category, service, count",
    [
        ("Logging and Monitoring", "cloudtrail", 3),
        ("Identity and Access Management", "iam", 3),
    ],
)
def test_the_categories_that_had_two_spellings(world, category, service, count):
    listed = _checks(world)

    in_category = [c for c in listed["checks"] if c["category"] == category]
    assert len(in_category) == count
    assert {c["service"].lower() for c in in_category} == {service}
    assert category in listed["categories"]
    assert category.replace(" and ", " & ") not in listed["categories"]


@pytest.mark.parametrize(
    "asked",
    [
        "Logging and Monitoring",
        # The spelling two of the three checks had, as a client kept it.
        "Logging & Monitoring",
        "logging & monitoring",
        "LOGGING AND MONITORING",
        "Logging&Monitoring",
        "  Logging   and\tMonitoring ",
    ],
)
def test_the_filter_finds_a_category_by_either_spelling(world, asked):
    expected = _checks(world, category="Logging and Monitoring")
    assert expected["total_checks"] == 3

    answer = _checks(world, category=asked)

    assert answer == expected
    # Listed in the catalog's spelling, whatever the spelling asked in.
    assert answer["categories"] == ["Logging and Monitoring"]
    assert {c["category"] for c in answer["checks"]} == {"Logging and Monitoring"}


@pytest.mark.parametrize(
    "asked", ["Identity and Access Management", "Identity & Access Management"]
)
def test_the_other_category_that_had_two_spellings(world, asked):
    answer = _checks(world, category=asked)

    assert answer["total_checks"] == 3
    assert answer["categories"] == ["Identity and Access Management"]


def test_the_filter_is_still_exact_about_the_words(world):
    every = _checks(world)["total_checks"]

    for asked in (
        "Logging",
        "Monitoring and Logging",
        "Access",
        "Loggingand Monitoring",
    ):
        assert _checks(world, category=asked)["total_checks"] == 0, asked
    # "Access Management" is a category of its own, not a part of another.
    access = _checks(world, category="access management")
    assert access["categories"] == ["Access Management"]
    assert 0 < access["total_checks"] < every


@pytest.mark.parametrize(
    "one, other",
    [
        ("Logging & Monitoring", "Logging and Monitoring"),
        ("Logging&Monitoring", "logging  AND monitoring"),
        (" Encryption ", "encryption"),
    ],
)
def test_one_key_for_the_spellings_of_one_category(one, other):
    assert category_key(one) == category_key(other)


@pytest.mark.parametrize(
    "one, other",
    [
        # "and" inside a word is not an ampersand, nor the other way round.
        ("Command Security", "Comm& Security"),
        ("Standards", "St&ards"),
        ("Access Control", "Access Management"),
        ("Logging and Monitoring", "Logging Monitoring"),
    ],
)
def test_different_categories_keep_different_keys(one, other):
    assert category_key(one) != category_key(other)
