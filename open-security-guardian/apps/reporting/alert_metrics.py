"""What an alert rule measures (#549).

An alert rule names a metric in ``data_source``, narrows it with filters in
``condition_config`` and compares the value with ``threshold_value`` using
``operator``. Every rule used to be evaluated against 0, whatever it named,
so a rule could never fire on real data, and one with "> 0" never fired at
all. Each metric below is a query over guardian's own tables:

``vulnerabilities.unresolved``
    Vulnerabilities that are open or in progress.
``vulnerabilities.overdue``
    Open vulnerabilities past their due date: the SLA check's definition
    (apps.vulnerabilities.tasks.check_sla_violations).
``vulnerabilities.max_risk_score``
    The highest risk score (0-10) among unresolved vulnerabilities; 0 when
    there are none.
``compliance.non_compliant_results``
    Compliance results found non-compliant.
``compliance.overdue_assessments``
    Planned or in-progress assessments past their due date, as the overdue
    reminder counts them (apps.compliance.tasks.check_overdue_assessments).

The vulnerability metrics accept the filters ``severity`` (a list of
severities) and ``asset`` (an asset id); the non-compliant results accept
``risk_level`` (a list of risk levels).

Only ``threshold`` conditions are evaluated. ``change``, ``trend`` and
``anomaly`` were never implemented (they evaluated to "not triggered"
whatever the data), and the API refuses them, like an unknown metric,
instead of accepting a rule that cannot fire.
"""

import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict

from django.db.models import Max
from django.utils import timezone


class UnsupportedAlertRule(ValueError):
    """A rule whose metric, condition or filters guardian cannot evaluate."""


def _choice_list(name, choices):
    allowed = {value for value, _ in choices}

    def parse(value):
        if not isinstance(value, list) or not value:
            raise UnsupportedAlertRule(f"{name} must be a non-empty list")
        unknown = [item for item in value if item not in allowed]
        if unknown:
            raise UnsupportedAlertRule(
                f"{name}: unknown value(s) {unknown}; allowed: {sorted(allowed)}"
            )
        return value

    return parse


def _uuid(name):
    def parse(value):
        try:
            return str(uuid.UUID(str(value)))
        except ValueError:
            raise UnsupportedAlertRule(f"{name} must be an id (UUID)")

    return parse


@dataclass(frozen=True)
class Metric:
    description: str
    compute: Callable[[dict], float]
    filters: Dict[str, Callable] = field(default_factory=dict)


def _vulnerability_filters():
    from apps.vulnerabilities.models import VulnerabilitySeverity

    return {
        "severity": _choice_list("severity", VulnerabilitySeverity.choices),
        "asset": _uuid("asset"),
    }


def _vulnerabilities(filters):
    from apps.vulnerabilities.models import Vulnerability

    queryset = Vulnerability.objects.all()
    if "severity" in filters:
        queryset = queryset.filter(severity__in=filters["severity"])
    if "asset" in filters:
        queryset = queryset.filter(asset_id=filters["asset"])
    return queryset


UNRESOLVED = ("open", "in_progress")


def _unresolved(filters):
    return float(_vulnerabilities(filters).filter(status__in=UNRESOLVED).count())


def _overdue(filters):
    return float(
        _vulnerabilities(filters)
        .filter(status="open", due_date__lt=timezone.now())
        .count()
    )


def _max_risk_score(filters):
    found = (
        _vulnerabilities(filters)
        .filter(status__in=UNRESOLVED)
        .aggregate(value=Max("risk_score"))["value"]
    )
    return float(found or 0.0)


def _non_compliant_results(filters):
    from apps.compliance.models import ComplianceResult

    queryset = ComplianceResult.objects.filter(status="non_compliant")
    if "risk_level" in filters:
        queryset = queryset.filter(risk_level__in=filters["risk_level"])
    return float(queryset.count())


def _overdue_assessments(filters):
    from apps.compliance.models import ComplianceAssessment

    return float(
        ComplianceAssessment.objects.filter(
            due_date__lt=timezone.now(), status__in=["planned", "in_progress"]
        ).count()
    )


def _compliance_result_filters():
    from apps.compliance.models import ComplianceResult

    return {"risk_level": _choice_list("risk_level", ComplianceResult.RISK_LEVELS)}


def metrics():
    """The supported metrics, by the name a rule gives in data_source."""
    vulnerability_filters = _vulnerability_filters()
    return {
        "vulnerabilities.unresolved": Metric(
            "Vulnerabilities open or in progress",
            _unresolved,
            vulnerability_filters,
        ),
        "vulnerabilities.overdue": Metric(
            "Open vulnerabilities past their due date",
            _overdue,
            vulnerability_filters,
        ),
        "vulnerabilities.max_risk_score": Metric(
            "Highest risk score among unresolved vulnerabilities",
            _max_risk_score,
            vulnerability_filters,
        ),
        "compliance.non_compliant_results": Metric(
            "Non-compliant compliance results",
            _non_compliant_results,
            _compliance_result_filters(),
        ),
        "compliance.overdue_assessments": Metric(
            "Planned or in-progress assessments past their due date",
            _overdue_assessments,
        ),
    }


SUPPORTED_CONDITION_TYPES = ("threshold",)


def parse_rule(data_source, condition_type, operator, threshold_value, config):
    """(metric, filters) for a rule; UnsupportedAlertRule if it cannot run.

    Raises with a dict of field -> message, so the API can report each
    field the way a serializer does.
    """
    errors = {}
    known = metrics()
    metric = known.get(data_source)
    if metric is None:
        errors["data_source"] = (
            f"unknown metric {data_source!r}; supported: {', '.join(sorted(known))}"
        )
    if condition_type not in SUPPORTED_CONDITION_TYPES:
        errors["condition_type"] = (
            f"{condition_type!r} conditions are not evaluated; only 'threshold' is"
        )
    if not operator:
        errors["operator"] = "a threshold condition needs an operator"
    if threshold_value is None:
        errors["threshold_value"] = "a threshold condition needs a threshold"
    filters = {}
    if config is None:
        config = {}
    if not isinstance(config, dict):
        errors["condition_config"] = "must be an object of filters"
    elif metric is not None:
        unknown = sorted(set(config) - set(metric.filters))
        if unknown:
            allowed = ", ".join(sorted(metric.filters)) or "none"
            errors["condition_config"] = (
                f"unknown filter(s) {unknown} for {data_source}; allowed: {allowed}"
            )
        else:
            try:
                filters = {
                    name: metric.filters[name](value) for name, value in config.items()
                }
            except UnsupportedAlertRule as exc:
                errors["condition_config"] = str(exc)
    if errors:
        raise UnsupportedAlertRule(errors)
    return metric, filters


def current_value(rule):
    """The value of ``rule``'s metric now; UnsupportedAlertRule if it has none."""
    metric, filters = parse_rule(
        rule.data_source,
        rule.condition_type,
        rule.operator,
        rule.threshold_value,
        rule.condition_config,
    )
    return metric.compute(filters)
