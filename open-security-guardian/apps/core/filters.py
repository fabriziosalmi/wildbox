"""What guardian's filter sets share (#724)."""


def either(queryset, value, condition):
    """The rows that meet ``condition`` for a true ``value``, the others for a
    false one.

    For the true/false filters that have a method of their own. Several
    returned the queryset untouched for ``false``: ``?overdue=false`` listed
    every vulnerability, the overdue ones included, and nothing said the
    value had been ignored. django-filter does not call the method when the
    parameter is absent or empty, so ``value`` is always a decision.
    """
    if value:
        return queryset.filter(condition)
    return queryset.exclude(condition)
