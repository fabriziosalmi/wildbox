"""Fields the API refuses instead of dropping what the caller sent.

A ``ModelSerializer`` ignores a key it has no field for: the request is
answered 201 or 200 and the value is gone. For most keys that is harmless.
For a credential it is a lie the caller cannot see, because these fields
were write-only, so a response never showed whether one was kept: a client
that sends a scanner's API key and reads "created" believes guardian holds
it.

guardian stopped storing the credentials of scanners, external systems,
webhooks and notification channels, which nothing read (#728). A serializer
of one of those models lists the fields it no longer has in
``refused_fields``, each with the reason, and a request that sends a value
for one is answered 400 on that field. An empty value (``""``, ``null``,
``{}``, ``[]``) is not refused: nothing was sent, so nothing is lost, and a
client that fills every key of a form keeps working.

The refusal names the field and the reason and never repeats the value.
"""

from rest_framework import serializers


def _is_empty(value):
    return value is None or value == "" or value == {} or value == []


class RefusedFieldsMixin:
    """Answer 400 for a value sent in a field guardian no longer stores."""

    #: ``{field name: why guardian does not take it}``.
    refused_fields = {}

    def to_internal_value(self, data):
        errors = {}
        if hasattr(data, "get"):
            for name, reason in self.refused_fields.items():
                if name in data and not _is_empty(data.get(name)):
                    errors[name] = [reason]
        if errors:
            raise serializers.ValidationError(errors)
        return super().to_internal_value(data)
