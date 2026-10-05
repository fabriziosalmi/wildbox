"""What guardian needs to send an e-mail is checked when it starts (#705).

Compose passed guardian no mail setting, and ``EMAIL_BACKEND`` defaulted to
Django's console backend: every e-mail was printed to the worker's log and
recorded as sent. guardian/mailconf.py now reads the mail server, the
address of the dashboard and where it asks identity for addresses, and
refuses a value that cannot work, so that a typo stops guardian at start-up
instead of dropping e-mail later.
"""

import pytest
from django.core.exceptions import ImproperlyConfigured
from guardian.mailconf import (
    TEAM_CONTACTS_URL_DEFAULT,
    mail_settings,
    public_base_url,
    team_contacts_settings,
)

SMTP = "django.core.mail.backends.smtp.EmailBackend"
SERVER = {"EMAIL_HOST": "smtp.example.com", "DEFAULT_FROM_EMAIL": "g@example.com"}


def _refused(function, environ):
    with pytest.raises(ImproperlyConfigured) as refused:
        function(environ)
    return str(refused.value)


# --- the mail server --------------------------------------------------------------


@pytest.mark.parametrize(
    "environ",
    [
        {},
        {"EMAIL_HOST": ""},
        {"EMAIL_HOST": "   "},
        # Nothing else is read without a host: none of it can be wrong.
        {"EMAIL_PORT": "not-a-port", "EMAIL_USE_TLS": "maybe", "EMAIL_HOST_USER": "u"},
        {"EMAIL_BACKEND": "django.core.mail.backends.console.EmailBackend"},
    ],
)
def test_without_a_host_there_is_no_mail_server(environ):
    settings = mail_settings(environ)

    assert settings["EMAIL_HOST"] == ""
    assert settings["EMAIL_BACKEND"] == SMTP
    assert settings["DEFAULT_FROM_EMAIL"] == ""


def test_a_mail_server_with_its_defaults():
    assert mail_settings(SERVER) == {
        "EMAIL_BACKEND": SMTP,
        "EMAIL_HOST": "smtp.example.com",
        "EMAIL_PORT": 587,
        "EMAIL_USE_TLS": True,
        "EMAIL_USE_SSL": False,
        "EMAIL_HOST_USER": "",
        "EMAIL_HOST_PASSWORD": "",
        # Not Django's default, which waits for ever on a server gone quiet.
        "EMAIL_TIMEOUT": 30,
        "DEFAULT_FROM_EMAIL": "g@example.com",
    }


def test_the_values_compose_passes_empty_are_the_defaults():
    """${GUARDIAN_EMAIL_PORT:-} is an empty string, not an absent variable."""
    empty = {
        name: ""
        for name in (
            "EMAIL_PORT",
            "EMAIL_USE_TLS",
            "EMAIL_USE_SSL",
            "EMAIL_HOST_USER",
            "EMAIL_HOST_PASSWORD",
        )
    }

    assert mail_settings({**SERVER, **empty}) == mail_settings(SERVER)


def test_every_value_is_read():
    settings = mail_settings(
        {
            "EMAIL_HOST": " mail.internal ",
            "EMAIL_PORT": "465",
            "EMAIL_USE_SSL": "TRUE",
            "EMAIL_HOST_USER": "guardian",
            "EMAIL_HOST_PASSWORD": " p4ss word ",
            "DEFAULT_FROM_EMAIL": "Wildbox Guardian <guardian@example.com>",
        }
    )

    assert settings["EMAIL_HOST"] == "mail.internal"
    assert (settings["EMAIL_PORT"], settings["EMAIL_USE_SSL"]) == (465, True)
    # TLS from the start: no STARTTLS on top of it.
    assert settings["EMAIL_USE_TLS"] is False
    assert settings["EMAIL_HOST_USER"] == "guardian"
    # A password is taken as it is.
    assert settings["EMAIL_HOST_PASSWORD"] == " p4ss word "
    assert settings["DEFAULT_FROM_EMAIL"] == "Wildbox Guardian <guardian@example.com>"


@pytest.mark.parametrize(
    "host", ["10.0.0.5", "::1", "fd00::25", "smtp-1.mail_x.internal"]
)
def test_a_host_is_a_name_or_an_address(host):
    assert mail_settings({**SERVER, "EMAIL_HOST": host})["EMAIL_HOST"] == host


@pytest.mark.parametrize(
    "extra,why",
    [
        ({"EMAIL_HOST": "smtp://smtp.example.com"}, "EMAIL_HOST"),
        ({"EMAIL_HOST": "smtp.example.com:587"}, "EMAIL_PORT"),
        ({"EMAIL_HOST": "user@smtp.example.com"}, "EMAIL_HOST"),
        ({"EMAIL_HOST": "smtp.example.com/x"}, "EMAIL_HOST"),
        ({"EMAIL_HOST": "smtp example com"}, "EMAIL_HOST"),
        ({"EMAIL_PORT": "smtp"}, "EMAIL_PORT"),
        ({"EMAIL_PORT": "0"}, "EMAIL_PORT"),
        ({"EMAIL_PORT": "65536"}, "EMAIL_PORT"),
        ({"EMAIL_PORT": "-25"}, "EMAIL_PORT"),
        ({"EMAIL_PORT": "25.0"}, "EMAIL_PORT"),
        ({"EMAIL_USE_TLS": "maybe"}, "EMAIL_USE_TLS"),
        ({"EMAIL_USE_SSL": "2"}, "EMAIL_USE_SSL"),
        ({"EMAIL_USE_TLS": "true", "EMAIL_USE_SSL": "true"}, "not both"),
        ({"EMAIL_HOST_USER": "guardian"}, "go together"),
        ({"EMAIL_HOST_PASSWORD": "p4ss"}, "go together"),
        (
            {
                "EMAIL_HOST_USER": "guardian",
                "EMAIL_HOST_PASSWORD": "p4ss",
                "EMAIL_USE_TLS": "false",
            },
            "clear text",
        ),
        ({"DEFAULT_FROM_EMAIL": ""}, "DEFAULT_FROM_EMAIL is required"),
        ({"DEFAULT_FROM_EMAIL": "guardian"}, "DEFAULT_FROM_EMAIL is required"),
        (
            {"DEFAULT_FROM_EMAIL": "Guardian <guardian>"},
            "DEFAULT_FROM_EMAIL is required",
        ),
        ({"DEFAULT_FROM_EMAIL": "a@b.example, c@d.example"}, "DEFAULT_FROM_EMAIL"),
        ({"DEFAULT_FROM_EMAIL": "a@b.example\nBcc: c@d.example"}, "DEFAULT_FROM_EMAIL"),
        ({"DEFAULT_FROM_EMAIL": "a@b.example (ops, security)"}, "DEFAULT_FROM_EMAIL"),
    ],
)
def test_a_value_that_cannot_work_stops_guardian(extra, why):
    assert why in _refused(mail_settings, {**SERVER, **extra})


def test_a_refusal_does_not_show_the_password():
    message = _refused(
        mail_settings,
        {
            **SERVER,
            "EMAIL_HOST_USER": "guardian",
            "EMAIL_HOST_PASSWORD": "s3cret-p4ssword",
            "EMAIL_USE_TLS": "false",
        },
    )

    assert "s3cret-p4ssword" not in message


def test_a_server_without_a_login_may_be_reached_without_tls():
    """A relay on the internal network: no password to protect."""
    settings = mail_settings({**SERVER, "EMAIL_USE_TLS": "false", "EMAIL_PORT": "25"})

    assert (settings["EMAIL_USE_TLS"], settings["EMAIL_USE_SSL"]) == (False, False)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1", True),
        ("yes", True),
        ("On", True),
        ("0", False),
        ("no", False),
        ("OFF", False),
    ],
)
def test_true_and_false_as_people_write_them(value, expected):
    assert (
        mail_settings({**SERVER, "EMAIL_USE_TLS": value})["EMAIL_USE_TLS"] is expected
    )


def test_guardian_s_settings_are_these(settings):
    """settings.py takes every e-mail setting from here, and no backend from the environment."""
    from guardian import settings as guardian_settings

    assert guardian_settings.EMAIL_BACKEND == SMTP
    assert guardian_settings.EMAIL_TIMEOUT == 30
    assert guardian_settings.EMAIL_USE_SSL is False
    source = open(guardian_settings.__file__).read()
    assert "os.getenv('EMAIL" not in source and 'os.getenv("EMAIL' not in source
    assert "os.getenv('DEFAULT_FROM_EMAIL" not in source


# --- the address of the dashboard ---------------------------------------------------


@pytest.mark.parametrize(
    "unset", [{}, {"GUARDIAN_BASE_URL": ""}, {"GUARDIAN_BASE_URL": "  "}]
)
def test_without_a_public_address_there_is_none(unset):
    assert public_base_url(unset) == ""


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://wildbox.example.com", "https://wildbox.example.com"),
        ("https://wildbox.example.com/", "https://wildbox.example.com"),
        (" https://wildbox.example.com:8443 ", "https://wildbox.example.com:8443"),
        ("http://localhost", "http://localhost"),
        ("https://[fd00::1]:8443", "https://[fd00::1]:8443"),
    ],
)
def test_a_public_address_is_an_origin(value, expected):
    assert public_base_url({"GUARDIAN_BASE_URL": value}) == expected


@pytest.mark.parametrize(
    "value",
    [
        "wildbox.example.com",
        "//wildbox.example.com",
        "/vulnerabilities",
        "ftp://wildbox.example.com",
        "javascript:alert(1)",
        "https://",
        "https://user:pass@wildbox.example.com",
        "https://user@wildbox.example.com",
        "https://wildbox.example.com/guardian",
        "https://wildbox.example.com/?next=x",
        "https://wildbox.example.com/#x",
        "https://wildbox.example.com:port",
        "https://wildbox.example.com:0",
        "https://wild box.example.com",
        "https://wildbox.example.com\nhttps://elsewhere.example",
    ],
)
def test_a_public_address_a_browser_could_not_open_stops_guardian(value):
    assert "GUARDIAN_BASE_URL" in _refused(
        public_base_url, {"GUARDIAN_BASE_URL": value}
    )


# --- where identity is asked ---------------------------------------------------------

SECRET = "contacts-" + "0123456789abcdef" * 3


@pytest.mark.parametrize(
    "unset", [{}, {"GUARDIAN_CONTACTS_SECRET": ""}, {"GUARDIAN_CONTACTS_SECRET": " "}]
)
def test_without_a_contacts_secret_guardian_asks_nothing(unset):
    assert team_contacts_settings(unset) == (TEAM_CONTACTS_URL_DEFAULT, None)


def test_the_default_is_identity_s_name_on_the_network():
    assert team_contacts_settings(
        {"GUARDIAN_CONTACTS_SECRET": SECRET, "GUARDIAN_TEAM_CONTACTS_URL": ""}
    ) == ("http://open-security-identity:8001/internal/team-contacts", SECRET)


def test_another_address_for_identity():
    url = "https://identity.internal:8443/internal/team-contacts"

    assert team_contacts_settings(
        {"GUARDIAN_CONTACTS_SECRET": SECRET, "GUARDIAN_TEAM_CONTACTS_URL": url}
    ) == (url, SECRET)


@pytest.mark.parametrize(
    "url",
    [
        "open-security-identity:8001/internal/team-contacts",
        "ftp://open-security-identity/internal/team-contacts",
        "http://user:pass@open-security-identity:8001/internal/team-contacts",
        "http://open-security-identity:8001/internal/team-contacts?team=x",
    ],
)
def test_an_address_for_identity_that_cannot_work_stops_guardian(url):
    message = _refused(team_contacts_settings, {"GUARDIAN_TEAM_CONTACTS_URL": url})

    assert "GUARDIAN_TEAM_CONTACTS_URL" in message


def test_a_short_contacts_secret_stops_guardian():
    message = _refused(
        team_contacts_settings, {"GUARDIAN_CONTACTS_SECRET": "short-one"}
    )

    assert "at least 32 characters" in message and "short-one" not in message


def test_the_gateway_s_secret_is_not_accepted_as_the_contacts_secret():
    """Where both are present, guardian does not start on the same value."""
    message = _refused(
        team_contacts_settings,
        {"GUARDIAN_CONTACTS_SECRET": SECRET, "GATEWAY_INTERNAL_SECRET": SECRET},
    )

    assert "must not be the value of GATEWAY_INTERNAL_SECRET" in message
    assert SECRET not in message
    # A different value is the usual case.
    assert team_contacts_settings(
        {"GUARDIAN_CONTACTS_SECRET": SECRET, "GATEWAY_INTERNAL_SECRET": SECRET[::-1]}
    ) == (TEAM_CONTACTS_URL_DEFAULT, SECRET)
