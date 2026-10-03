"""The password policy: the one rule every new password goes through (#583).

UserManager.validate_password() applies it, and every path that sets a
password reaches that method: registration (create), the reset-password
flow, change-password (set_password), an administrator's reset of another
account (PATCH /users/{id}) and the accounts a team administrator creates.

The rule follows NIST SP 800-63B (section 5.1.1.2, memorized secrets):

* a length of 12 to 128 characters;
* not the account's email address, and not containing it or its local part;
* not one of the most common passwords (data/common_passwords.txt).

There are deliberately no composition rules (an uppercase letter, a digit, a
symbol, ...): NIST advises against them, because they push people towards
predictable patterns ("Password1!") without making passwords harder to
guess. Length and a deny-list of passwords actually in use do.

The maximum is there to bound the work a request can cause, not to limit
users: every new password is hashed with Argon2, whose first step digests
the whole input, so an arbitrarily long password costs CPU in proportion to
its length on every hash. 128 characters is well beyond what a passphrase or
a password manager produces (NIST requires accepting at least 64).
"""

from functools import lru_cache
from pathlib import Path
from typing import Iterable, Optional

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

# A local part shorter than this is not looked for inside the password:
# "jo@example.com" would otherwise refuse every password containing "jo".
MIN_LOCAL_PART_LENGTH = 4

DENY_LIST_PATH = Path(__file__).parent / "data" / "common_passwords.txt"


@lru_cache(maxsize=1)
def common_passwords() -> frozenset:
    """The vendored deny-list, lower-cased, read once."""
    with DENY_LIST_PATH.open(encoding="utf-8") as handle:
        return frozenset(
            line.rstrip("\n").lower()
            for line in handle
            if line.strip() and not line.startswith("#")
        )


def password_problem(
    password: str, emails: Iterable[Optional[str]] = ()
) -> Optional[str]:
    """Why `password` is refused for an account with `emails`, or None.

    `emails` are the addresses the account has or is about to have; each is
    compared case-insensitively, as a whole and by its local part.
    """
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        return f"The password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"The password must be at most {MAX_PASSWORD_LENGTH} characters long."

    folded = password.casefold()
    for email in emails:
        if not email:
            continue
        email = str(email).strip().casefold()
        local_part = email.split("@", 1)[0]
        if email in folded or (
            len(local_part) >= MIN_LOCAL_PART_LENGTH and local_part in folded
        ):
            return "The password must not contain the account's email address or the part before the @."

    if password.lower() in common_passwords():
        return "This password is one of the most commonly used passwords. Choose a less common one."
    return None
