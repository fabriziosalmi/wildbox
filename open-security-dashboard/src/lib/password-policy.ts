/**
 * The password rule identity applies to every new password (#583), checked
 * here first so a form can explain it before submitting. identity
 * (open-security-identity/app/password_policy.py) is the authority: it also
 * refuses the most common passwords, which this module does not ship, and
 * its reason is shown when it refuses one.
 *
 * Length and context only, no composition rules (NIST SP 800-63B).
 */

export const MIN_PASSWORD_LENGTH = 12
export const MAX_PASSWORD_LENGTH = 128

// identity does not look for a shorter local part inside the password.
const MIN_LOCAL_PART_LENGTH = 4

/** One line describing the rule, for the hint under a password field. */
export const PASSWORD_RULE_HINT =
  `${MIN_PASSWORD_LENGTH} to ${MAX_PASSWORD_LENGTH} characters, not containing the ` +
  "account's email address. Very common passwords are refused."

/** Why identity would refuse `password` for `email`, or null if it may accept it. */
export function passwordPolicyProblem(password: string, email?: string | null): string | null {
  // Code points, as identity counts them (Python's len()).
  const length = Array.from(password).length
  if (length < MIN_PASSWORD_LENGTH) {
    return `The password must be at least ${MIN_PASSWORD_LENGTH} characters long.`
  }
  if (length > MAX_PASSWORD_LENGTH) {
    return `The password must be at most ${MAX_PASSWORD_LENGTH} characters long.`
  }
  const address = (email ?? '').trim().toLowerCase()
  if (address) {
    const folded = password.toLowerCase()
    const localPart = address.split('@')[0]
    if (
      folded.includes(address) ||
      (localPart.length >= MIN_LOCAL_PART_LENGTH && folded.includes(localPart))
    ) {
      return "The password must not contain the account's email address or the part before the @."
    }
  }
  return null
}
