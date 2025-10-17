# Page snapshot

```yaml
- img
- heading "Wildbox Security" [level=1]
- paragraph: Sign in to your security dashboard
- heading "Welcome back" [level=3]
- paragraph: Enter your credentials to access your account
- paragraph: Network error - please check your connection
- text: Email address
- textbox "Email address": superadmin@wildbox.com
- text: Password
- textbox "Password": wildbox123
- button:
  - img
- checkbox "Remember me"
- text: Remember me
- link "Forgot password?":
  - /url: /auth/forgot-password
- button "Sign in"
- text: Don't have an account?
- link "Sign up":
  - /url: /auth/signup
- paragraph:
  - text: By signing in, you agree to our
  - link "Terms of Service":
    - /url: /terms
  - text: and
  - link "Privacy Policy":
    - /url: /privacy
- region "Notifications (F8)":
  - list
- button "Open Tanstack query devtools":
  - img
- alert
```