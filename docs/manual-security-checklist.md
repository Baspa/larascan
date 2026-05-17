# Manual Security Checklist

LaraScan automates a lot of common Laravel security checks, but some concerns need a human to look at the architecture. This page covers the items LaraScan **cannot** detect — review them periodically as part of your security routine.

## 2FA on sensitive actions

Require fresh second-factor verification before:
- Password change
- Account email change
- Account deletion
- Adding/removing payment methods
- Any privileged role change

A single login session is not enough — sensitive actions should re-prompt. See [Securing Laravel — Tip #118](https://securinglaravel.com/security-tip-2fa-isnt-just-for-logins/).

## Account recovery for MFA

When users lose their second factor, they need a recovery path. Make sure recovery:
- Uses one-time codes generated at 2FA setup (printed/downloaded by the user)
- Does NOT fall back to SMS without an additional verification step
- Invalidates all sessions when recovery codes are consumed

See [Securing Laravel — Tip #119](https://securinglaravel.com/security-tip-account-recovery-for-mfa/).

## Add authorization early

Gates and Policies should land in the codebase before features grow. Retrofitting authorization onto an app that didn't have it is much harder than starting with it. Whenever you introduce a new entity, ask "who can read/write/delete this?" and write the Gate or Policy before the first endpoint.

See [Securing Laravel — Tip #116](https://securinglaravel.com/security-tip-add-authorisation-at-the-start/).

## Email verification before persisting

When a user changes their email address, do not overwrite the existing one immediately. Store the new email in a pending field, send a verification link to that new address, and only commit the change when the link is followed. This prevents an attacker who briefly accesses the account from locking the real owner out.

See [Securing Laravel — In Depth #38](https://securinglaravel.com/in-depth-email-verification-isnt-as-simple-as-you-think/).

---

Inspired by [securinglaravel.com](https://securinglaravel.com/) by Stephen Rees-Carter.
