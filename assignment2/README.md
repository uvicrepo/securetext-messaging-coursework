# Assignment 2: Authentication and Authorization

This assignment strengthens SecureText beyond simple passwords by adding stronger identity checks and access control.

## Goals
- implement MFA with TOTP
- add OAuth-based login
- enforce role-based access and session limits
- explain why these controls matter

## Tasks
### 1. MFA with TOTP
Add time-based one-time passwords to the login flow:
- generate per-user secrets
- display QR codes for authenticator apps
- validate TOTP during authentication
- explain security benefits and trade-offs

### 2. OAuth integration
Add login with a third-party identity provider (GitHub is recommended):
- OAuth authorization flow
- state validation
- session handling
- hybrid local + OAuth account support

### 3. Zero Trust controls
Add:
- challenge-response checks
- role-based authorization
- session expiration
- logging and alerting for failed access or suspicious activity

## Deliverables
- MFA-enhanced SecureText implementation
- OAuth-integrated version
- zero-trust version with access controls
- security analysis and examples of attack resistance

## Notes
- Treat secrets as sensitive and do not commit credentials.
- Keep each implementation separate and clearly documented.
