# Assignment 1: Security Foundations

This assignment turns the base SecureText app into a security exercise. You will find weaknesses, demonstrate attacks, and then harden the system.

## Goals
- analyze the insecure app
- secure stored passwords
- exploit and fix message authentication weaknesses
- document attacks with evidence

## Tasks
### 1. Vulnerability analysis
Identify at least five weaknesses in the application and explain:
- the issue and location
- the impact
- how it could be exploited
- how it violates security principles

### 2. Password hardening
Improve password storage by:
- hashing passwords
- adding unique salts
- using a slow hashing function
- showing why plaintext storage is unsafe

### 3. Network security and MACs
Implement and compare:
- insecure message authentication using `SHA-256(k || m)`
- a length-extension attack
- a secure fix using HMAC-SHA256

## Deliverables
- vulnerability report
- password-hardening implementation
- attack scripts and evidence
- final secure version of the app

## Expected files
- `securetext_salted.py`
- `migrate_passwords.py`
- `attack_dictionary.py`
- `securetext_flawed_mac.py`
- `attack_length_extension.py`
- `securetext_secure_mac.py`
- `capture_evidence/`

## Notes
- Keep evidence in screenshots, logs, and packet captures.
- Do not overwrite each version; keep separate deliverable files.
