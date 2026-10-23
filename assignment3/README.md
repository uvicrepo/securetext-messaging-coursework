# Assignment 3: End-to-End Encryption

This final assignment adds end-to-end encryption to SecureText so that message contents are protected from the server and intermediaries.

## Goals
- implement ECDH key exchange
- encrypt messages with AES-GCM
- manage session expiration and cleanup
- show that confidentiality and integrity are preserved

## Core requirements
### 1. ECDH + AES-GCM
Use:
- P-256 ECDH for key agreement
- HKDF-SHA256 to derive session keys
- AES-256-GCM for authenticated encryption

### 2. Session management
Add:
- 30-minute inactivity timeout
- expiry warnings
- forced re-authentication
- secure cleanup of session keys and state

### 3. Security proof
Demonstrate:
- server cannot read message contents
- tampering is detected
- forward secrecy is supported by session expiration
- E2EE works alongside the earlier authentication fixes

## Deliverables
- complete E2EE SecureText implementation
- session management logic
- proof screenshots and logs
- final security report and analysis

## Notes
- Keep evidence for confidentiality, integrity, and session-expiration checks.
- Follow the report template and include all required proof artifacts.
