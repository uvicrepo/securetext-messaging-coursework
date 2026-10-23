# SecureText: Secure Messaging Coursework

A course-based project for exploring secure software design through a deliberately insecure messaging app. The project moves from basic vulnerabilities to hardened authentication, network protections, and zero-trust controls.

## Overview

SecureText is a console-based messaging application used as a security lab. The project highlights common weaknesses in software and then shows how to harden them across several assignments.

Topics covered:
- password storage and hashing
- network eavesdropping and tampering
- MACs and length-extension attacks
- multi-factor authentication
- OAuth-based login
- zero-trust principles

## Repository Layout

```text
securetext-messaging-coursework/
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt
├── src/
│   └── securetext.py
├── assignment1/
│   ├── README.md
│   └── deliverables/
├── assignment2/
│   ├── README.md
│   └── deliverables/
├── assignment3/
│   ├── README.md
│   └── deliverables/
├── tools/
│   └── length_extension.py
├── docs/
│   └── setup.md
└── tests/
```

## Quick Start

### Prerequisites
- Python 3.10+
- Git
- Basic command-line familiarity

### Install
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run the app
```bash
python src/securetext.py server
python src/securetext.py
```

## Assignments

### Assignment 1: Security Foundations
- vulnerability analysis
- password hashing and salting
- MACs and length-extension attacks

### Assignment 2: Authentication and Authorization
- TOTP / MFA
- OAuth integration
- role-based access and session handling

### Assignment 3: Advanced Security Hardening
- secure communication design
- stronger authentication flows
- zero-trust concepts and practical controls

## Notes

This repository is intended for coursework and learning. The base app is deliberately insecure so that students can identify and exploit flaws before implementing fixes.

## License

This project is licensed under the MIT License.
