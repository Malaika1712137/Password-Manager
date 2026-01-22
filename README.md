# Python Password Manager

A local password manager built in Python that securely stores and encrypts user credentials using a master password. Features include password generation, account categorization, and optional two-factor authentication (TOTP).

## Features
- Encrypted local storage using **Fernet (AES-GCM)**
- Generate strong, random passwords
- Store username, password, notes, and optional TOTP
- Categorize accounts
- Command-line interface (CLI) using Typer

## Installation
```bash
git clone https://github.com/yourusername/secure-password-manager.git
cd secure-password-manager
pip install -r requirements.txt
