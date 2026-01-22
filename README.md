# SecureVault – Python Password Manager

A local password manager built in Python that securely stores and encrypts user credentials using a master password. Features include password generation, account categorization, and optional two-factor authentication (TOTP). Designed to help users manage multiple accounts safely while demonstrating cryptography and secure coding practices.

---

## Features
- Encrypted local storage using **Fernet (AES-GCM)**
- Generate strong, random passwords
- Store username, password, notes, and optional TOTP
- Categorize accounts for easy organization
- Command-line interface (CLI) using **Typer**
- Optional **two-factor authentication (TOTP)** integration
- Secure retrieval of stored passwords

---

## Installation
pip install -r requirements.txt

## Usage
- Initialize a new vault "python pwmanager.py init"

- Add a new entry
python pwmanager.py add "Gmail" --username "you@example.com" --generate --category email --notes "backup email account",generates a strong password automatically.

## Optional flags:
- --generate → auto-generate password
- --length 20 → set custom password length
- --category <name> → categorize the entry
- --notes "<text>" → add notes


- List all entries using python pwmanager.py list
- Retrieve a password using python pwmanager.py get 1

## Notes
This project is meant for learning and demonstration purposes
Use strong, unique master passwords for real accounts
Consider using dummy credentials when experimenting.
