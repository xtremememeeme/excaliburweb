#!/usr/bin/env python3
"""
Run this ONCE locally to generate your FERNET_KEY.
Copy the printed value and paste it into Render's environment variables.

Usage:
    python generate_fernet_key.py
"""
from cryptography.fernet import Fernet
key = Fernet.generate_key().decode()
print("=" * 60)
print("  Copy this value as FERNET_KEY in Render's env vars:")
print()
print(f"  {key}")
print()
print("  Keep this safe — if you lose it, all stored TOTP")
print("  secrets in the database will be unreadable.")
print("=" * 60)
