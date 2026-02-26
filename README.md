# Excalibur Tours Georgia — Web Application

## Quick Start

```bash
cd excalibur_tours
python start.py
```

Then open your browser: **http://localhost:8000**

---

## Features

### 🎬 Landing Sequence
- Centered logo with a delayed 360° spin animation
- Logo shrinks and rises, revealing the site title
- Smooth fade into dual-portal login screen after 2 seconds

### 🌍 Customer Portal (Green border + Blue shield)
- Login with email/password
- Sign-up flow with password strength meter
- Password requirements: 8+ chars, uppercase, lowercase, number, special character
- 5 failed attempts → 5-minute account lockout
- All passwords hashed with PBKDF2+SHA256 (salt length 16)

### ⚙️ Admin Portal (Grey, lightens on hover + Red shield)
- Warning splash screen with "Go Back" option
- Three-field login: Email, Password, Secret Word
- Second-tier: 6-digit TOTP via Google Authenticator
- First login shows QR code to scan and register device
- **2 failed attempts → 1-hour full site lockout**

### 🔒 Security
- All passwords hashed with Werkzeug PBKDF2:SHA256
- TOTP secrets encrypted at rest with Fernet (AES-128-CBC)
- Encryption key stored separately in `.enc_key`
- Database: SQLite (excalibur.db in project root)
- Site-wide lockout screen with real-time countdown

---

## Admin Credentials

| Field | Value |
|-------|-------|
| Email | excrebminate@gmail.com |
| Password | 20AsD_213DDsxzQ1 |
| Secret Word | secretwordlol |

> **First login:** Scan the QR code with Google Authenticator.
> Subsequent logins will require the 6-digit TOTP from the app.

---

## Directory Structure

```
excalibur_tours/
├── app.py              # Flask backend (all logic)
├── start.py            # Entry point
├── requirements.txt
├── excalibur.db        # SQLite database (auto-created)
├── .enc_key            # Fernet encryption key (auto-created)
└── templates/
    └── index.html      # Full single-page frontend
```

---

## Dependencies (all standard/pre-installed)

- Flask
- Werkzeug
- cryptography (Fernet)
- Pillow (QR fallback image)

TOTP is implemented natively in `app.py` — no `pyotp` required.
QR codes use `qrcodejs` (CDN) on the frontend for display.
