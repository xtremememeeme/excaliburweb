#!/usr/bin/env python3
"""
Excalibur Tours Georgia - Local Startup Script
Run: python start.py
Then open: http://localhost:8000

For production (Render), gunicorn is used instead — see render.yaml.
"""
import sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, init_db

if __name__ == "__main__":
    print("=" * 60)
    print("  EXCALIBUR TOURS GEORGIA")
    print("  Starting server at http://localhost:8000")
    print("=" * 60)
    print()
    print("  Admin credentials:")
    print("  Email:       excrebminate@gmail.com")
    print("  Password:    20AsD_213DDsxzQ1")
    print("  Secret Word: secretwordlol")
    print()
    print("  IMPORTANT: On first admin login, scan the QR code")
    print("  with Google Authenticator to enable 2FA.")
    print()
    print("=" * 60)

    init_db()
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)
