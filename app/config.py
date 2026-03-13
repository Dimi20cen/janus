import os
from pathlib import Path

APP_ID = os.getenv("AUTH_APP_ID", "personal-auth")
PUBLIC_BASE_URL = os.getenv("AUTH_PUBLIC_BASE_URL", "http://127.0.0.1:8100").rstrip("/")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{Path('./runtime/auth.db').resolve()}")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", f"{PUBLIC_BASE_URL}/oauth/google/callback")
AUTH_SERVICE_TOKEN = os.getenv("AUTH_SERVICE_TOKEN", "")

DEFAULT_SCOPES = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/gmail.readonly",
]

ALLOWED_SCOPES = {
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/calendar",
}

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
