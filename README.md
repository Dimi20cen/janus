# personal-auth

Tiny shared OAuth service for private apps on `auth.dimy.dev`.

## What it does

- owns the public Google OAuth callback for personal apps
- stores one personal Google account connection
- lets apps start Google auth flows without keeping Google client secrets locally
- can return a valid Gmail access token to trusted internal callers

## Environment

Copy `.env.example` to `.env` and fill in:

- `AUTH_APP_ID`
- `AUTH_PUBLIC_BASE_URL`
- `DATABASE_URL`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI`
- `AUTH_SERVICE_TOKEN`

`AUTH_SERVICE_TOKEN` is the shared bearer token trusted callers use for `GET /oauth/google/token`.

## Local run

```bash
cp .env.example .env
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8100
```

## Deploy shape

The current deployment runs on `srv` and is exposed publicly through the VPS reverse proxy:

- app runtime on `srv:8100`
- public hostname `https://auth.dimy.dev`
- Google redirect URI `https://auth.dimy.dev/oauth/google/callback`

## Endpoints

- `GET /`
- `GET /health`
- `GET /status`
- `POST /oauth/google/start`
- `GET /oauth/google/callback`
- `POST /oauth/google/disconnect`
- `GET /oauth/flows/{flow_id}`
- `GET /oauth/google/token`
