import base64
import hmac
import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode, urlparse
from uuid import UUID

import httpx
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import config
from app.models import OAuthAccount, OAuthFlow, OAuthToken


def status_payload(db: Session) -> dict[str, Any]:
    account = db.execute(select(OAuthAccount).where(OAuthAccount.provider == "google")).scalar_one_or_none()
    token = db.get(OAuthToken, account.id) if account else None
    scopes = json.loads(token.scopes_json) if token else []
    return {
        "app_id": config.APP_ID,
        "google": {
            "connected": bool(account and token),
            "provider": "google",
            "email": account.email if account else None,
            "display_name": account.display_name if account else None,
            "scopes": scopes,
        },
    }


def start_google_oauth(db: Session, app: str, scopes: list[str], return_url: str | None) -> tuple[str, str]:
    _ensure_google_config()
    normalized_scopes = _normalize_scopes(scopes)
    if not normalized_scopes:
        raise HTTPException(status_code=400, detail="At least one Google scope is required.")
    _validate_return_url(return_url)

    flow = OAuthFlow(
        app=app,
        provider="google",
        state=secrets.token_urlsafe(24),
        code_verifier=secrets.token_urlsafe(64),
        scopes_json=json.dumps(normalized_scopes),
        return_url=return_url,
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
    )
    db.add(flow)
    db.commit()
    db.refresh(flow)

    code_challenge = _base64url(hashlib.sha256(flow.code_verifier.encode("utf-8")).digest())
    query = urlencode(
        {
            "client_id": config.GOOGLE_CLIENT_ID,
            "redirect_uri": config.GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": " ".join(normalized_scopes),
            "access_type": "offline",
            "include_granted_scopes": "true",
            "prompt": "consent",
            "state": flow.state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    return str(flow.id), f"{config.GOOGLE_AUTH_URL}?{query}"


def complete_google_oauth(db: Session, code: str, state: str) -> str:
    _ensure_google_config()
    flow = db.execute(select(OAuthFlow).where(OAuthFlow.state == state)).scalar_one_or_none()
    if flow is None:
        raise HTTPException(status_code=400, detail="Invalid OAuth state.")
    if flow.status != "pending":
        raise HTTPException(status_code=400, detail="OAuth flow already completed.")
    if _coerce_utc(flow.expires_at) < datetime.now(UTC):
        raise HTTPException(status_code=400, detail="OAuth flow expired.")

    token_response = httpx.post(
        config.GOOGLE_TOKEN_URL,
        data={
            "client_id": config.GOOGLE_CLIENT_ID,
            "client_secret": config.GOOGLE_CLIENT_SECRET,
            "code": code,
            "code_verifier": flow.code_verifier,
            "grant_type": "authorization_code",
            "redirect_uri": config.GOOGLE_REDIRECT_URI,
        },
        timeout=30,
    )
    if token_response.status_code >= 400:
        raise HTTPException(status_code=502, detail=_error_message(token_response, "Google token exchange failed."))
    token_payload = token_response.json()
    access_token = token_payload.get("access_token")
    if not access_token:
        raise HTTPException(status_code=502, detail="Google token exchange did not return an access token.")

    userinfo_response = httpx.get(
        config.GOOGLE_USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30,
    )
    if userinfo_response.status_code >= 400:
        raise HTTPException(status_code=502, detail=_error_message(userinfo_response, "Google user info request failed."))
    userinfo = userinfo_response.json()
    subject = userinfo.get("sub")
    email = userinfo.get("email")
    if not subject or not email:
        raise HTTPException(status_code=502, detail="Google user info response was missing account identity.")

    account = db.execute(
        select(OAuthAccount).where(
            OAuthAccount.provider == "google",
            OAuthAccount.provider_account_id == subject,
        )
    ).scalar_one_or_none()
    if account is None:
        account = OAuthAccount(provider="google", provider_account_id=subject, email=email)
    account.email = email
    account.display_name = userinfo.get("name")
    db.add(account)
    db.flush()

    token = db.get(OAuthToken, account.id)
    if token is None:
        token = OAuthToken(account_id=account.id, access_token=access_token, scopes_json=flow.scopes_json)
    token.access_token = access_token
    token.refresh_token = token_payload.get("refresh_token") or token.refresh_token
    token.token_type = token_payload.get("token_type")
    token.expiry = (
        datetime.now(UTC) + timedelta(seconds=int(token_payload.get("expires_in", 3600)) - 60)
        if token_payload.get("expires_in")
        else None
    )
    token.scopes_json = json.dumps(_scopes_from_token_response(token_payload, json.loads(flow.scopes_json)))
    db.add(token)

    flow.status = "completed"
    flow.account_id = account.id
    flow.completed_at = datetime.now(UTC)
    db.add(flow)
    db.commit()
    return _build_return_url(flow)


def exchange_flow(db: Session, flow_id: str | UUID) -> dict[str, Any]:
    flow_uuid = UUID(str(flow_id))
    flow = db.get(OAuthFlow, flow_uuid)
    if flow is None:
        raise HTTPException(status_code=404, detail="OAuth flow not found.")
    account = db.get(OAuthAccount, flow.account_id) if flow.account_id else None
    return {
        "connected": flow.status == "completed",
        "flow_id": flow.id,
        "status": flow.status,
        "account_email": account.email if account else None,
    }


def disconnect_google(db: Session) -> None:
    account = db.execute(select(OAuthAccount).where(OAuthAccount.provider == "google")).scalar_one_or_none()
    if account is None:
        return
    token = db.get(OAuthToken, account.id)
    if token is not None:
        db.delete(token)
    db.delete(account)
    db.commit()


def google_token_payload(db: Session, service_token: str, required_scope: str | None = None) -> dict[str, Any]:
    _require_service_token(service_token)
    account = db.execute(select(OAuthAccount).where(OAuthAccount.provider == "google")).scalar_one_or_none()
    if account is None:
        raise HTTPException(status_code=404, detail="No Google account connected.")
    token = db.get(OAuthToken, account.id)
    if token is None:
        raise HTTPException(status_code=404, detail="No Google token available.")

    scopes = _deserialize_scopes(token.scopes_json)
    if required_scope and required_scope not in scopes:
        raise HTTPException(status_code=400, detail=f"Connected Google account is missing required scope: {required_scope}")

    access_token = _ensure_fresh_access_token(db, token)
    return {
        "access_token": access_token,
        "expiry": token.expiry.isoformat() if token.expiry else None,
        "email": account.email,
        "scopes": _deserialize_scopes(token.scopes_json),
    }


def _normalize_scopes(scopes: list[str]) -> list[str]:
    normalized = []
    for scope in scopes:
        cleaned = scope.strip()
        if not cleaned:
            continue
        if cleaned not in config.ALLOWED_SCOPES:
            raise HTTPException(status_code=400, detail=f"Unsupported Google scope: {cleaned}")
        if cleaned not in normalized:
            normalized.append(cleaned)
    return normalized


def _validate_return_url(return_url: str | None) -> None:
    if not return_url:
        return
    parsed = urlparse(return_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="return_url must be an absolute http(s) URL.")


def _build_return_url(flow: OAuthFlow) -> str:
    if not flow.return_url:
        return f"{config.PUBLIC_BASE_URL}/?google=connected"
    separator = "&" if "?" in flow.return_url else "?"
    return f"{flow.return_url}{separator}auth=connected&flow_id={flow.id}"


def _ensure_google_config() -> None:
    if not config.GOOGLE_CLIENT_ID or not config.GOOGLE_CLIENT_SECRET:
        raise HTTPException(
            status_code=400,
            detail="Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET in environment.",
        )


def _require_service_token(service_token: str) -> None:
    if not config.AUTH_SERVICE_TOKEN:
        raise HTTPException(status_code=500, detail="AUTH_SERVICE_TOKEN is not configured on Janus.")
    if not hmac.compare_digest(service_token, config.AUTH_SERVICE_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid auth service token.")


def _ensure_fresh_access_token(db: Session, token: OAuthToken) -> str:
    expiry = _coerce_utc(token.expiry) if token.expiry else None
    if token.access_token and expiry and expiry > datetime.now(UTC):
        return token.access_token
    if token.access_token and expiry is None:
        return token.access_token
    if not token.refresh_token:
        raise HTTPException(status_code=401, detail="Stored Google token expired and has no refresh token.")

    token_response = httpx.post(
        config.GOOGLE_TOKEN_URL,
        data={
            "client_id": config.GOOGLE_CLIENT_ID,
            "client_secret": config.GOOGLE_CLIENT_SECRET,
            "refresh_token": token.refresh_token,
            "grant_type": "refresh_token",
        },
        timeout=30,
    )
    if token_response.status_code >= 400:
        detail = _error_message(token_response, "Google token refresh failed.")
        if _is_revoked_token_error(token_response, detail):
            _disconnect_account_by_token(db, token)
            raise HTTPException(status_code=401, detail="Stored Google token expired or revoked. Reconnect Google.")
        raise HTTPException(status_code=502, detail=detail)
    payload = token_response.json()
    access_token = payload.get("access_token")
    if not access_token:
        raise HTTPException(status_code=502, detail="Google token refresh did not return an access token.")

    token.access_token = access_token
    token.token_type = payload.get("token_type") or token.token_type
    token.expiry = (
        datetime.now(UTC) + timedelta(seconds=int(payload.get("expires_in", 3600)) - 60)
        if payload.get("expires_in")
        else None
    )
    current_scopes = _deserialize_scopes(token.scopes_json)
    token.scopes_json = json.dumps(_scopes_from_token_response(payload, current_scopes))
    db.add(token)
    db.commit()
    db.refresh(token)
    return token.access_token


def _error_message(response: httpx.Response, fallback: str) -> str:
    if response.headers.get("content-type", "").startswith("application/json"):
        payload = response.json()
        if isinstance(payload, dict):
            if payload.get("error_description"):
                return str(payload["error_description"])
            if isinstance(payload.get("error"), dict) and payload["error"].get("message"):
                return str(payload["error"]["message"])
            if isinstance(payload.get("error"), str):
                return str(payload["error"])
    return response.text or fallback


def _is_revoked_token_error(response: httpx.Response, detail: str) -> bool:
    if response.status_code not in {400, 401}:
        return False
    normalized = detail.lower()
    return "invalid_grant" in normalized or "expired or revoked" in normalized or "revoked" in normalized


def _disconnect_account_by_token(db: Session, token: OAuthToken) -> None:
    account = db.get(OAuthAccount, token.account_id)
    db.delete(token)
    if account is not None:
        db.delete(account)
    db.commit()


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("utf-8")


def _coerce_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _scopes_from_token_response(payload: dict[str, Any], fallback: list[str]) -> list[str]:
    raw_scope = payload.get("scope")
    if not raw_scope:
        return fallback
    scopes = [scope for scope in str(raw_scope).split() if scope]
    return scopes or fallback


def _deserialize_scopes(scopes_json: str) -> list[str]:
    try:
        scopes = json.loads(scopes_json)
    except json.JSONDecodeError:
        return []
    return [scope for scope in scopes if isinstance(scope, str)]
