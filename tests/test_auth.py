from contextlib import contextmanager
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app import config, service
from app.main import (
    flow_exchange,
    google_callback,
    google_disconnect,
    google_start,
    google_token,
    health,
    status,
)
from app.models import Base
from app.schemas import StartGoogleOAuthRequest


@contextmanager
def build_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_session_local = sessionmaker(bind=engine, autoflush=False, autocommit=False, class_=Session)
    Base.metadata.create_all(bind=engine)
    db = testing_session_local()
    try:
        yield db
    finally:
        db.close()


def test_health() -> None:
    response = health()
    assert response.status == "ok"


def test_start_requires_google_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "GOOGLE_CLIENT_ID", "")
    monkeypatch.setattr(config, "GOOGLE_CLIENT_SECRET", "")
    with build_session() as db:
        with pytest.raises(Exception) as exc:
            google_start(
                StartGoogleOAuthRequest(app="jobby", scopes=["openid"], return_url="https://example.com"),
                db,
            )
        assert "GOOGLE_CLIENT_ID" in str(exc.value.detail)


def test_start_rejects_unknown_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "GOOGLE_CLIENT_ID", "client")
    monkeypatch.setattr(config, "GOOGLE_CLIENT_SECRET", "secret")
    with build_session() as db:
        with pytest.raises(Exception) as exc:
            google_start(
                StartGoogleOAuthRequest(
                    app="jobby",
                    scopes=["https://www.googleapis.com/auth/drive"],
                    return_url="https://example.com",
                ),
                db,
            )
        assert "Unsupported Google scope" in str(exc.value.detail)


def test_callback_stores_account_and_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "GOOGLE_CLIENT_ID", "client")
    monkeypatch.setattr(config, "GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setattr(config, "GOOGLE_REDIRECT_URI", "http://testserver/oauth/google/callback")

    with build_session() as db:
        started = google_start(
            StartGoogleOAuthRequest(
                app="jobby",
                scopes=["openid", "email", "profile", "https://www.googleapis.com/auth/gmail.readonly"],
                return_url="https://jobby.example/settings",
            ),
            db,
        )
        state = parse_qs(urlparse(started.auth_url).query)["state"][0]

        def fake_post(url: str, **kwargs):
            assert url == config.GOOGLE_TOKEN_URL
            return httpx.Response(
                200,
                json={
                    "access_token": "access-token",
                    "refresh_token": "refresh-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )

        def fake_get(url: str, **kwargs):
            assert url == config.GOOGLE_USERINFO_URL
            return httpx.Response(200, json={"sub": "abc123", "email": "dim@example.com", "name": "Dim"})

        monkeypatch.setattr(service.httpx, "post", fake_post)
        monkeypatch.setattr(service.httpx, "get", fake_get)

        callback_response = google_callback("oauth-code", state, db)
        assert callback_response.headers["location"].startswith("https://jobby.example/settings?auth=connected&flow_id=")

        status_response = status(db)
        assert status_response.google.email == "dim@example.com"

        exchange_response = flow_exchange(str(started.flow_id), db)
        assert exchange_response.connected is True


def test_disconnect_clears_google_link(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "GOOGLE_CLIENT_ID", "client")
    monkeypatch.setattr(config, "GOOGLE_CLIENT_SECRET", "secret")
    with build_session() as db:
        response = google_disconnect(db)
        assert response.disconnected is True


def test_google_token_requires_service_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "AUTH_SERVICE_TOKEN", "shared-secret")
    with build_session() as db:
        with pytest.raises(Exception) as exc:
            google_token("https://www.googleapis.com/auth/gmail.readonly", "Bearer wrong", db)
        assert exc.value.status_code == 401


def test_google_token_refreshes_expired_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "GOOGLE_CLIENT_ID", "client")
    monkeypatch.setattr(config, "GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setattr(config, "GOOGLE_REDIRECT_URI", "http://testserver/oauth/google/callback")
    monkeypatch.setattr(config, "AUTH_SERVICE_TOKEN", "shared-secret")

    with build_session() as db:
        started = google_start(
            StartGoogleOAuthRequest(
                app="jobby",
                scopes=["openid", "email", "profile", "https://www.googleapis.com/auth/gmail.readonly"],
                return_url="https://jobby.example/settings",
            ),
            db,
        )
        state = parse_qs(urlparse(started.auth_url).query)["state"][0]

        def fake_post(url: str, **kwargs):
            if kwargs["data"]["grant_type"] == "authorization_code":
                return httpx.Response(
                    200,
                    json={
                        "access_token": "initial-access-token",
                        "refresh_token": "refresh-token",
                        "token_type": "Bearer",
                        "expires_in": 1,
                        "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly",
                    },
                )
            return httpx.Response(
                200,
                json={
                    "access_token": "refreshed-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly",
                },
            )

        def fake_get(url: str, **kwargs):
            assert url == config.GOOGLE_USERINFO_URL
            return httpx.Response(200, json={"sub": "abc123", "email": "dim@example.com", "name": "Dim"})

        monkeypatch.setattr(service.httpx, "post", fake_post)
        monkeypatch.setattr(service.httpx, "get", fake_get)

        google_callback("oauth-code", state, db)
        token_response = google_token(
            "https://www.googleapis.com/auth/gmail.readonly",
            "Bearer shared-secret",
            db,
        )
        assert token_response.access_token == "refreshed-access-token"
        assert token_response.email == "dim@example.com"


def test_google_token_clears_connection_when_refresh_token_is_revoked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "GOOGLE_CLIENT_ID", "client")
    monkeypatch.setattr(config, "GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setattr(config, "GOOGLE_REDIRECT_URI", "http://testserver/oauth/google/callback")
    monkeypatch.setattr(config, "AUTH_SERVICE_TOKEN", "shared-secret")

    with build_session() as db:
        started = google_start(
            StartGoogleOAuthRequest(
                app="jobby",
                scopes=["openid", "email", "profile", "https://www.googleapis.com/auth/gmail.readonly"],
                return_url="https://jobby.example/settings",
            ),
            db,
        )
        state = parse_qs(urlparse(started.auth_url).query)["state"][0]

        def fake_post(url: str, **kwargs):
            if kwargs["data"]["grant_type"] == "authorization_code":
                return httpx.Response(
                    200,
                    json={
                        "access_token": "initial-access-token",
                        "refresh_token": "refresh-token",
                        "token_type": "Bearer",
                        "expires_in": 1,
                        "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly",
                    },
                )
            return httpx.Response(
                400,
                json={
                    "error": "invalid_grant",
                    "error_description": "Token has been expired or revoked.",
                },
            )

        def fake_get(url: str, **kwargs):
            assert url == config.GOOGLE_USERINFO_URL
            return httpx.Response(200, json={"sub": "abc123", "email": "dim@example.com", "name": "Dim"})

        monkeypatch.setattr(service.httpx, "post", fake_post)
        monkeypatch.setattr(service.httpx, "get", fake_get)

        google_callback("oauth-code", state, db)

        with pytest.raises(Exception) as exc:
            google_token("https://www.googleapis.com/auth/gmail.readonly", "Bearer shared-secret", db)

        assert exc.value.status_code == 401
        assert exc.value.detail == "Stored Google token expired or revoked. Reconnect Google."

        status_response = status(db)
        assert status_response.google.connected is False
        assert status_response.google.email is None
