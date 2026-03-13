from urllib.parse import quote

from fastapi import Depends, FastAPI, Header
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from app.db import engine, get_db
from app.models import Base
from app.schemas import (
    DisconnectResponse,
    FlowExchangeResponse,
    GoogleTokenResponse,
    HealthResponse,
    StartGoogleOAuthRequest,
    StartGoogleOAuthResponse,
    StatusResponse,
)
from app.service import (
    complete_google_oauth,
    disconnect_google,
    exchange_flow,
    google_token_payload,
    start_google_oauth,
    status_payload,
)

BASE_DIR = __import__("pathlib").Path(__file__).resolve().parent.parent

app = FastAPI(title="Personal Auth", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.get("/status", response_model=StatusResponse)
def status(db: Session = Depends(get_db)) -> StatusResponse:
    return StatusResponse(**status_payload(db))


@app.get("/", response_class=HTMLResponse)
def home(db: Session = Depends(get_db)) -> HTMLResponse:
    payload = status_payload(db)
    google = payload["google"]
    default_scopes = quote("openid email profile https://www.googleapis.com/auth/gmail.readonly")
    return_url = quote("")
    email = google["email"] or "No account linked"
    if google["connected"]:
        body = f"""
        <p class="muted-copy">Scopes: {", ".join(google["scopes"])}</p>
        <a class="button secondary" href="/oauth/google/disconnect/browser">Disconnect Google</a>
        """
    else:
        body = f"""
        <p class="muted-copy">Use this to connect a personal Google account for private apps like Jobby and HQ.</p>
        <a class="button" href="/oauth/google/start/browser?app_name=auth-ui&scopes={default_scopes}&return_url={return_url}">Connect Google</a>
        """
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Personal Auth</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <main class="shell">
    <section class="hero panel">
      <p class="eyebrow">Shared Infra</p>
      <h1>Personal Auth</h1>
      <p class="lede">A tiny shared OAuth service for private apps on dimy.dev.</p>
    </section>
    <section class="panel">
      <div class="section-heading">
        <div>
          <p class="eyebrow">Google</p>
          <h2>{"Connected" if google["connected"] else "Not connected"}</h2>
        </div>
        <span class="status-chip {'connected' if google['connected'] else 'muted'}">{email}</span>
      </div>
      {body}
    </section>
  </main>
</body>
</html>"""
    return HTMLResponse(html)


@app.post("/oauth/google/start", response_model=StartGoogleOAuthResponse)
def google_start(payload: StartGoogleOAuthRequest, db: Session = Depends(get_db)) -> StartGoogleOAuthResponse:
    flow_id, auth_url = start_google_oauth(db, payload.app, payload.scopes, payload.return_url)
    return StartGoogleOAuthResponse(flow_id=flow_id, auth_url=auth_url)


@app.get("/oauth/google/start/browser")
def google_start_browser(
    app_name: str,
    scopes: str,
    return_url: str | None = None,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    flow_id, auth_url = start_google_oauth(
        db,
        app_name,
        [scope for scope in scopes.split() if scope.strip()],
        return_url,
    )
    _ = flow_id
    return RedirectResponse(auth_url, status_code=303)


@app.get("/oauth/google/callback")
def google_callback(code: str, state: str, db: Session = Depends(get_db)) -> RedirectResponse:
    destination = complete_google_oauth(db, code, state)
    return RedirectResponse(destination, status_code=302)


@app.post("/oauth/google/disconnect", response_model=DisconnectResponse)
def google_disconnect(db: Session = Depends(get_db)) -> DisconnectResponse:
    disconnect_google(db)
    return DisconnectResponse(disconnected=True)


@app.get("/oauth/google/disconnect/browser")
def google_disconnect_browser(db: Session = Depends(get_db)) -> RedirectResponse:
    disconnect_google(db)
    return RedirectResponse("/", status_code=303)


@app.get("/oauth/flows/{flow_id}", response_model=FlowExchangeResponse)
def flow_exchange(flow_id: str, db: Session = Depends(get_db)) -> FlowExchangeResponse:
    return FlowExchangeResponse(**exchange_flow(db, flow_id))


@app.get("/oauth/google/token", response_model=GoogleTokenResponse)
def google_token(
    scope: str | None = None,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> GoogleTokenResponse:
    if not authorization or not authorization.startswith("Bearer "):
        from fastapi import HTTPException

        raise HTTPException(status_code=401, detail="Missing bearer token.")
    return GoogleTokenResponse(**google_token_payload(db, authorization.removeprefix("Bearer "), scope))
