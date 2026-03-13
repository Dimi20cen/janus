from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str


class StartGoogleOAuthRequest(BaseModel):
    app: str = Field(min_length=1, max_length=64)
    scopes: list[str] = Field(min_length=1)
    return_url: str | None = None


class StartGoogleOAuthResponse(BaseModel):
    auth_url: str
    flow_id: UUID


class ConnectionStatus(BaseModel):
    connected: bool
    provider: Literal["google"]
    email: str | None
    display_name: str | None
    scopes: list[str]


class StatusResponse(BaseModel):
    app_id: str
    google: ConnectionStatus


class DisconnectResponse(BaseModel):
    disconnected: bool


class FlowExchangeResponse(BaseModel):
    connected: bool
    flow_id: UUID
    status: str
    account_email: str | None


class GoogleTokenResponse(BaseModel):
    access_token: str
    expiry: str | None
    email: str | None
    scopes: list[str]
