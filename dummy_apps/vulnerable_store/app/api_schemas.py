"""Request/response models for the normal baseline API."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    app: str


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class LoginResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authenticated: bool
    username: str
    display_name: str


class ProductResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    name: str
    description: str


class DocumentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int
    title: str
