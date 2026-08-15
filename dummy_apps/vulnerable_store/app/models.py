"""Database models for the normal baseline application."""

from __future__ import annotations

from sqlalchemy import Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class User(Base):
    """Synthetic user used only by the local dummy application."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(64))


class Product(Base):
    """Small product record used by the normal search endpoint."""

    __tablename__ = "products"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), index=True)
    description: Mapped[str] = mapped_column(String(500))


class Document(Base):
    """Approved downloadable document metadata.

    The route resolves a database-backed filename inside a fixed seed directory
    instead of accepting a caller-controlled filesystem path.
    """

    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(120))
    stored_filename: Mapped[str] = mapped_column(String(120), unique=True)
