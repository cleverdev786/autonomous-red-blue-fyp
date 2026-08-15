"""Functional/regression baseline tests for the normal dummy app."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from dummy_apps.vulnerable_store.app.config import StoreSettings
from dummy_apps.vulnerable_store.app.main import create_app
from dummy_apps.vulnerable_store.app.models import Product, User
from dummy_apps.vulnerable_store.app.seed import reset_database


@pytest.fixture
def app_settings(tmp_path: Path) -> StoreSettings:
    database_path = tmp_path / "store.db"
    seed_dir = tmp_path / "seed-files"
    scenario_dir = tmp_path / "scenario-files"
    return StoreSettings(
        database_url=f"sqlite:///{database_path.as_posix()}",
        seed_files_dir=seed_dir,
        scenario_files_dir=scenario_dir,
    )


@pytest.fixture
def app(app_settings: StoreSettings):
    return create_app(app_settings, reset_on_start=True)


@pytest.fixture
def client(app) -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "app": "vulnerable-store-baseline",
    }


def test_login_accepts_seeded_user(client: TestClient) -> None:
    response = client.post(
        "/login",
        json={
            "username": "student1",
            "password": "demo-pass-1",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "authenticated": True,
        "username": "student1",
        "display_name": "Demo Student One",
    }


def test_login_rejects_wrong_password(client: TestClient) -> None:
    response = client.post(
        "/login",
        json={
            "username": "student1",
            "password": "wrong-password",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"


def test_search_returns_expected_product(client: TestClient) -> None:
    response = client.get("/search", params={"q": "Notebook"})

    assert response.status_code == 200
    products = response.json()
    assert len(products) == 1
    assert products[0]["name"] == "Web Testing Notebook"


def test_empty_search_returns_seed_catalog(client: TestClient) -> None:
    response = client.get("/search")

    assert response.status_code == 200
    assert [item["name"] for item in response.json()] == [
        "Secure Coding Handbook",
        "Web Testing Notebook",
        "Blue Team Checklist",
    ]


def test_document_listing_and_download(client: TestClient) -> None:
    listing = client.get("/documents")

    assert listing.status_code == 200
    assert listing.json() == [
        {"id": 1, "title": "Welcome Guide"},
        {"id": 2, "title": "Security Lab Rules"},
    ]

    response = client.get("/files/1")

    assert response.status_code == 200
    assert "Welcome to the local FYP Vulnerable Store baseline application." in response.text


def test_missing_document_returns_404(client: TestClient) -> None:
    response = client.get("/files/999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Document not found"


def test_reset_restores_known_database_state(app, app_settings: StoreSettings) -> None:
    session_factory = app.state.session_factory

    with session_factory() as session:
        session.add(
            Product(
                name="Temporary Product",
                description="This row must disappear after reset.",
            )
        )
        user = session.scalar(select(User).where(User.username == "student1"))
        assert user is not None
        user.display_name = "Changed Name"
        session.commit()

    reset_database(
        engine=app.state.engine,
        session_factory=session_factory,
        seed_files_dir=app_settings.seed_files_dir,
        scenario_files_dir=app_settings.scenario_files_dir,
    )

    with session_factory() as session:
        product_count = session.scalar(select(func.count()).select_from(Product))
        restored_user = session.scalar(select(User).where(User.username == "student1"))

    assert product_count == 3
    assert restored_user is not None
    assert restored_user.display_name == "Demo Student One"


def test_login_input_is_not_interpreted_as_sql(client: TestClient) -> None:
    """Baseline regression guard: the normal app uses bound ORM queries."""
    response = client.post(
        "/login",
        json={
            "username": "' OR 1=1 --",
            "password": "anything",
        },
    )

    assert response.status_code == 401


def test_search_returns_input_as_data_not_html(client: TestClient) -> None:
    """Milestone 3 does not intentionally reflect raw query strings into HTML."""
    response = client.get("/search", params={"q": "<script>alert(1)</script>"})

    assert response.status_code == 200
    assert response.json() == []


def test_file_route_accepts_identifier_not_raw_path(client: TestClient) -> None:
    """Baseline route does not accept a filesystem path parameter."""
    response = client.get("/files/../../etc/passwd")

    assert response.status_code in {404, 422}
