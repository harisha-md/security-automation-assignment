
import os
import sys

# Add app directory to Python path BEFORE importing application modules
APP_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "app")
)
sys.path.insert(0, APP_DIR)

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import models
from database import Base, get_db
from main import app

TEST_DB_URL = "sqlite:///./test_vulntracker.db"

engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False}
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    # TODO: add assertions for search results
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204

# --------------------------------------------------
# Share Report Link Tests
# --------------------------------------------------

def test_create_share_link():
    token = register_and_login()

    scan = client.post("/scans/", json={
        "title": "Share test scan",
        "severity": "high",
        "affected_component": "API"
    }, headers=auth_headers(token))

    assert scan.status_code == 201

    scan_id = scan.json()["id"]

    resp = client.post(
        f"/scans/{scan_id}/share",
        json={},
        headers=auth_headers(token)
    )

    assert resp.status_code == 200
    assert "share_url" in resp.json()


def test_access_shared_scan():
    token = register_and_login()

    scan = client.post("/scans/", json={
        "title": "Public share test",
        "severity": "medium",
        "affected_component": "API"
    }, headers=auth_headers(token))

    scan_id = scan.json()["id"]

    resp = client.post(
        f"/scans/{scan_id}/share",
        json={},
        headers=auth_headers(token)
    )

    share_url = resp.json()["share_url"]
    share_token = share_url.rstrip("/").split("/")[-1]

    shared = client.get(f"/share/{share_token}")

    assert shared.status_code == 200
    assert shared.json()["id"] == scan_id


def test_expired_share_link():
    token = register_and_login()

    scan = client.post("/scans/", json={
        "title": "Expired share test",
        "severity": "low",
        "affected_component": "API"
    }, headers=auth_headers(token))

    scan_id = scan.json()["id"]

    db = TestingSessionLocal()
    try:
        db.add(models.ShareLink(
            token="expired-test-token",
            scan_id=scan_id,
            expires_at=datetime.utcnow() - timedelta(hours=1),
            password_hash=None
        ))
        db.commit()
    finally:
        db.close()

    resp = client.get("/share/expired-test-token")

    assert resp.status_code == 410


def test_password_protected_share():
    token = register_and_login()

    scan = client.post("/scans/", json={
        "title": "Protected share test",
        "severity": "high",
        "affected_component": "API"
    }, headers=auth_headers(token))

    scan_id = scan.json()["id"]

    resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "share-secret"},
        headers=auth_headers(token)
    )

    assert resp.status_code == 200

    share_token = resp.json()["share_url"].rstrip("/").split("/")[-1]

    wrong = client.get(
        f"/share/{share_token}",
        params={"password": "wrong-password"}
    )
    assert wrong.status_code == 401

    correct = client.get(
        f"/share/{share_token}",
        params={"password": "share-secret"}
    )
    assert correct.status_code == 200


def test_unauthorized_share_creation():
    owner_token = register_and_login()

    scan = client.post("/scans/", json={
        "title": "Private scan",
        "severity": "high",
        "affected_component": "API"
    }, headers=auth_headers(owner_token))

    scan_id = scan.json()["id"]

    other_token = register_and_login(
        username="bob",
        email="bob@example.com",
        password="password123"
    )

    resp = client.post(
        f"/scans/{scan_id}/share",
        json={},
        headers=auth_headers(other_token)
    )

    assert resp.status_code == 404
