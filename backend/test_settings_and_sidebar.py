import pytest
from fastapi.testclient import TestClient
from main import app
from database import get_db, SessionLocal
from models import User, UserSettings

client = TestClient(app)

from routers import request_counts

@pytest.fixture(autouse=True)
def clear_limits():
    request_counts.clear()
    yield
    request_counts.clear()

@pytest.fixture
def auth_users():
    db = SessionLocal()
    from security import get_password_hash
    # User A
    user_a = db.query(User).filter(User.email == "settings_user_a@test.com").first()
    if not user_a:
        user_a = User(
            email="settings_user_a@test.com",
            full_name="User Alpha",
            website="https://alpha.example.com",
            password_hash=get_password_hash("Password123!"),
            is_verified=True,
            role="admin"
        )
        db.add(user_a)
    else:
        user_a.password_hash = get_password_hash("Password123!")
        user_a.full_name = "User Alpha"
        user_a.website = "https://alpha.example.com"
        user_a.session_revoked_at = None
        user_a.failed_login_attempts = 0
        user_a.locked_until = None

    # User B
    user_b = db.query(User).filter(User.email == "settings_user_b@test.com").first()
    if not user_b:
        user_b = User(
            email="settings_user_b@test.com",
            full_name="User Beta",
            website="https://beta.example.com",
            password_hash=get_password_hash("Password123!"),
            is_verified=True,
            role="user"
        )
        db.add(user_b)
    else:
        user_b.password_hash = get_password_hash("Password123!")
        user_b.session_revoked_at = None
        user_b.failed_login_attempts = 0
        user_b.locked_until = None

    db.commit()
    db.close()

    # Login User A
    res_a = client.post("/api/auth/login", json={"email": "settings_user_a@test.com", "password": "Password123!"})
    token_a = res_a.json()["token"]

    # Login User B
    res_b = client.post("/api/auth/login", json={"email": "settings_user_b@test.com", "password": "Password123!"})
    token_b = res_b.json()["token"]

    return {
        "user_a": user_a,
        "token_a": token_a,
        "user_b": user_b,
        "token_b": token_b
    }

def test_get_user_profile(auth_users):
    headers = {"Authorization": f"Bearer {auth_users['token_a']}"}
    res = client.get("/api/user/profile", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == "settings_user_a@test.com"
    assert data["full_name"] == "User Alpha"
    assert data["website"] == "https://alpha.example.com"
    assert data["role"] == "admin"
    assert data["is_verified"] is True

def test_update_user_profile(auth_users):
    headers = {"Authorization": f"Bearer {auth_users['token_a']}"}
    res = client.put("/api/user/profile", json={
        "full_name": "Updated Alpha Name",
        "website": "https://new-alpha.example.com"
    }, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["full_name"] == "Updated Alpha Name"
    assert data["website"] == "https://new-alpha.example.com"

    # Verify persistence with fresh GET
    res_get = client.get("/api/user/profile", headers=headers)
    assert res_get.json()["full_name"] == "Updated Alpha Name"

def test_change_password_success_and_login(auth_users):
    headers = {"Authorization": f"Bearer {auth_users['token_a']}"}
    # 1. Successful password change
    res = client.post("/api/auth/change-password", json={
        "current_password": "Password123!",
        "new_password": "NewSecurePassword456!"
    }, headers=headers)
    assert res.status_code == 200
    assert "successfully updated" in res.json()["message"]

    # 2. Login with old password fails
    res_old = client.post("/api/auth/login", json={
        "email": "settings_user_a@test.com",
        "password": "Password123!"
    })
    assert res_old.status_code == 401

    # 3. Login with new password succeeds
    res_new = client.post("/api/auth/login", json={
        "email": "settings_user_a@test.com",
        "password": "NewSecurePassword456!"
    })
    assert res_new.status_code == 200
    assert "token" in res_new.json()

def test_change_password_invalid_current_password(auth_users):
    headers = {"Authorization": f"Bearer {auth_users['token_b']}"}
    res = client.post("/api/auth/change-password", json={
        "current_password": "WrongCurrentPassword!",
        "new_password": "NewPassword789!"
    }, headers=headers)
    assert res.status_code == 400
    assert "Incorrect current password" in res.json()["detail"]

def test_change_password_too_short(auth_users):
    headers = {"Authorization": f"Bearer {auth_users['token_b']}"}
    res = client.post("/api/auth/change-password", json={
        "current_password": "Password123!",
        "new_password": "short"
    }, headers=headers)
    assert res.status_code == 422

def test_get_and_update_user_settings(auth_users):
    headers = {"Authorization": f"Bearer {auth_users['token_b']}"}
    # Get settings
    res = client.get("/api/user/settings", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "default_scan_depth" in data

    # Update settings
    res_put = client.put("/api/user/settings", json={
        "default_scan_depth": "deep",
        "notif_scan_completed": True,
        "notif_scan_failed": False,
        "notif_security_findings": True
    }, headers=headers)
    assert res_put.status_code == 200
    updated = res_put.json()
    assert updated["default_scan_depth"] == "deep"
    assert updated["notif_scan_failed"] is False

def test_unauthenticated_access_denied():
    assert client.get("/api/user/profile").status_code == 401
    assert client.put("/api/user/profile", json={"full_name": "Hack"}).status_code == 401
    assert client.post("/api/auth/change-password", json={"current_password": "a", "new_password": "b"}).status_code == 401
    assert client.get("/api/user/settings").status_code == 401
    assert client.put("/api/user/settings", json={"default_scan_depth": "deep"}).status_code == 401

def test_account_isolation(auth_users):
    headers_a = {"Authorization": f"Bearer {auth_users['token_a']}"}
    headers_b = {"Authorization": f"Bearer {auth_users['token_b']}"}

    prof_a = client.get("/api/user/profile", headers=headers_a).json()
    prof_b = client.get("/api/user/profile", headers=headers_b).json()

    assert prof_a["email"] != prof_b["email"]
    assert prof_a["id"] != prof_b["id"]

def test_shared_sidebar_consistency():
    import os
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ETHIOSEC SCANNER 2"))
    pages = [
        ("dashboardfinal.html", "dashboardfinal.html"),
        ("scanfinal.html", "scanfinal.html"),
        ("scan_history.html", "scan_history.html"),
        ("results.html", "results.html"),
        ("reports.html", "reports.html"),
        ("assistant.html", "assistant.html"),
        ("settings.html", "settings.html"),
        ("livescan.html", "scanfinal.html")
    ]

    expected_nav_links = [
        "dashboardfinal.html",
        "scanfinal.html",
        "scan_history.html",
        "results.html",
        "reports.html",
        "assistant.html",
        "settings.html"
    ]

    for filename, active_href in pages:
        filepath = os.path.join(frontend_dir, filename)
        assert os.path.exists(filepath), f"Missing page: {filename}"
        with open(filepath, "r", encoding="utf-8") as f:
            html = f.read()

        # 1. Shared assets
        assert "shared_nav_header.css" in html, f"{filename} missing shared_nav_header.css"
        assert "shared_auth.js" in html, f"{filename} missing shared_auth.js"

        # 2. Sidebar container & logo
        assert '<aside class="sidebar" id="sidebar">' in html, f"{filename} missing standard sidebar"
        assert 'class="sidebar-logo"' in html, f"{filename} missing sidebar-logo"
        assert 'class="logo-shield-icon"' in html, f"{filename} missing logo-shield-icon"
        assert "EthioSecScan" in html, f"{filename} missing EthioSecScan logo title"

        # 3. All navigation links exist
        for link in expected_nav_links:
            assert f'href="{link}"' in html, f"{filename} missing navigation link to {link}"

        # 4. Service status box
        assert 'class="service-status-box"' in html or 'id="serviceStatusBox"' in html, f"{filename} missing service status box"

