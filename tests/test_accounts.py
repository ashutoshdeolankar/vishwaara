"""Tests for sign up, login, saved trips and favourite places."""

import re
import time
import uuid
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select, update

from src.api import accounts
from src.api import main as api_main
from src.api.accounts import favourites, saved_trips, sessions, users
from src.api.main import app
from src.db.connection import engine

TEST_DOMAIN = "@pytest.travelpal.test"


@pytest.fixture(autouse=True)
def _fresh_state(monkeypatch):
    """Reset the rate limiter before each test and remove test accounts after."""
    # real reCAPTCHA keys (if set on this computer) must not change these tests
    monkeypatch.delenv("RECAPTCHA_SITE_KEY", raising=False)
    monkeypatch.delenv("RECAPTCHA_SECRET_KEY", raising=False)
    # the emailed-code step must not change these tests either
    monkeypatch.delenv("SMTP_USER", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    monkeypatch.delenv("EMAIL_CODES", raising=False)
    api_main._rate_tracker.clear()
    accounts.ensure_tables()
    yield
    api_main._rate_tracker.clear()
    with engine.begin() as conn:
        ids = [
            row.id
            for row in conn.execute(
                select(users.c.id).where(users.c.email.like("%" + TEST_DOMAIN))
            )
        ]
        if ids:
            conn.execute(delete(favourites).where(favourites.c.user_id.in_(ids)))
            conn.execute(delete(saved_trips).where(saved_trips.c.user_id.in_(ids)))
            conn.execute(delete(sessions).where(sessions.c.user_id.in_(ids)))
            conn.execute(delete(users).where(users.c.id.in_(ids)))


client = TestClient(app)


def new_email() -> str:
    return "user-" + uuid.uuid4().hex[:10] + TEST_DOMAIN


def solve(question: str) -> int:
    """Answer a question like 'What is 7 plus 5?'"""
    match = re.search(r"(\d+) (plus|minus|times) (\d+)", question)
    first, word, second = int(match.group(1)), match.group(2), int(match.group(3))
    return {"plus": first + second, "minus": first - second, "times": first * second}[word]


def human_check() -> dict:
    """Fetch a fresh human-check question and answer it correctly."""
    data = client.get("/auth/captcha").json()
    return {"captcha_token": data["token"], "captcha_answer": str(solve(data["question"]))}


def sign_up(email: str | None = None, password: str = "secret-pass-1") -> dict:
    response = client.post(
        "/auth/register",
        json={
            "name": "Test User",
            "email": email or new_email(),
            "password": password,
            "home_city": "Pune",
            **human_check(),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def auth(token: str) -> dict:
    return {"Authorization": "Bearer " + token}


# ── passwords ──────────────────────────────────────────────────────
def test_password_hash_checks_correctly():
    stored = accounts.hash_password("correct horse")
    assert stored.startswith("scrypt$")
    assert "correct horse" not in stored
    assert accounts.check_password("correct horse", stored)
    assert not accounts.check_password("wrong horse", stored)
    assert not accounts.check_password("anything", "not-a-real-hash")


def test_same_password_gets_different_hashes():
    assert accounts.hash_password("same") != accounts.hash_password("same")


# ── sign up and login ──────────────────────────────────────────────
def test_register_returns_token_and_user_without_password():
    data = sign_up()
    assert data["token"]
    assert data["user"]["name"] == "Test User"
    assert data["user"]["home_city"] == "Pune"
    assert "password" not in str(data).lower()


def test_password_is_stored_hashed_in_the_database():
    email = new_email()
    sign_up(email, "plain-text-check")
    with engine.connect() as conn:
        stored = conn.execute(
            select(users.c.password_hash).where(users.c.email == email)
        ).scalar()
    assert stored != "plain-text-check"
    assert stored.startswith("scrypt$")


def test_same_email_cannot_register_twice_even_in_capitals():
    email = new_email()
    sign_up(email)
    response = client.post(
        "/auth/register",
        json={
            "name": "Other",
            "email": email.upper(),
            "password": "another-pass-1",
            **human_check(),
        },
    )
    assert response.status_code == 409


@pytest.mark.parametrize(
    "change",
    [
        {"password": "short"},
        {"email": "not-an-email"},
        {"name": "   "},
    ],
)
def test_bad_sign_up_is_rejected(change):
    body = {
        "name": "Test User",
        "email": new_email(),
        "password": "secret-pass-1",
        **human_check(),
    }
    body.update(change)
    assert client.post("/auth/register", json=body).status_code == 422


def test_login_with_right_password_works():
    email = new_email()
    sign_up(email, "my-login-pass")
    response = client.post(
        "/auth/login", json={"email": email, "password": "my-login-pass", **human_check()}
    )
    assert response.status_code == 200
    assert response.json()["token"]


def test_login_fails_for_wrong_password_and_unknown_email_with_same_message():
    email = new_email()
    sign_up(email, "my-login-pass")
    wrong = client.post(
        "/auth/login", json={"email": email, "password": "nope-nope-1", **human_check()}
    )
    unknown = client.post(
        "/auth/login",
        json={"email": new_email(), "password": "nope-nope-1", **human_check()},
    )
    assert wrong.status_code == 401
    assert unknown.status_code == 401
    assert wrong.json()["detail"] == unknown.json()["detail"]


# ── human check ────────────────────────────────────────────────────
def test_captcha_is_a_simple_question_and_does_not_leak_the_answer():
    data = client.get("/auth/captcha").json()
    assert set(data) == {"provider", "question", "token"}
    assert data["provider"] == "math"
    assert data["question"].startswith("What is ")
    assert solve(data["question"]) >= 0


def test_sign_up_needs_the_human_check():
    body = {"name": "Test User", "email": new_email(), "password": "secret-pass-1"}
    response = client.post("/auth/register", json=body)
    assert response.status_code == 400
    assert "human check" in response.json()["detail"]


def test_login_needs_the_human_check():
    email = new_email()
    sign_up(email, "my-login-pass")
    response = client.post("/auth/login", json={"email": email, "password": "my-login-pass"})
    assert response.status_code == 400


def test_wrong_human_check_answer_is_refused():
    check = human_check()
    check["captcha_answer"] = str(int(check["captcha_answer"]) + 1)
    body = {"name": "Test User", "email": new_email(), "password": "secret-pass-1", **check}
    assert client.post("/auth/register", json=body).status_code == 400


def test_a_question_cannot_be_used_twice():
    check = human_check()
    first = {"name": "Test User", "email": new_email(), "password": "secret-pass-1", **check}
    second = {"name": "Test User", "email": new_email(), "password": "secret-pass-1", **check}
    assert client.post("/auth/register", json=first).status_code == 201
    assert client.post("/auth/register", json=second).status_code == 400


def test_a_wrong_guess_uses_the_question_up():
    check = human_check()
    right = check["captcha_answer"]
    check["captcha_answer"] = str(int(right) + 1)
    body = {"name": "Test User", "email": new_email(), "password": "secret-pass-1", **check}
    assert client.post("/auth/register", json=body).status_code == 400
    body["captcha_answer"] = right
    assert client.post("/auth/register", json=body).status_code == 400


def test_an_expired_question_is_refused(monkeypatch):
    monkeypatch.setattr(accounts, "CAPTCHA_LIFETIME_SECONDS", -5)
    check = human_check()
    body = {"name": "Test User", "email": new_email(), "password": "secret-pass-1", **check}
    response = client.post("/auth/register", json=body)
    assert response.status_code == 400
    assert "expired" in response.json()["detail"]


# ── Google reCAPTCHA (switched on by two environment variables) ────
def use_google(monkeypatch, answer):
    """Switch reCAPTCHA on and replace Google with a fake that gives `answer`."""
    monkeypatch.setenv("RECAPTCHA_SITE_KEY", "site-123")
    monkeypatch.setenv("RECAPTCHA_SECRET_KEY", "secret-xyz")
    calls = []

    def fake_post(url, data, timeout):
        calls.append(data)
        if isinstance(answer, Exception):
            raise answer
        return SimpleNamespace(json=lambda: {"success": answer})

    fake_httpx = SimpleNamespace(post=fake_post, HTTPError=httpx.HTTPError)
    monkeypatch.setattr(accounts, "httpx", fake_httpx)
    return calls


def google_body() -> dict:
    return {
        "name": "Test User",
        "email": new_email(),
        "password": "secret-pass-1",
        "captcha_token": "token-from-the-browser",
    }


def test_site_key_is_offered_when_recaptcha_is_set(monkeypatch):
    use_google(monkeypatch, True)
    data = client.get("/auth/captcha").json()
    assert data == {"provider": "recaptcha", "site_key": "site-123"}


def test_sign_up_works_when_google_says_yes(monkeypatch):
    calls = use_google(monkeypatch, True)
    response = client.post("/auth/register", json=google_body())
    assert response.status_code == 201
    assert calls == [{"secret": "secret-xyz", "response": "token-from-the-browser"}]


def test_sign_up_is_refused_when_google_says_no(monkeypatch):
    use_google(monkeypatch, False)
    response = client.post("/auth/register", json=google_body())
    assert response.status_code == 400
    assert "not a robot" in response.json()["detail"]


def test_sign_up_is_refused_when_the_box_was_not_ticked(monkeypatch):
    calls = use_google(monkeypatch, True)
    body = google_body()
    body["captcha_token"] = ""
    assert client.post("/auth/register", json=body).status_code == 400
    assert calls == []


def test_a_clear_error_is_given_when_google_cannot_be_reached(monkeypatch):
    use_google(monkeypatch, httpx.ConnectError("no internet"))
    response = client.post("/auth/register", json=google_body())
    assert response.status_code == 503
    assert "Google" in response.json()["detail"]


# ── sessions ───────────────────────────────────────────────────────
def test_me_needs_a_token():
    assert client.get("/auth/me").status_code == 401
    assert client.get("/auth/me", headers=auth("made-up-token")).status_code == 401


def test_me_returns_the_logged_in_user():
    data = sign_up()
    response = client.get("/auth/me", headers=auth(data["token"]))
    assert response.status_code == 200
    assert response.json()["user"]["email"] == data["user"]["email"]


def test_logout_ends_the_session():
    token = sign_up()["token"]
    assert client.post("/auth/logout", headers=auth(token)).status_code == 200
    assert client.get("/auth/me", headers=auth(token)).status_code == 401


def test_expired_session_is_rejected():
    token = sign_up()["token"]
    with engine.begin() as conn:
        conn.execute(
            update(sessions)
            .where(sessions.c.token_hash == accounts.hash_token(token))
            .values(expires_at=int(time.time()) - 10)
        )
    assert client.get("/auth/me", headers=auth(token)).status_code == 401


def test_profile_can_be_updated():
    token = sign_up()["token"]
    response = client.put(
        "/auth/me", headers=auth(token), json={"name": "New Name", "home_city": "Mumbai"}
    )
    assert response.status_code == 200
    user = client.get("/auth/me", headers=auth(token)).json()["user"]
    assert user["name"] == "New Name"
    assert user["home_city"] == "Mumbai"


# ── saved trips ────────────────────────────────────────────────────
TRIP = {
    "title": "Kerala in 5 days",
    "destination": "Kerala",
    "duration_days": 5,
    "budget": 15000,
    "plan": {"days": [{"day": 1, "title": "Arrive in Kochi"}]},
}


def test_trips_need_login():
    assert client.get("/trips").status_code == 401
    assert client.post("/trips", json=TRIP).status_code == 401


def test_trip_can_be_saved_listed_and_deleted():
    token = sign_up()["token"]
    created = client.post("/trips", headers=auth(token), json=TRIP)
    assert created.status_code == 201
    trip_id = created.json()["id"]

    trips = client.get("/trips", headers=auth(token)).json()["trips"]
    assert len(trips) == 1
    assert trips[0]["title"] == "Kerala in 5 days"
    assert trips[0]["plan"]["days"][0]["title"] == "Arrive in Kochi"

    assert client.delete(f"/trips/{trip_id}", headers=auth(token)).status_code == 200
    assert client.get("/trips", headers=auth(token)).json()["trips"] == []


def test_a_user_cannot_see_or_delete_another_users_trip():
    owner = sign_up()["token"]
    other = sign_up()["token"]
    trip_id = client.post("/trips", headers=auth(owner), json=TRIP).json()["id"]

    assert client.get("/trips", headers=auth(other)).json()["trips"] == []
    assert client.delete(f"/trips/{trip_id}", headers=auth(other)).status_code == 404
    assert len(client.get("/trips", headers=auth(owner)).json()["trips"]) == 1


def test_a_huge_trip_is_refused():
    token = sign_up()["token"]
    big = dict(TRIP, plan={"text": "x" * (accounts.MAX_PLAN_BYTES + 10)})
    assert client.post("/trips", headers=auth(token), json=big).status_code == 413


# ── favourite places ───────────────────────────────────────────────
PLACE = {
    "place_name": "Mattancherry Palace",
    "city": "Kochi",
    "state": "Kerala",
    "place_type": "Museum",
    "entrance_fee_inr": 20,
    "avg_rating": 4.4,
}


def test_favourites_need_login():
    assert client.get("/favourites").status_code == 401


def test_favourite_can_be_added_once_listed_and_removed():
    token = sign_up()["token"]
    first = client.post("/favourites", headers=auth(token), json=PLACE)
    second = client.post("/favourites", headers=auth(token), json=PLACE)
    assert first.status_code == 201
    assert second.json()["favourite"]["id"] == first.json()["favourite"]["id"]

    listed = client.get("/favourites", headers=auth(token)).json()["favourites"]
    assert len(listed) == 1
    assert listed[0]["place_name"] == "Mattancherry Palace"

    favourite_id = listed[0]["id"]
    assert client.delete(f"/favourites/{favourite_id}", headers=auth(token)).status_code == 200
    assert client.get("/favourites", headers=auth(token)).json()["favourites"] == []


def test_a_user_cannot_remove_another_users_favourite():
    owner = sign_up()["token"]
    other = sign_up()["token"]
    favourite_id = client.post("/favourites", headers=auth(owner), json=PLACE).json()[
        "favourite"
    ]["id"]
    assert client.delete(f"/favourites/{favourite_id}", headers=auth(other)).status_code == 404
