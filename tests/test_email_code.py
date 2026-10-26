"""Tests for the emailed 6-digit code on sign up and login."""

import re
import time
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select, update

from src.api import accounts
from src.api import main as api_main
from src.api.accounts import favourites, login_codes, saved_trips, sessions, users
from src.api.main import app
from src.db.connection import engine

TEST_DOMAIN = "@code.travelpal.test"
client = TestClient(app)
sent_mails: list[tuple[str, str]] = []


@pytest.fixture(autouse=True)
def _mail_on(monkeypatch):
    """Turn the code step on and catch the emails instead of sending them."""
    monkeypatch.delenv("RECAPTCHA_SITE_KEY", raising=False)
    monkeypatch.delenv("RECAPTCHA_SECRET_KEY", raising=False)
    monkeypatch.setenv("SMTP_USER", "test@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "not-a-real-password")
    sent_mails.clear()
    monkeypatch.setattr(
        accounts, "send_email", lambda to, subject, body: sent_mails.append((to, body))
    )
    api_main._rate_tracker.clear()
    accounts.ensure_tables()
    yield
    api_main._rate_tracker.clear()
    with engine.begin() as conn:
        ids = [
            row.id
            for row in conn.execute(select(users.c.id).where(users.c.email.like("%" + TEST_DOMAIN)))
        ]
        conn.execute(delete(login_codes).where(login_codes.c.email.like("%" + TEST_DOMAIN)))
        if ids:
            conn.execute(delete(favourites).where(favourites.c.user_id.in_(ids)))
            conn.execute(delete(saved_trips).where(saved_trips.c.user_id.in_(ids)))
            conn.execute(delete(sessions).where(sessions.c.user_id.in_(ids)))
            conn.execute(delete(users).where(users.c.id.in_(ids)))


def human_check() -> dict:
    data = client.get("/auth/captcha").json()
    first, word, second = re.search(r"(\d+) (plus|minus|times) (\d+)", data["question"]).groups()
    a, b = int(first), int(second)
    answer = {"plus": a + b, "minus": a - b, "times": a * b}[word]
    return {"captcha_token": data["token"], "captcha_answer": str(answer)}


def register(email: str):
    return client.post(
        "/auth/register",
        json={"name": "Code User", "email": email, "password": "secret-pass-1", **human_check()},
    )


def login(email: str):
    return client.post(
        "/auth/login", json={"email": email, "password": "secret-pass-1", **human_check()}
    )


def last_code() -> str:
    return re.search(r"\b(\d{6})\b", sent_mails[-1][1]).group(1)


def new_email() -> str:
    return "u-" + uuid.uuid4().hex[:10] + TEST_DOMAIN


def test_sign_up_sends_a_code_and_gives_no_token_yet():
    email = new_email()
    response = register(email)
    assert response.status_code == 201
    assert response.json() == {"needs_code": True, "email": email}
    assert sent_mails and sent_mails[-1][0] == email


def test_the_right_code_logs_you_in():
    email = new_email()
    register(email)
    response = client.post("/auth/verify", json={"email": email, "code": last_code()})
    assert response.status_code == 200
    token = response.json()["token"]
    me = client.get("/auth/me", headers={"Authorization": "Bearer " + token})
    assert me.json()["user"]["email"] == email


def test_login_needs_the_code_after_the_password():
    email = new_email()
    register(email)
    time.sleep(0.01)
    with engine.begin() as conn:  # allow a new code at once
        conn.execute(update(login_codes).where(login_codes.c.email == email).values(sent_at=0))
    response = login(email)
    assert response.json() == {"needs_code": True, "email": email}
    assert client.post("/auth/verify", json={"email": email, "code": last_code()}).status_code == 200


def test_wrong_password_sends_no_email():
    email = new_email()
    register(email)
    sent_mails.clear()
    with engine.begin() as conn:
        conn.execute(update(login_codes).where(login_codes.c.email == email).values(sent_at=0))
    response = client.post(
        "/auth/login", json={"email": email, "password": "wrong-pass-9", **human_check()}
    )
    assert response.status_code == 401
    assert sent_mails == []


def test_a_wrong_code_is_refused_and_five_wrong_tries_lock_it():
    email = new_email()
    register(email)
    good = last_code()
    bad = "000000" if good != "000000" else "111111"
    for _ in range(5):
        assert client.post("/auth/verify", json={"email": email, "code": bad}).status_code == 400
    assert client.post("/auth/verify", json={"email": email, "code": good}).status_code == 400


def test_a_code_works_only_once():
    email = new_email()
    register(email)
    code = last_code()
    assert client.post("/auth/verify", json={"email": email, "code": code}).status_code == 200
    assert client.post("/auth/verify", json={"email": email, "code": code}).status_code == 400


def test_an_expired_code_is_refused():
    email = new_email()
    register(email)
    with engine.begin() as conn:
        conn.execute(update(login_codes).where(login_codes.c.email == email).values(expires_at=1))
    assert client.post("/auth/verify", json={"email": email, "code": last_code()}).status_code == 400


def test_a_new_code_cannot_be_asked_for_every_second():
    email = new_email()
    register(email)
    response = login(email)
    assert response.status_code == 429


def test_resend_gives_a_new_code_that_works():
    email = new_email()
    register(email)
    with engine.begin() as conn:
        conn.execute(update(login_codes).where(login_codes.c.email == email).values(sent_at=0))
    count = len(sent_mails)
    assert client.post("/auth/resend", json={"email": email}).json() == {"ok": True}
    assert len(sent_mails) == count + 1
    assert client.post("/auth/verify", json={"email": email, "code": last_code()}).status_code == 200


def test_resend_does_nothing_for_unknown_email():
    client.post("/auth/resend", json={"email": new_email()})
    assert sent_mails == []


def test_a_failed_email_gives_a_clear_error(monkeypatch):
    def broken(*_args):
        raise OSError("no internet")

    monkeypatch.setattr(accounts, "send_email", broken)
    response = register(new_email())
    assert response.status_code == 503
