"""Accounts for Vishwaara: sign up, log in, saved trips and favourite places.

Everything is stored in PostgreSQL (tables are created on first use).
Passwords are never stored as plain text: they are hashed with scrypt and a
random salt. A login gives the browser a random token; only a SHA-256 hash
of that token is stored, and it expires after 7 days.

Endpoints (the token is sent as "Authorization: Bearer <token>"):
    GET    /auth/captcha      which human check to show (Google reCAPTCHA or a maths question)
    POST   /auth/register     create an account (and log in, or email a 6-digit code)
    POST   /auth/login        log in (or check the password and email a 6-digit code)
    POST   /auth/verify       send the emailed code, get the login token
    POST   /auth/resend       email a new code
    POST   /auth/logout       log out
    GET    /auth/me           who am I
    PUT    /auth/me           change name / home city
    GET    /trips             my saved trips
    POST   /trips             save a trip
    DELETE /trips/{id}        delete one of my trips
    GET    /favourites        my favourite places
    POST   /favourites        save a favourite place
    DELETE /favourites/{id}   remove a favourite place
"""

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import smtplib
import threading
import time
from email.message import EmailMessage
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    delete,
    func,
    insert,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError

from src.db.connection import engine

logger = logging.getLogger("travelpal")

router = APIRouter(tags=["accounts"])

SESSION_LIFETIME_SECONDS = 7 * 24 * 60 * 60
CAPTCHA_LIFETIME_SECONDS = 5 * 60
RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
MAX_PLAN_BYTES = 200_000
MAX_TRIPS_PER_USER = 200
MAX_FAVOURITES_PER_USER = 500
CODE_LIFETIME_SECONDS = 10 * 60
CODE_RESEND_SECONDS = 30
CODE_MAX_TRIES = 5
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# ── Tables ─────────────────────────────────────────────────────────
metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("email", String(254), nullable=False, unique=True),
    Column("name", String(100), nullable=False),
    Column("home_city", String(100)),
    Column("password_hash", String(300), nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
)

sessions = Table(
    "sessions",
    metadata,
    Column("token_hash", String(64), primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("expires_at", Integer, nullable=False),
)

saved_trips = Table(
    "saved_trips",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("title", String(200), nullable=False),
    Column("destination", String(100)),
    Column("duration_days", Integer, nullable=False),
    Column("budget", Integer, nullable=False),
    Column("plan_json", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
)

favourites = Table(
    "favourites",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("place_name", String(200), nullable=False),
    Column("city", String(100), nullable=False, default=""),
    Column("state", String(100)),
    Column("place_type", String(100)),
    Column("entrance_fee_inr", Integer),
    Column("avg_rating", Float),
    Column("created_at", DateTime(timezone=True), server_default=func.now()),
    UniqueConstraint("user_id", "place_name", "city", name="uq_favourite_place"),
)

# one pending email code per address: only a hash of the code is stored
login_codes = Table(
    "login_codes",
    metadata,
    Column("email", String(254), primary_key=True),
    Column("code_hash", String(64), nullable=False),
    Column("expires_at", Integer, nullable=False),
    Column("tries", Integer, nullable=False, default=0),
    Column("sent_at", Integer, nullable=False),
)

_tables_ready = False
_tables_lock = threading.Lock()


def ensure_tables() -> None:
    """Create the account tables if they do not exist yet."""
    global _tables_ready
    if _tables_ready:
        return
    with _tables_lock:
        if not _tables_ready:
            metadata.create_all(engine)
            _tables_ready = True


# ── Passwords and tokens ───────────────────────────────────────────
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${digest.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    actual = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=len(expected)
    )
    return hmac.compare_digest(actual, expected)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ── "Are you human?" check ─────────────────────────────────────────
# The server asks a small maths question. The question comes with a signed
# token that holds the (hidden) answer, so nothing is stored on the server
# except the tokens already used (each question works only once).
_captcha_secret = os.environ.get("CAPTCHA_SECRET") or secrets.token_hex(32)
_used_captchas: dict[str, int] = {}
_captcha_lock = threading.Lock()


def _captcha_signature(expires: int, nonce: str, answer: str) -> str:
    message = f"{expires}.{nonce}.{answer}".encode()
    return hmac.new(_captcha_secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def make_captcha() -> tuple[str, int, str]:
    """Return (question, answer, token). Only the question and token are sent out."""
    kind = secrets.choice(["plus", "minus", "times"])
    if kind == "plus":
        a, b = secrets.randbelow(9) + 1, secrets.randbelow(9) + 1
        answer = a + b
    elif kind == "minus":
        a = secrets.randbelow(10) + 5
        b = secrets.randbelow(a - 1) + 1
        answer = a - b
    else:
        a, b = secrets.randbelow(8) + 2, secrets.randbelow(8) + 2
        answer = a * b

    expires = int(time.time()) + CAPTCHA_LIFETIME_SECONDS
    nonce = secrets.token_hex(8)
    token = f"{expires}.{nonce}.{_captcha_signature(expires, nonce, str(answer))}"
    return f"What is {a} {kind} {b}?", answer, token


def verify_captcha(token: str, answer: str) -> None:
    """Raise a 400 error unless the token is valid, unused, fresh and the answer is right."""
    wrong = HTTPException(
        status_code=400, detail="Wrong answer to the human check. Please try again."
    )

    try:
        expires_text, nonce, signature = token.split(".")
        expires = int(expires_text)
        normalised = str(int(answer.strip()))
    except ValueError:
        raise wrong from None

    now = int(time.time())
    if expires < now:
        raise HTTPException(
            status_code=400, detail="The human check expired. Please try again."
        )
    if expires > now + CAPTCHA_LIFETIME_SECONDS + 5:
        raise wrong  # real questions never live this long

    # Every attempt, right or wrong, uses the question up, so answers cannot be guessed.
    with _captcha_lock:
        for old_nonce in [key for key, value in _used_captchas.items() if value < now]:
            del _used_captchas[old_nonce]
        if nonce in _used_captchas:
            raise wrong
        _used_captchas[nonce] = expires

    expected = _captcha_signature(expires, nonce, normalised)
    if not hmac.compare_digest(expected, signature):
        raise wrong


def recaptcha_keys() -> tuple[str, str]:
    """(site key, secret key) of Google reCAPTCHA, or ("", "") when it is not set up."""
    site_key = os.environ.get("RECAPTCHA_SITE_KEY", "").strip()
    secret_key = os.environ.get("RECAPTCHA_SECRET_KEY", "").strip()
    if site_key and secret_key:
        return site_key, secret_key
    return "", ""


def verify_recaptcha(response_token: str, secret_key: str) -> None:
    """Ask Google whether the "I'm not a robot" box was solved by a person."""
    if not response_token:
        raise HTTPException(status_code=400, detail="Please tick \"I'm not a robot\".")

    try:
        reply = httpx.post(
            RECAPTCHA_VERIFY_URL,
            data={"secret": secret_key, "response": response_token},
            timeout=5.0,
        )
        passed = bool(reply.json().get("success"))
    except (httpx.HTTPError, ValueError) as error:
        raise HTTPException(
            status_code=503,
            detail="Could not reach Google to check you are human. Check the internet and retry.",
        ) from error

    if not passed:
        raise HTTPException(
            status_code=400, detail="The \"I'm not a robot\" check failed. Please try again."
        )


def verify_human(token: str, answer: str) -> None:
    """Use Google reCAPTCHA when its keys are set, otherwise the maths question."""
    _site_key, secret_key = recaptcha_keys()
    if secret_key:
        verify_recaptcha(token, secret_key)
    else:
        verify_captcha(token, answer)


# ── Email code (one-time password) ─────────────────────────────────
# When the SMTP settings are present (SMTP_USER + SMTP_PASSWORD, for example a
# Gmail address with an "app password"), sign up and login also need a 6-digit
# code that was emailed to the user. With EMAIL_CODES=log the code is printed in
# the API log instead (for testing). With neither, there is no code step.
def email_codes_mode() -> str:
    """"smtp", "log" or "off"."""
    if os.environ.get("SMTP_USER", "").strip() and os.environ.get("SMTP_PASSWORD", "").strip():
        return "smtp"
    if os.environ.get("EMAIL_CODES", "").strip().lower() == "log":
        return "log"
    return "off"


def send_email(to_address: str, subject: str, body: str) -> None:
    """Send a plain-text email through the SMTP account from the environment."""
    user = os.environ["SMTP_USER"].strip()
    password = os.environ["SMTP_PASSWORD"].replace(" ", "")  # Google shows it in groups of 4
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()
    port = int(os.environ.get("SMTP_PORT", "465"))
    sender = os.environ.get("SMTP_FROM", "").strip() or user

    message = EmailMessage()
    message["From"] = f"Vishwaara <{sender}>"
    message["To"] = to_address
    message["Subject"] = subject
    message.set_content(body)

    if port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=15)
    else:
        server = smtplib.SMTP(host, port, timeout=15)
        server.starttls()
    with server:
        server.login(user, password)
        server.send_message(message)


def _code_hash(email: str, code: str) -> str:
    return hash_token(f"{email}:{code}")


def send_login_code(email: str, name: str) -> None:
    """Make a fresh 6-digit code for this email address and send it."""
    now = int(time.time())
    code = f"{secrets.randbelow(1_000_000):06d}"

    with engine.begin() as conn:
        old = conn.execute(select(login_codes).where(login_codes.c.email == email)).first()
        if old is not None and now - old.sent_at < CODE_RESEND_SECONDS:
            raise HTTPException(
                status_code=429,
                detail="A code was just sent. Please wait half a minute before asking again.",
            )
        conn.execute(delete(login_codes).where(login_codes.c.email == email))
        conn.execute(
            insert(login_codes).values(
                email=email,
                code_hash=_code_hash(email, code),
                expires_at=now + CODE_LIFETIME_SECONDS,
                tries=0,
                sent_at=now,
            )
        )

    if email_codes_mode() == "log":
        logger.warning("Verification code for %s is %s (EMAIL_CODES=log)", email, code)
        return

    try:
        send_email(
            email,
            "Your Vishwaara verification code",
            f"Hi {name},\n\nYour Vishwaara verification code is {code}.\n"
            f"It works for 10 minutes. If you did not ask for it, you can ignore this email.\n",
        )
    except (smtplib.SMTPException, OSError) as error:
        logger.error("Could not send the verification email: %s", error)
        raise HTTPException(
            status_code=503,
            detail="Could not send the verification email. Please try again in a moment.",
        ) from error


def check_login_code(email: str, code: str) -> None:
    """Raise a 400 error unless this is the right, fresh, unused code for the email."""
    wrong = HTTPException(status_code=400, detail="Wrong code. Please check the email and try again.")
    now = int(time.time())

    with engine.begin() as conn:
        row = conn.execute(select(login_codes).where(login_codes.c.email == email)).first()
        if row is None:
            raise HTTPException(
                status_code=400, detail="No code is waiting for this email. Log in again."
            )
        if row.expires_at < now:
            conn.execute(delete(login_codes).where(login_codes.c.email == email))
            raise HTTPException(status_code=400, detail="The code expired. Log in again to get a new one.")
        if row.tries >= CODE_MAX_TRIES:
            conn.execute(delete(login_codes).where(login_codes.c.email == email))
            raise HTTPException(status_code=400, detail="Too many wrong tries. Log in again to get a new code.")

        if hmac.compare_digest(row.code_hash, _code_hash(email, code.strip())):
            conn.execute(delete(login_codes).where(login_codes.c.email == email))  # works only once
            return

        conn.execute(
            update(login_codes).where(login_codes.c.email == email).values(tries=row.tries + 1)
        )
    # raised after the block so the extra "try" is saved, not rolled back
    raise wrong


def _start_session(conn: Any, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    conn.execute(
        insert(sessions).values(
            token_hash=hash_token(token),
            user_id=user_id,
            expires_at=int(time.time()) + SESSION_LIFETIME_SECONDS,
        )
    )
    return token


def _user_dict(row: Any) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "email": row.email,
        "home_city": row.home_city,
    }


# ── Request bodies ─────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=8, max_length=128)
    home_city: str | None = Field(default=None, max_length=100)
    captcha_token: str = Field(default="", max_length=4096)
    captcha_answer: str = Field(default="", max_length=20)

    @field_validator("email")
    @classmethod
    def _clean_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not EMAIL_PATTERN.match(value):
            raise ValueError("Enter a valid email address.")
        return value

    @field_validator("name")
    @classmethod
    def _clean_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Name cannot be empty.")
        return value


class LoginRequest(BaseModel):
    email: str = Field(..., max_length=254)
    password: str = Field(..., max_length=128)
    captcha_token: str = Field(default="", max_length=4096)
    captcha_answer: str = Field(default="", max_length=20)


class VerifyRequest(BaseModel):
    email: str = Field(..., max_length=254)
    code: str = Field(..., min_length=1, max_length=12)


class ResendRequest(BaseModel):
    email: str = Field(..., max_length=254)


class ProfileUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    home_city: str | None = Field(default=None, max_length=100)


class TripIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    destination: str | None = Field(default=None, max_length=100)
    duration_days: int = Field(..., ge=1, le=60)
    budget: int = Field(..., ge=0, le=10_000_000)
    plan: dict[str, Any] = Field(default_factory=dict)


class FavouriteIn(BaseModel):
    place_name: str = Field(..., min_length=1, max_length=200)
    city: str = Field(default="", max_length=100)
    state: str | None = Field(default=None, max_length=100)
    place_type: str | None = Field(default=None, max_length=100)
    entrance_fee_inr: int | None = Field(default=None, ge=0, le=1_000_000)
    avg_rating: float | None = Field(default=None, ge=0, le=5)


# ── Who is logged in ───────────────────────────────────────────────
def current_user(authorization: Annotated[str | None, Header()] = None) -> dict:
    ensure_tables()

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Please log in.")

    token = authorization[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Please log in.")

    token_hash = hash_token(token)
    with engine.begin() as conn:
        row = conn.execute(
            select(
                users.c.id,
                users.c.name,
                users.c.email,
                users.c.home_city,
                sessions.c.expires_at,
            )
            .select_from(sessions.join(users, users.c.id == sessions.c.user_id))
            .where(sessions.c.token_hash == token_hash)
        ).first()

        if row is None:
            raise HTTPException(status_code=401, detail="Please log in again.")

        expired = row.expires_at < int(time.time())
        if expired:
            conn.execute(delete(sessions).where(sessions.c.token_hash == token_hash))

    # raised after the block so the delete above is saved, not rolled back
    if expired:
        raise HTTPException(status_code=401, detail="Your session expired. Please log in again.")

    return _user_dict(row)


CurrentUser = Annotated[dict, Depends(current_user)]


# ── Account endpoints ──────────────────────────────────────────────
@router.get("/auth/captcha")
def captcha() -> dict:
    site_key, _secret_key = recaptcha_keys()
    if site_key:
        return {"provider": "recaptcha", "site_key": site_key}
    question, _answer, token = make_captcha()
    return {"provider": "math", "question": question, "token": token}


@router.post("/auth/register", status_code=201)
def register(body: RegisterRequest) -> dict:
    verify_human(body.captcha_token, body.captcha_answer)
    ensure_tables()

    with engine.begin() as conn:
        exists = conn.execute(select(users.c.id).where(users.c.email == body.email)).first()
        if exists is not None:
            raise HTTPException(
                status_code=409, detail="An account with this email already exists."
            )

        try:
            result = conn.execute(
                insert(users).values(
                    email=body.email,
                    name=body.name,
                    home_city=(body.home_city or "").strip() or None,
                    password_hash=hash_password(body.password),
                )
            )
        except IntegrityError as error:
            raise HTTPException(
                status_code=409, detail="An account with this email already exists."
            ) from error

        user_id = result.inserted_primary_key[0]
        if email_codes_mode() == "off":
            token = _start_session(conn, user_id)
        else:
            token = None
        row = conn.execute(select(users).where(users.c.id == user_id)).one()

    logger.info("New account created (user id %s)", user_id)
    if token is None:
        send_login_code(row.email, row.name)
        return {"needs_code": True, "email": row.email}
    return {"token": token, "user": _user_dict(row)}


@router.post("/auth/login")
def login(body: LoginRequest) -> dict:
    verify_human(body.captcha_token, body.captcha_answer)
    ensure_tables()
    email = body.email.strip().lower()

    with engine.begin() as conn:
        row = conn.execute(select(users).where(users.c.email == email)).first()

        # same message for "no such email" and "wrong password"
        if row is None or not check_password(body.password, row.password_hash):
            raise HTTPException(status_code=401, detail="Wrong email or password.")

        token = _start_session(conn, row.id) if email_codes_mode() == "off" else None

    if token is None:
        send_login_code(row.email, row.name)
        return {"needs_code": True, "email": row.email}
    return {"token": token, "user": _user_dict(row)}


@router.post("/auth/verify")
def verify(body: VerifyRequest) -> dict:
    ensure_tables()
    email = body.email.strip().lower()
    check_login_code(email, body.code)

    with engine.begin() as conn:
        row = conn.execute(select(users).where(users.c.email == email)).first()
        if row is None:
            raise HTTPException(status_code=400, detail="No account for this email.")
        token = _start_session(conn, row.id)

    return {"token": token, "user": _user_dict(row)}


@router.post("/auth/resend")
def resend(body: ResendRequest) -> dict:
    """Email a new code, but only to an address that already has a code waiting."""
    ensure_tables()
    email = body.email.strip().lower()
    with engine.connect() as conn:
        waiting = conn.execute(select(login_codes.c.email).where(login_codes.c.email == email)).first()
        row = conn.execute(select(users).where(users.c.email == email)).first()
    if waiting is not None and row is not None:
        send_login_code(row.email, row.name)
    return {"ok": True}


@router.post("/auth/logout")
def logout(authorization: Annotated[str | None, Header()] = None) -> dict:
    ensure_tables()
    if authorization and authorization.lower().startswith("bearer "):
        token_hash = hash_token(authorization[7:].strip())
        with engine.begin() as conn:
            conn.execute(delete(sessions).where(sessions.c.token_hash == token_hash))
    return {"ok": True}


@router.get("/auth/me")
def me(user: CurrentUser) -> dict:
    return {"user": user}


@router.put("/auth/me")
def update_me(body: ProfileUpdate, user: CurrentUser) -> dict:
    values: dict[str, Any] = {}
    if body.name is not None:
        values["name"] = body.name.strip()
    if body.home_city is not None:
        values["home_city"] = body.home_city.strip() or None

    if values:
        with engine.begin() as conn:
            conn.execute(update(users).where(users.c.id == user["id"]).values(**values))
            row = conn.execute(select(users).where(users.c.id == user["id"])).one()
        user = _user_dict(row)

    return {"user": user}


# ── Saved trips ────────────────────────────────────────────────────
@router.get("/trips")
def list_trips(user: CurrentUser) -> dict:
    with engine.connect() as conn:
        rows = conn.execute(
            select(saved_trips)
            .where(saved_trips.c.user_id == user["id"])
            .order_by(saved_trips.c.id.desc())
        ).all()

    return {
        "trips": [
            {
                "id": row.id,
                "title": row.title,
                "destination": row.destination,
                "duration_days": row.duration_days,
                "budget": row.budget,
                "plan": json.loads(row.plan_json),
                "created_at": str(row.created_at),
            }
            for row in rows
        ]
    }


@router.post("/trips", status_code=201)
def save_trip(body: TripIn, user: CurrentUser) -> dict:
    plan_json = json.dumps(body.plan)
    if len(plan_json.encode("utf-8")) > MAX_PLAN_BYTES:
        raise HTTPException(status_code=413, detail="This trip is too large to save.")

    with engine.begin() as conn:
        count = conn.execute(
            select(func.count()).select_from(saved_trips).where(saved_trips.c.user_id == user["id"])
        ).scalar()
        if (count or 0) >= MAX_TRIPS_PER_USER:
            raise HTTPException(
                status_code=400, detail="Trip limit reached. Delete an old trip first."
            )

        result = conn.execute(
            insert(saved_trips).values(
                user_id=user["id"],
                title=body.title.strip(),
                destination=body.destination,
                duration_days=body.duration_days,
                budget=body.budget,
                plan_json=plan_json,
            )
        )

    return {"id": result.inserted_primary_key[0]}


@router.delete("/trips/{trip_id}")
def delete_trip(trip_id: int, user: CurrentUser) -> dict:
    with engine.begin() as conn:
        result = conn.execute(
            delete(saved_trips).where(
                saved_trips.c.id == trip_id, saved_trips.c.user_id == user["id"]
            )
        )
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Trip not found.")
    return {"ok": True}


# ── Favourite places ───────────────────────────────────────────────
def _favourite_dict(row: Any) -> dict:
    return {
        "id": row.id,
        "place_name": row.place_name,
        "city": row.city,
        "state": row.state,
        "place_type": row.place_type,
        "entrance_fee_inr": row.entrance_fee_inr,
        "avg_rating": row.avg_rating,
    }


@router.get("/favourites")
def list_favourites(user: CurrentUser) -> dict:
    with engine.connect() as conn:
        rows = conn.execute(
            select(favourites)
            .where(favourites.c.user_id == user["id"])
            .order_by(favourites.c.id.desc())
        ).all()
    return {"favourites": [_favourite_dict(row) for row in rows]}


@router.post("/favourites", status_code=201)
def add_favourite(body: FavouriteIn, user: CurrentUser) -> dict:
    with engine.begin() as conn:
        existing = conn.execute(
            select(favourites).where(
                favourites.c.user_id == user["id"],
                favourites.c.place_name == body.place_name,
                favourites.c.city == body.city,
            )
        ).first()
        if existing is not None:
            return {"favourite": _favourite_dict(existing)}

        count = conn.execute(
            select(func.count()).select_from(favourites).where(favourites.c.user_id == user["id"])
        ).scalar()
        if (count or 0) >= MAX_FAVOURITES_PER_USER:
            raise HTTPException(status_code=400, detail="Favourites limit reached.")

        result = conn.execute(
            insert(favourites).values(user_id=user["id"], **body.model_dump())
        )
        row = conn.execute(
            select(favourites).where(favourites.c.id == result.inserted_primary_key[0])
        ).one()

    return {"favourite": _favourite_dict(row)}


@router.delete("/favourites/{favourite_id}")
def delete_favourite(favourite_id: int, user: CurrentUser) -> dict:
    with engine.begin() as conn:
        result = conn.execute(
            delete(favourites).where(
                favourites.c.id == favourite_id, favourites.c.user_id == user["id"]
            )
        )
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Favourite not found.")
    return {"ok": True}
