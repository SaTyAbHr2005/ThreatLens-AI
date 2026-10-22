"""Analyst login for the console: password → Slider CAPTCHA → login-anomaly check → JWT.

"We protect the humans who protect the agents." A stolen analyst password alone is not
enough: the login must also pass a human-movement CAPTCHA and look like that analyst's
usual logins. Every attempt is recorded in `login_events`.
"""

import hashlib
import logging
import math
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from threatlens.core.config import Settings, get_settings
from threatlens.core.db import C
from threatlens.core.http import require_operator
from threatlens.core.schemas import utcnow
from threatlens.core.security import AUD_CONSOLE, InvalidToken, hash_password, issue_token, verify_password, verify_token

from .anomaly import LoginAnomalyModel
from .captcha import CaptchaAnswer, CaptchaVerifier

log = logging.getLogger(__name__)

LOCKOUT_FAILURES = 5
LOCKOUT_WINDOW_S = 15 * 60
HISTORY = 50  # login hours kept per analyst
_DUMMY_HASH = hash_password("timing-equaliser-not-a-real-password")
Email = Annotated[str, Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=254)]


class Analyst(BaseModel):
    email: str
    name: str
    password_hash: str
    created_at: datetime = Field(default_factory=utcnow)
    devices: list[str] = Field(default_factory=list)  # hashed device ids that logged in successfully
    login_hours: list[int] = Field(default_factory=list)  # UTC hours of recent successful logins


class AnalystStore:
    """All analysts in memory (a console has few), written through to Atlas when available."""

    def __init__(self, db=None):
        self.db = db
        self._by_email: dict[str, Analyst] = {}

    async def load(self) -> None:
        if self.db is not None:
            async for doc in self.db[C.analysts].find({}, {"_id": 0}):
                self._by_email[doc["email"]] = Analyst(**doc)

    def get(self, email: str) -> Analyst | None:
        return self._by_email.get(email.lower())

    def all(self) -> list[Analyst]:
        return list(self._by_email.values())

    async def save(self, a: Analyst) -> None:
        self._by_email[a.email] = a
        if self.db is not None:
            await self.db[C.analysts].replace_one({"email": a.email}, a.model_dump(), upsert=True)

    async def log(self, event: dict) -> None:
        if self.db is not None:
            try:
                await self.db[C.login_events].insert_one(event)
            except Exception:
                log.exception("could not record login event")


def _device(device_id: str, user_agent: str) -> str:
    return hashlib.sha256(f"{device_id}|{user_agent}".encode()).hexdigest()[:16]


def _hour_shift(hours: list[int], now_hour: int) -> float:
    if len(hours) < 5:
        return 0.0  # not enough history to know the usual time
    usual = sorted(hours)[len(hours) // 2]
    d = abs(now_hour - usual) % 24
    return float(min(d, 24 - d))


class LoginIn(BaseModel):
    email: Email
    password: str = Field(min_length=1, max_length=200)
    device_id: str = Field(min_length=8, max_length=100, description="random id the browser keeps")
    captcha: CaptchaAnswer


class AnalystIn(BaseModel):
    email: Email
    name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=12, max_length=200)


class AnalystOut(BaseModel):
    email: str
    name: str
    created_at: datetime
    devices: int


def _out(a: Analyst) -> AnalystOut:
    return AnalystOut(email=a.email, name=a.name, created_at=a.created_at, devices=len(a.devices))


class AuthService:
    def __init__(self, store: AnalystStore, settings: Settings):
        self.store = store
        self.settings = settings
        self.captcha = CaptchaVerifier(settings)
        self.model = LoginAnomalyModel()
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    async def create(self, email: str, name: str, password: str) -> Analyst:
        a = Analyst(email=email.lower(), name=name, password_hash=hash_password(password))
        await self.store.save(a)
        return a

    async def seed_demo(self) -> None:
        email, password = self.settings.demo_analyst_email, self.settings.demo_analyst_password
        if not (email and password):
            return
        if self.settings.env == "prod" and len(password) < 12:
            log.warning("DEMO_ANALYST_PASSWORD is shorter than 12 characters; demo account not created")
            return
        existing = self.store.get(email)
        if existing is None or not verify_password(existing.password_hash, password):
            await self.store.save(Analyst(email=email.lower(), name="Demo analyst", password_hash=hash_password(password),
                                          devices=existing.devices if existing else [],
                                          login_hours=existing.login_hours if existing else []))

    def _recent_failures(self, email: str) -> int:
        q, cutoff = self._failures[email], time.time() - LOCKOUT_WINDOW_S
        while q and q[0] < cutoff:
            q.popleft()
        return len(q)

    async def _fail(self, email: str, record: dict, status: int, detail) -> HTTPException:
        self._failures[email].append(time.time())
        await self.store.log({**record, "ok": False, "reason": detail if isinstance(detail, str) else detail["reason"]})
        return HTTPException(status, detail)

    async def login(self, body: LoginIn, ip: str, user_agent: str) -> dict:
        email = body.email.lower()
        now = utcnow()
        record = {"ts": now, "email": email, "ip": ip, "device": _device(body.device_id, user_agent)}
        failures = self._recent_failures(email)
        if failures >= LOCKOUT_FAILURES:
            await self.store.log({**record, "ok": False, "reason": "locked"})
            raise HTTPException(429, "too many failed attempts; try again in 15 minutes")

        cap = self.captcha.verify(body.captcha)
        if not cap.ok:
            raise await self._fail(email, record, 400, f"CAPTCHA failed: {cap.reason}")

        a = self.store.get(email)
        # Same work whether or not the account exists, so timing doesn't reveal which emails are real.
        if not verify_password(a.password_hash if a else _DUMMY_HASH, body.password) or a is None:
            raise await self._fail(email, record, 401, "invalid email or password")

        risk = self.model.assess({
            "hour_shift": _hour_shift(a.login_hours, now.hour),
            "new_device": float(bool(a.devices) and record["device"] not in a.devices),
            "failures": float(failures),
            "solve_log_ms": math.log10(max(cap.solve_ms, 1.0)),
            "speed_cv": cap.speed_cv,
        })
        record["risk"] = {"score": risk.score, "threshold": risk.threshold, "features": risk.features}
        if risk.anomalous:
            raise await self._fail(email, record, 403, {
                "reason": "login blocked as anomalous", "reasons": risk.reasons,
                "score": risk.score, "threshold": risk.threshold})

        if record["device"] not in a.devices:
            a.devices = (a.devices + [record["device"]])[-20:]
        a.login_hours = (a.login_hours + [now.hour])[-HISTORY:]
        await self.store.save(a)
        self._failures.pop(email, None)
        await self.store.log({**record, "ok": True, "reason": "ok"})
        token, claims = issue_token(email, AUD_CONSOLE, self.settings.analyst_token_ttl_s,
                                    {"name": a.name, "role": "analyst"}, self.settings)
        return {"token": token, "expires_at": claims["exp"], "analyst": _out(a).model_dump(mode="json"),
                "login_risk": {"score": risk.score, "threshold": risk.threshold}}


# ---------------------------------------------------------------- router

router = APIRouter(prefix="/v1/auth", tags=["auth"])


def _auth(request: Request) -> AuthService:
    return request.app.state.auth


@router.post("/captcha")
def captcha(svc: AuthService = Depends(_auth)):
    """A single-use slider challenge (valid two minutes)."""
    return svc.captcha.challenge()


@router.post("/login")
async def login(body: LoginIn, request: Request, user_agent: str = Header(default=""),
                svc: AuthService = Depends(_auth)):
    return await svc.login(body, request.client.host if request.client else "", user_agent)


@router.get("/me", response_model=AnalystOut)
def me(authorization: str = Header(default=""), svc: AuthService = Depends(_auth)):
    try:
        claims = verify_token(authorization.removeprefix("Bearer ").strip(), AUD_CONSOLE, get_settings())
    except InvalidToken:
        raise HTTPException(401, "invalid or expired session") from None
    a = svc.store.get(claims["sub"])
    if a is None:
        raise HTTPException(401, "unknown analyst")
    return _out(a)


@router.get("/analysts", response_model=list[AnalystOut], dependencies=[Depends(require_operator)])
def list_analysts(svc: AuthService = Depends(_auth)):
    return [_out(a) for a in svc.store.all()]


@router.post("/analysts", response_model=AnalystOut, status_code=201, dependencies=[Depends(require_operator)])
async def create_analyst(body: AnalystIn, svc: AuthService = Depends(_auth)):
    if svc.store.get(body.email):
        raise HTTPException(409, "analyst already exists")
    return _out(await svc.create(body.email, body.name, body.password))
