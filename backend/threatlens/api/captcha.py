"""Slider CAPTCHA, verified on the server from the drag trajectory.

The client drags a piece along a track to a target. The server checks the signed,
single-use challenge, that the piece landed on the target, and that the movement
looks like a hand: a human speeds up and slows down and wobbles off the line;
a script tends to move at constant speed in a perfectly straight line.

ponytail: the target position is sent to the client (it draws the gap), so this stops
scripted logins by behaviour, not by hiding the answer. The login-anomaly model is the
second line. Used challenge ids live in memory (one process); Redis when scaled out.
"""

import math
import secrets
import time
from dataclasses import dataclass

from pydantic import BaseModel, Field

from threatlens.core.config import Settings
from threatlens.core.security import InvalidToken, issue_token, verify_token

AUD_CAPTCHA = "threatlens-captcha"
TRACK = 300  # px; the client scales its drawing to this
PIECE = 44
TOLERANCE = 6  # px
TTL_S = 120
MIN_MS, MAX_MS = 250, 30_000


class Point(BaseModel):
    t: float = Field(ge=0)  # ms since the drag started
    x: float
    y: float = 0.0


class CaptchaAnswer(BaseModel):
    token: str
    trajectory: list[Point] = Field(min_length=2, max_length=2000)


@dataclass
class CaptchaResult:
    ok: bool
    reason: str
    solve_ms: float = 0.0
    speed_cv: float = 0.0  # variation in drag speed (humans are uneven)
    y_wobble: float = 0.0  # px off the straight line


class CaptchaVerifier:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._used: dict[str, float] = {}  # jti -> expiry

    def challenge(self) -> dict:
        target = secrets.randbelow(TRACK - PIECE - 80) + 80  # never at the start
        token, _ = issue_token("captcha", AUD_CAPTCHA, TTL_S, {"target": target}, self.settings)
        return {"token": token, "target": target, "track": TRACK, "piece": PIECE, "tolerance": TOLERANCE,
                "expires_in": TTL_S}

    def verify(self, answer: CaptchaAnswer) -> CaptchaResult:
        try:
            claims = verify_token(answer.token, AUD_CAPTCHA, self.settings)
        except InvalidToken:
            return CaptchaResult(False, "challenge expired or invalid")
        now = time.time()
        self._used = {j: exp for j, exp in self._used.items() if exp > now}
        if claims["jti"] in self._used:
            return CaptchaResult(False, "challenge already used")
        self._used[claims["jti"]] = now + TTL_S

        pts = answer.trajectory
        if any(b.t < a.t for a, b in zip(pts, pts[1:])):
            return CaptchaResult(False, "trajectory out of order")
        solve_ms = pts[-1].t - pts[0].t
        speeds = [abs(b.x - a.x) / (b.t - a.t) for a, b in zip(pts, pts[1:]) if b.t > a.t]
        mean = sum(speeds) / len(speeds) if speeds else 0.0
        speed_cv = math.sqrt(sum((s - mean) ** 2 for s in speeds) / len(speeds)) / mean if mean else 0.0
        ys = [p.y for p in pts]
        y_wobble = max(ys) - min(ys)
        r = CaptchaResult(False, "", solve_ms, round(speed_cv, 3), round(y_wobble, 2))

        if abs(pts[-1].x - claims["target"]) > TOLERANCE:
            r.reason = "the piece did not reach the gap"
        elif not MIN_MS <= solve_ms <= MAX_MS:
            r.reason = "too fast" if solve_ms < MIN_MS else "too slow"
        elif len(speeds) < 8:
            r.reason = "too few movement samples"
        elif speed_cv < 0.15 and y_wobble < 0.5:
            r.reason = "movement looks scripted (constant speed, perfectly straight)"
        else:
            r.ok, r.reason = True, "ok"
        return r
