"""Per-credential rate limiting (per IP for login and for anonymous calls).

ponytail: fixed one-minute windows in process memory. Behind more than one API
instance this moves to Redis (INCR + EXPIRE), same keys.
"""

import hashlib
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

EXEMPT = ("/v1/health", "/metrics", "/docs", "/openapi.json")


class RateLimiter(BaseHTTPMiddleware):
    def __init__(self, app, per_min: int, auth_per_min: int):
        super().__init__(app)
        self.per_min, self.auth_per_min = per_min, auth_per_min
        self._windows: dict[str, tuple[int, int]] = {}  # key -> (minute, count)

    def _key(self, request) -> tuple[str, int]:
        ip = request.client.host if request.client else "?"
        if request.url.path.startswith("/v1/auth/"):
            return f"auth:{ip}", self.auth_per_min
        cred = request.headers.get("authorization") or request.headers.get("x-admin-key")
        if cred:
            return "cred:" + hashlib.sha256(cred.encode()).hexdigest()[:24], self.per_min
        return f"ip:{ip}", self.per_min

    async def dispatch(self, request, call_next):
        if request.url.path.startswith(EXEMPT) or request.method == "OPTIONS":
            return await call_next(request)
        key, limit = self._key(request)
        minute = int(time.time() // 60)
        start, count = self._windows.get(key, (minute, 0))
        if start != minute:
            start, count = minute, 0
        if count >= limit:
            retry = 60 - int(time.time() % 60)
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429, headers={"Retry-After": str(retry)})
        self._windows[key] = (start, count + 1)
        if len(self._windows) > 50_000:  # drop windows from earlier minutes
            self._windows = {k: v for k, v in self._windows.items() if v[0] == minute}
        return await call_next(request)
