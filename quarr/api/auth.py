"""
auth.py - Authentication & RBAC for the Web API (Phase 6, professional).

- Password hashing via passlib (bcrypt).
- JWT access/refresh tokens via PyJWT.
- A minimal in-memory user store seeded from Settings (admin) with optional
  additional users. Roles map to the Phase 4 permission roles.
"""

import secrets as _secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

import jwt
import bcrypt

from quarr.core.exceptions import QuarrError
from quarr.core.logging import get_logger

logger = get_logger("quarr.auth")

ROLES = ("viewer", "operator", "admin")

# bcrypt operates on the first 72 bytes of the password.
_BCRYPT_MAX = 72


def _prep(password: str) -> bytes:
    return password.encode("utf-8")[:_BCRYPT_MAX]


class AuthError(QuarrError):
    """Raised on authentication/authorization failures."""


@dataclass
class User:
    username: str
    password_hash: str
    role: str = "operator"


@dataclass
class UserStore:
    users: Dict[str, User] = field(default_factory=dict)

    def add(self, username: str, password: str, role: str = "operator") -> User:
        if role not in ROLES:
            raise AuthError("Invalid role", context={"role": role})
        user = User(username=username, password_hash=hash_password(password), role=role)
        self.users[username] = user
        return user

    def verify(self, username: str, password: str) -> Optional[User]:
        user = self.users.get(username)
        if not user:
            return None
        if verify_password(password, user.password_hash):
            return user
        return None


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prep(password), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_prep(password), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


class TokenService:
    def __init__(self, secret: str, algorithm: str = "HS256",
                 access_ttl_min: int = 30, refresh_ttl_min: int = 1440):
        self.secret = secret
        self.algorithm = algorithm
        self.access_ttl = timedelta(minutes=access_ttl_min)
        self.refresh_ttl = timedelta(minutes=refresh_ttl_min)

    def _make(self, sub: str, role: str, token_type: str, ttl: timedelta) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": sub,
            "role": role,
            "type": token_type,
            "iat": now,
            "exp": now + ttl,
        }
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def access_token(self, sub: str, role: str) -> str:
        return self._make(sub, role, "access", self.access_ttl)

    def refresh_token(self, sub: str, role: str) -> str:
        return self._make(sub, role, "refresh", self.refresh_ttl)

    def decode(self, token: str, expected_type: Optional[str] = None) -> dict:
        try:
            payload = jwt.decode(token, self.secret, algorithms=[self.algorithm])
        except jwt.ExpiredSignatureError as e:
            raise AuthError("Token expired", context={"reason": "expired"}) from e
        except jwt.InvalidTokenError as e:
            raise AuthError("Invalid token", context={"reason": "invalid"}) from e
        if expected_type and payload.get("type") != expected_type:
            raise AuthError("Wrong token type",
                            context={"expected": expected_type})
        return payload


class LoginRateLimiter:
    """Simple per-client sliding-window limiter for login attempts."""

    def __init__(self, max_per_min: int = 5, clock=None):
        self.max_per_min = max_per_min
        self._clock = clock or time.monotonic
        self._hits: Dict[str, list] = {}

    def check(self, client_id: str) -> bool:
        now = self._clock()
        hits = [t for t in self._hits.get(client_id, []) if now - t < 60.0]
        if len(hits) >= self.max_per_min:
            self._hits[client_id] = hits
            return False
        hits.append(now)
        self._hits[client_id] = hits
        return True


def build_user_store(settings) -> UserStore:
    """Seed a user store with the admin account from settings."""
    store = UserStore()
    password = settings.web_admin_password
    generated = False
    if not password:
        password = _secrets.token_urlsafe(16)
        generated = True
    store.add(settings.web_admin_user, password, role="admin")
    if generated:
        # Log once at startup so the operator can retrieve the credential.
        logger.warning("admin_password_generated",
                       username=settings.web_admin_user,
                       password=password)
    return store
