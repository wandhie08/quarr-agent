"""
security.py - FastAPI security dependencies (Phase 6 professional).

Wires the auth module into FastAPI: bearer-token extraction, current-user
resolution, and role-based access control dependencies.
"""

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from quarr.api.auth import AuthError, TokenService, UserStore, LoginRateLimiter
from quarr.core.config import Settings

_bearer = HTTPBearer(auto_error=False)

# Module-level singletons initialized by init_security().
_settings: Settings | None = None
_token_service: TokenService | None = None
_user_store: UserStore | None = None
_rate_limiter: LoginRateLimiter | None = None

_ROLE_ORDER = {"viewer": 0, "operator": 1, "admin": 2}


def init_security(settings: Settings, user_store: UserStore) -> None:
    global _settings, _token_service, _user_store, _rate_limiter
    _settings = settings
    _user_store = user_store
    _token_service = TokenService(
        secret=settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        access_ttl_min=settings.jwt_access_ttl_min,
        refresh_ttl_min=settings.jwt_refresh_ttl_min,
    )
    _rate_limiter = LoginRateLimiter(max_per_min=settings.login_rate_limit)


def token_service() -> TokenService:
    if _token_service is None:
        raise RuntimeError("security not initialized")
    return _token_service


def user_store() -> UserStore:
    if _user_store is None:
        raise RuntimeError("security not initialized")
    return _user_store


def rate_limiter() -> LoginRateLimiter:
    if _rate_limiter is None:
        raise RuntimeError("security not initialized")
    return _rate_limiter


def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
) -> dict:
    if creds is None or not creds.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = token_service().decode(creds.credentials, expected_type="access")
    except AuthError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e.message),
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
    return {"username": payload["sub"], "role": payload["role"]}


def require_role(minimum: str):
    """Dependency factory enforcing a minimum role."""

    def _dep(user: dict = Depends(get_current_user)) -> dict:
        if _ROLE_ORDER.get(user["role"], -1) < _ROLE_ORDER.get(minimum, 99):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role '{minimum}' or higher",
            )
        return user

    return _dep


def client_id(request: Request) -> str:
    return request.client.host if request.client else "unknown"
