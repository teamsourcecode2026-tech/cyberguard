"""
JWT Authentication module for CyberGuard.

Provides:
- create_access_token() — generate JWT tokens on login
- get_current_user() — FastAPI dependency to protect endpoints
- SECRET_KEY loaded from environment or uses a default for dev
"""
import os
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Configuration
SECRET_KEY = os.environ.get("CYBERGUARD_JWT_SECRET", "cyberguard-dev-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

security = HTTPBearer(auto_error=False)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT token with the given data payload."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS))
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict:
    """Verify and decode a JWT token. Returns the payload dict."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing subject",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> dict:
    """
    FastAPI dependency that extracts and validates the JWT token.
    Use as: Depends(get_current_user)

    Returns the decoded token payload (contains 'sub' = username).
    If no token is provided, allows access but returns None (for gradual rollout).
    """
    if credentials is None:
        # Gradual rollout: allow unauthenticated access for now
        # Change this to raise HTTPException once frontend sends tokens
        return None

    return verify_token(credentials.credentials)


async def require_auth(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> dict:
    """
    Strict version — REQUIRES a valid token. Use for sensitive endpoints.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return verify_token(credentials.credentials)
