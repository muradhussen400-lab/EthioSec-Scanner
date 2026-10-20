import os
import re
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Tuple, Optional
import argon2
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from database import get_db
from models import User

load_dotenv()

logger = logging.getLogger("ethiosec.security")

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "supersecretethioskey_replace_me_in_production")
ALGORITHM = "HS256"
# Short-lived token default (60 minutes) to minimize token theft window
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

def is_email_verification_required() -> bool:
    return os.getenv("REQUIRE_EMAIL_VERIFICATION", "true").strip().lower() == "true"

class _RequireEmailVerificationProxy:
    def __bool__(self):
        return is_email_verification_required()
    def __eq__(self, other):
        return bool(self) == bool(other)

REQUIRE_EMAIL_VERIFICATION = _RequireEmailVerificationProxy()

# Primary Password Hasher: Argon2id (OWASP recommended)
argon2_hasher = argon2.PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)

# Legacy bcrypt context for backward-compatibility with existing accounts
legacy_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """
    Validates server-side password strength against OWASP ASVS guidelines:
    - Minimum length 8 characters
    - Maximum length 128 characters (prevents ReDoS/memory exhaustion)
    - Must contain at least one lowercase letter, one uppercase letter, and one number.
    """
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    return True, None

def verify_password(plain_password: str, hashed_password: str) -> Tuple[bool, bool]:
    """
    Verifies a plaintext password against its hash.
    Supports Argon2id natively and falls back to legacy bcrypt.
    Returns (is_valid, needs_rehash).
    """
    if not hashed_password or not plain_password:
        return False, False

    # Check for Argon2id
    if hashed_password.startswith("$argon2"):
        try:
            argon2_hasher.verify(hashed_password, plain_password)
            needs_rehash = argon2_hasher.check_needs_rehash(hashed_password)
            return True, needs_rehash
        except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.VerificationError):
            return False, False
        except Exception as e:
            logger.error(f"Argon2 verification unexpected error: {e}")
            return False, False

    # Fallback to legacy bcrypt (with sha256 pre-hash)
    try:
        pre_hashed = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
        is_valid = legacy_pwd_context.verify(pre_hashed[:72], hashed_password)
        # If valid with legacy bcrypt, flag that it needs upgrade to Argon2id
        return is_valid, True
    except Exception as e:
        logger.error(f"Legacy bcrypt verification error: {e}")
        return False, False

def get_password_hash(password: str) -> str:
    """Hash password using Argon2id."""
    return argon2_hasher.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Generate a signed JWT token containing subject, issued-at, and expiry."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": now.timestamp()
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """
    Validates token signature, expiration, and session revocation.
    Returns authenticated User model.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        token_iat: Optional[float] = payload.get("iat")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email.strip().lower()).first()
    if user is None:
        raise credentials_exception

    # Check for temporary account lockout
    if user.locked_until:
        try:
            locked_time = datetime.fromisoformat(user.locked_until)
            if datetime.now(timezone.utc) < locked_time:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is temporarily locked due to multiple failed login attempts. Please try again later."
                )
        except (ValueError, TypeError):
            pass

    # Check for session revocation (e.g. after password reset or logout)
    if user.session_revoked_at and token_iat is not None:
        try:
            revoked_time = datetime.fromisoformat(user.session_revoked_at)
            token_time = datetime.fromtimestamp(token_iat, tz=timezone.utc)
            # If token_iat contains subseconds, compare exact time.
            # Otherwise (legacy integer tokens), compare at second resolution.
            if isinstance(token_iat, float) and not token_iat.is_integer():
                is_revoked = token_time < revoked_time
            else:
                is_revoked = int(token_time.timestamp()) < int(revoked_time.timestamp())

            if is_revoked:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session has been revoked. Please log in again.",
                    headers={"WWW-Authenticate": "Bearer"}
                )
        except (ValueError, TypeError):
            pass

    return user

def get_current_verified_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Ensures that the authenticated user has verified their email address
    before allowing access to protected scanner and report endpoints.
    """
    if REQUIRE_EMAIL_VERIFICATION and not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification required. Please verify your email to access this feature.",
            headers={"X-Error-Code": "EMAIL_NOT_VERIFIED"}
        )
    return current_user