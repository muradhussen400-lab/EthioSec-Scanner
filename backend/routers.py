from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request, status, Response
from fastapi.responses import RedirectResponse, StreamingResponse
from sqlalchemy.orm import Session
from typing import List, Any, Optional, Dict
import datetime
import time
from urllib.parse import urlparse
import uuid
import os
import json
import csv
import io
import httpx
import secrets
import string
import logging
import base64
import hashlib
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

from database import get_db
from models import User, Scan, ScanTarget, Finding, UserSettings, ScanModule, Report, Notification, AuditLog
from schemas import (
    UserRegister, UserLogin, UserOut, UserProfileUpdate, TokenResponse,
    VerifyEmailRequest, ResendVerificationRequest, ForgotPasswordRequest, ResetPasswordRequest, ChangePasswordRequest, MessageResponse,
    GoogleExchangeRequest, TargetCreate, TargetOut,
    ScanCreate, ScanStatusOut, ScanResultOut, FindingOut, DashboardSummaryOut, DashboardTrend, ScanCounts,
    AIRequest, AIResponse, UserSettingsUpdate, UserSettingsOut, AIAssistantRequestNew,
    PhoneSendCodeRequest, PhoneVerifyCodeRequest, PhoneStatusOut
)
from security import (
    get_password_hash, verify_password, create_access_token,
    get_current_user, get_current_verified_user,
    timedelta, ACCESS_TOKEN_EXPIRE_MINUTES, REQUIRE_EMAIL_VERIFICATION
)
from email_service import email_service, hash_verification_secret, verify_secret_hash
from phone_service import phone_service
from rate_limiter import (
    limit_login, limit_register, limit_verify, limit_resend, limit_reset, limit_scans, limit_ai,
    limit_phone_send, limit_phone_verify, _limiter
)
# Backward-compatibility alias for legacy test fixtures
request_counts = _limiter._records
from scanner.engine import run_scan_task
from ai.executive_summary import aggregate_finding_counts

# Configure audit logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
audit_logger = logging.getLogger("ethiosec.audit")

router = APIRouter()

# ==============================================================================
# AUTHENTICATION & EMAIL VERIFICATION
# ==============================================================================

@router.post("/auth/register", response_model=TokenResponse, dependencies=[Depends(limit_register)])
def register(user_in: UserRegister, db: Session = Depends(get_db)):
    email_norm = user_in.email.strip().lower()
    
    existing_user = db.query(User).filter(User.email == email_norm).first()
    if existing_user:
        audit_logger.warning(f"Registration attempted with existing email: {email_norm}")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")
    
    # Generate verification code
    code = email_service.generate_verification_code()
    code_hash = hash_verification_secret(code)
    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = (now + datetime.timedelta(minutes=15)).isoformat()
    
    new_user = User(
        email=email_norm,
        full_name=user_in.full_name,
        website=user_in.website,
        password_hash=get_password_hash(user_in.password),
        role="Security Administrator",
        is_verified=not REQUIRE_EMAIL_VERIFICATION, # False when verification required
        verification_code_hash=code_hash,
        verification_expires_at=expires_at,
        verification_attempts=0,
        verification_sent_at=now.isoformat()
    )
    db.add(new_user)
    
    # Send verification email if required
    if REQUIRE_EMAIL_VERIFICATION:
        sent = email_service.send_verification_email(new_user.email, code)
        if not sent:
            db.rollback()
            audit_logger.error(f"Registration aborted: Email delivery failed for {new_user.email}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Unable to send verification email. Please check your email configuration or try again later."
            )
    
    db.commit()
    db.refresh(new_user)
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": new_user.email, "is_verified": new_user.is_verified},
        expires_delta=access_token_expires
    )
    audit_logger.info(f"User registered successfully: {new_user.email} (verified={new_user.is_verified})")
    return {"token": access_token, "user": new_user}

@router.post("/auth/verify-email", response_model=TokenResponse, dependencies=[Depends(limit_verify)])
def verify_email(req: VerifyEmailRequest, db: Session = Depends(get_db)):
    email_norm = req.email.strip().lower()
    user = db.query(User).filter(User.email == email_norm).first()
    
    generic_error = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid or expired verification code."
    )
    
    if not user:
        raise generic_error
        
    if user.is_verified:
        # Already verified, generate fresh token
        token = create_access_token(data={"sub": user.email, "is_verified": True})
        return {"token": token, "user": user}
        
    # Check max attempt limit
    if user.verification_attempts >= 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum verification attempts exceeded. Please request a new verification code."
        )
        
    # Check expiration
    now = datetime.datetime.now(datetime.timezone.utc)
    if not user.verification_expires_at:
        raise generic_error
        
    try:
        expires_time = datetime.datetime.fromisoformat(user.verification_expires_at)
        if now > expires_time:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Verification code has expired. Please request a new code."
            )
    except (ValueError, TypeError):
        raise generic_error

    # Verify secret hash with constant-time comparison
    if not verify_secret_hash(req.code, user.verification_code_hash):
        user.verification_attempts += 1
        db.commit()
        audit_logger.warning(f"Failed verification attempt for user: {user.email}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification code.")

    # Successful verification - activate account atomically
    user.is_verified = True
    user.verification_code_hash = None
    user.verification_expires_at = None
    user.verification_attempts = 0
    db.commit()
    db.refresh(user)

    audit_logger.info(f"User email verified successfully: {user.email}")
    token = create_access_token(data={"sub": user.email, "is_verified": True})
    return {"token": token, "user": user}

@router.post("/auth/resend-verification", response_model=MessageResponse, dependencies=[Depends(limit_resend)])
def resend_verification(req: ResendVerificationRequest, db: Session = Depends(get_db)):
    email_norm = req.email.strip().lower()
    user = db.query(User).filter(User.email == email_norm).first()
    
    # Uniform response to avoid account enumeration
    success_msg = MessageResponse(message="If an unverified account exists for this email, a new verification code has been sent.")
    
    if not user or user.is_verified:
        return success_msg

    now = datetime.datetime.now(datetime.timezone.utc)
    
    # Enforce 60-second cooldown
    if user.verification_sent_at:
        try:
            last_sent = datetime.datetime.fromisoformat(user.verification_sent_at)
            if (now - last_sent).total_seconds() < 60:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Please wait 60 seconds before requesting another verification code."
                )
        except (ValueError, TypeError):
            pass

    # Generate new code, invalidating previous code
    code = email_service.generate_verification_code()
    user.verification_code_hash = hash_verification_secret(code)
    user.verification_expires_at = (now + datetime.timedelta(minutes=15)).isoformat()
    user.verification_attempts = 0
    user.verification_sent_at = now.isoformat()

    sent = email_service.send_verification_email(user.email, code)
    if not sent:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to send verification email. Please check your email configuration or try again later."
        )

    db.commit()
    audit_logger.info(f"Resent verification code to: {user.email}")
    return success_msg

@router.post("/auth/login", response_model=TokenResponse, dependencies=[Depends(limit_login)])
def login(user_in: UserLogin, db: Session = Depends(get_db)):
    email_norm = user_in.email.strip().lower()
    user = db.query(User).filter(User.email == email_norm).first()
    now = datetime.datetime.now(datetime.timezone.utc)

    # Check for active account lockout
    if user and user.locked_until:
        try:
            locked_time = datetime.datetime.fromisoformat(user.locked_until)
            if now < locked_time:
                audit_logger.warning(f"Login attempt on locked account: {email_norm}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is temporarily locked due to multiple failed login attempts. Please try again later."
                )
            else:
                user.failed_login_attempts = 0
                user.locked_until = None
                db.commit()
        except (ValueError, TypeError):
            pass

    if not user:
        audit_logger.warning(f"Failed login attempt for non-existent email: {email_norm}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    is_valid, needs_rehash = verify_password(user_in.password, user.password_hash)
    if not is_valid:
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.locked_until = (now + datetime.timedelta(minutes=15)).isoformat()
            audit_logger.warning(f"Account temporarily locked for 15 minutes due to failed logins: {user.email}")
        db.commit()
        audit_logger.warning(f"Failed login attempt for email: {user.email}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    # Successful credentials: reset failed count
    user.failed_login_attempts = 0
    user.locked_until = None
    
    # Automatically upgrade legacy bcrypt hashes to Argon2id
    if needs_rehash:
        user.password_hash = get_password_hash(user_in.password)
        audit_logger.info(f"Transparently upgraded password hash to Argon2id for: {user.email}")
    db.commit()
    db.refresh(user)

    # Check email verification status
    if REQUIRE_EMAIL_VERIFICATION and not user.is_verified:
        audit_logger.info(f"Unverified user login attempt: {user.email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified. Please verify your email before logging in.",
            headers={"X-Error-Code": "EMAIL_NOT_VERIFIED"}
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "is_verified": user.is_verified},
        expires_delta=access_token_expires
    )
    audit_logger.info(f"User logged in successfully: {user.email}")
    return {"token": access_token, "user": user}

@router.post("/auth/logout", response_model=MessageResponse)
def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Revokes the current session by invalidating tokens issued prior to this timestamp."""
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    current_user.session_revoked_at = now
    db.commit()
    audit_logger.info(f"User logged out and session revoked: {current_user.email}")
    return MessageResponse(message="Logged out successfully. All active sessions have been revoked.")

@router.post("/auth/forgot-password", response_model=MessageResponse, dependencies=[Depends(limit_reset)])
def forgot_password(req: ForgotPasswordRequest, db: Session = Depends(get_db)):
    email_norm = req.email.strip().lower()
    user = db.query(User).filter(User.email == email_norm).first()
    
    # Constant response to prevent account enumeration
    response = MessageResponse(message="If an account with that email exists, password reset instructions have been sent.")
    
    if not user:
        return response
        
    now = datetime.datetime.now(datetime.timezone.utc)
    token = email_service.generate_reset_token()
    user.reset_token_hash = hash_verification_secret(token)
    user.reset_expires_at = (now + datetime.timedelta(minutes=15)).isoformat()
    user.reset_attempts = 0

    sent = email_service.send_password_reset_email(user.email, token)
    if not sent:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to send password reset email at this time. Please try again later."
        )

    db.commit()
    audit_logger.info(f"Password reset token issued for: {user.email}")
    return response

@router.post("/auth/reset-password", response_model=MessageResponse, dependencies=[Depends(limit_reset)])
def reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    email_norm = req.email.strip().lower()
    user = db.query(User).filter(User.email == email_norm).first()
    generic_error = HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token.")
    
    if not user or not user.reset_token_hash or not user.reset_expires_at:
        raise generic_error
        
    if user.reset_attempts >= 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum reset attempts exceeded. Please request a new password reset."
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        expires_time = datetime.datetime.fromisoformat(user.reset_expires_at)
        if now > expires_time:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password reset token has expired.")
    except (ValueError, TypeError):
        raise generic_error

    if not verify_secret_hash(req.token, user.reset_token_hash):
        user.reset_attempts += 1
        db.commit()
        audit_logger.warning(f"Failed password reset attempt for: {user.email}")
        raise generic_error

    # Valid reset: update password to Argon2id, clear secret, and revoke all active sessions
    user.password_hash = get_password_hash(req.new_password)
    user.reset_token_hash = None
    user.reset_expires_at = None
    user.reset_attempts = 0
    user.session_revoked_at = now.isoformat()
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()
    
    audit_logger.info(f"Password successfully reset and sessions revoked for: {user.email}")
    return MessageResponse(message="Password reset successful. Please log in with your new password.")

@router.post("/auth/change-password", response_model=MessageResponse)
def change_password(req: ChangePasswordRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    is_valid, _ = verify_password(req.current_password, user.password_hash)
    if not is_valid:
        audit_logger.warning(f"Failed password change attempt: incorrect current password for {user.email}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect current password.")
        
    now = datetime.datetime.now(datetime.timezone.utc)
    user.password_hash = get_password_hash(req.new_password)
    user.session_revoked_at = now.isoformat()
    db.commit()
    audit_logger.info(f"Password successfully changed for: {user.email}")
    return MessageResponse(message="Password successfully updated.")

@router.get("/auth/me")
def read_users_me(current_user: User = Depends(get_current_user)):
    return {"user": current_user}

# Ephemeral OAuth state and exchange code stores with automatic cleanup
_oauth_states: Dict[str, Dict[str, Any]] = {}
_oauth_exchange_codes: Dict[str, Dict[str, Any]] = {}

def _cleanup_oauth_stores():
    now = time.time()
    expired_states = [s for s, data in _oauth_states.items() if now - data.get("created_at", 0) > 600]
    for s in expired_states:
        _oauth_states.pop(s, None)
    expired_codes = [c for c, data in _oauth_exchange_codes.items() if now - data.get("created_at", 0) > 60]
    for c in expired_codes:
        _oauth_exchange_codes.pop(c, None)

@router.get("/auth/google/login")
def google_login(request: Request):
    """
    Initiates Google OAuth 2.0 / OpenID Connect authentication using PKCE and secure state.
    """
    _cleanup_oauth_stores()
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "http://127.0.0.1:8000/api/auth/google/callback")
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5500").rstrip("/")
    
    if not client_id or not client_secret:
        audit_logger.warning("Google login requested but credentials are not configured on the server.")
        return RedirectResponse(f"{frontend_url}/login.html?oauth_error=not_configured")

    # Cryptographically secure state (CSRF mitigation)
    state = secrets.token_urlsafe(32)
    # PKCE (Proof Key for Code Exchange)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('ascii')).digest()).decode('ascii').rstrip('=')

    _oauth_states[state] = {
        "code_verifier": code_verifier,
        "created_at": time.time()
    }

    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?"
        f"response_type=code"
        f"&client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&scope=openid%20email%20profile"
        f"&state={state}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
        f"&access_type=offline"
        f"&prompt=select_account"
    )
    return RedirectResponse(auth_url)

@router.get("/auth/google/callback")
async def google_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Handles Google OAuth callback:
    1. Validates state and PKCE code_verifier (CSRF & replay protection)
    2. Exchanges authorization code for tokens
    3. Validates Google ID token signature, issuer, audience, and email_verified
    4. Identifies user by stable Google subject identifier (sub)
    5. Performs safe account linking or new registration
    6. Establishes session safely using a short-lived single-use exchange ticket (no JWT in URL)
    """
    _cleanup_oauth_stores()
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5500").rstrip("/")
    
    # 1. Handle user cancellation or provider errors
    if error:
        audit_logger.warning(f"Google OAuth provider returned error: {error}")
        return RedirectResponse(f"{frontend_url}/login.html?oauth_error={error}")

    if not code or not state:
        audit_logger.warning("Google OAuth callback invoked with missing code or state parameter.")
        return RedirectResponse(f"{frontend_url}/login.html?oauth_error=invalid_request")

    # 2. Validate state & retrieve PKCE verifier (single-use delete)
    state_data = _oauth_states.pop(state, None)
    if not state_data or (time.time() - state_data.get("created_at", 0) > 600):
        audit_logger.warning(f"Google OAuth state mismatch or expired: state={state}")
        return RedirectResponse(f"{frontend_url}/login.html?oauth_error=invalid_state")

    code_verifier = state_data.get("code_verifier")
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "http://127.0.0.1:8000/api/auth/google/callback")

    # 3. Exchange authorization code for tokens
    token_url = "https://oauth2.googleapis.com/token"
    token_payload = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
        "code_verifier": code_verifier,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as http_client:
            token_res = await http_client.post(token_url, data=token_payload)
            if token_res.status_code != 200:
                audit_logger.error(f"Google token exchange failed: HTTP {token_res.status_code} - {token_res.text}")
                return RedirectResponse(f"{frontend_url}/login.html?oauth_error=token_exchange_failed")
            token_data = token_res.json()
    except Exception as exc:
        audit_logger.error(f"Exception during Google token exchange: {exc}")
        return RedirectResponse(f"{frontend_url}/login.html?oauth_error=network_error")

    raw_id_token = token_data.get("id_token")
    if not raw_id_token:
        audit_logger.error("No ID token returned by Google OAuth token endpoint.")
        return RedirectResponse(f"{frontend_url}/login.html?oauth_error=missing_id_token")

    # 4. Strictly validate Google ID Token signature, issuer, audience, and expiry
    try:
        id_info = google_id_token.verify_oauth2_token(
            raw_id_token,
            google_requests.Request(),
            client_id
        )
    except Exception as val_err:
        audit_logger.error(f"Google ID token cryptographic validation failed: {val_err}")
        return RedirectResponse(f"{frontend_url}/login.html?oauth_error=invalid_token")

    # 5. Verify email_verified claim
    if not id_info.get("email_verified"):
        audit_logger.warning(f"Google user email is not verified by Google: {id_info.get('email')}")
        return RedirectResponse(f"{frontend_url}/login.html?oauth_error=unverified_google_email")

    # 6. Extract claims with stable subject identifier
    google_sub = str(id_info.get("sub", "")).strip()
    email = str(id_info.get("email", "")).strip().lower()
    full_name = id_info.get("name") or (email.split("@")[0] if email else "Google User")
    avatar_url = id_info.get("picture")

    if not google_sub or not email:
        return RedirectResponse(f"{frontend_url}/login.html?oauth_error=invalid_claims")

    # 7. Account Resolution & Safe Account Linking
    user = db.query(User).filter(User.google_id == google_sub).first()
    
    if not user:
        # Check if account already exists with this verified email
        existing_email_user = db.query(User).filter(User.email == email).first()
        if existing_email_user:
            if existing_email_user.google_id and existing_email_user.google_id != google_sub:
                audit_logger.warning(f"Account collision: {email} already linked to different Google sub.")
                return RedirectResponse(f"{frontend_url}/login.html?oauth_error=account_linked_to_different_google_id")
            
            # Safe account linking for verified email
            user = existing_email_user
            user.google_id = google_sub
            user.is_verified = True # Google has confirmed email ownership
            if not user.full_name and full_name:
                user.full_name = full_name
            if not user.avatar_url and avatar_url:
                user.avatar_url = avatar_url
            db.commit()
            audit_logger.info(f"Safely linked Google identity (sub={google_sub}) to existing user: {user.email}")
        else:
            # Brand-new user registration via Google OAuth
            # Password hash is initialized to an unusable random string
            random_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
            user = User(
                email=email,
                full_name=full_name,
                google_id=google_sub,
                auth_provider="google",
                avatar_url=avatar_url,
                password_hash=get_password_hash(random_password),
                role="Security Administrator", # Default standard role, no client escalation
                is_verified=True
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            audit_logger.info(f"New user created via Google OAuth: {user.email} (sub={google_sub})")

    # Reset failed login count and lockout if previously locked
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    # 8. Issue JWT and one-time single-use exchange code (eliminates JWT token in URL)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    jwt_token = create_access_token(
        data={"sub": user.email, "is_verified": user.is_verified},
        expires_delta=access_token_expires
    )
    
    exchange_code = secrets.token_urlsafe(32)
    _oauth_exchange_codes[exchange_code] = {
        "token": jwt_token,
        "user": UserOut.model_validate(user).model_dump(),
        "created_at": time.time()
    }

    audit_logger.info(f"Google OAuth authentication successful for user: {user.email}")
    return RedirectResponse(f"{frontend_url}/login.html?oauth_code={exchange_code}")

@router.post("/auth/google/exchange", response_model=TokenResponse)
def google_exchange(req: GoogleExchangeRequest):
    """
    Exchanges a single-use 60-second authorization code for a session token.
    Prevents token exposure in URLs and browser history.
    """
    _cleanup_oauth_stores()
    exchange_data = _oauth_exchange_codes.pop(req.code, None)
    if not exchange_data or (time.time() - exchange_data.get("created_at", 0) > 60):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired Google OAuth exchange code."
        )
    return {"token": exchange_data["token"], "user": exchange_data["user"]}

# ==============================================================================
# PHONE NUMBER VERIFICATION (SMS OTP PROVIDER)
# ==============================================================================

@router.post("/auth/phone/send-code", response_model=MessageResponse, dependencies=[Depends(limit_phone_send)])
async def send_phone_code(
    req: PhoneSendCodeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Sends an SMS verification code to the specified phone number via the configured provider (Twilio Verify)
    or safe development simulation.
    Enforces E.164 normalization, cooldown, and ownership validation.
    """
    is_valid, normalized_phone, err_msg = phone_service.normalize_and_validate(req.phone_number)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)

    # Prevent phone number hijacking: check if already verified by another user
    existing_owner = db.query(User).filter(
        User.phone_number == normalized_phone,
        User.phone_verified == True,
        User.id != current_user.id
    ).first()
    if existing_owner:
        audit_logger.warning(f"Phone verification attempted for already verified number: {normalized_phone[:5]}***")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This phone number is already verified and linked to another account."
        )

    # Check 60-second resend cooldown on user record
    now = datetime.datetime.now(datetime.timezone.utc)
    if current_user.phone_verification_sent_at:
        try:
            last_sent = datetime.datetime.fromisoformat(current_user.phone_verification_sent_at)
            elapsed = (now - last_sent).total_seconds()
            if elapsed < 60:
                retry_after = int(60 - elapsed)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Please wait {retry_after} seconds before requesting another SMS verification code.",
                    headers={"Retry-After": str(retry_after)}
                )
        except (ValueError, TypeError):
            pass

    success, msg, meta = await phone_service.send_verification_code(normalized_phone)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    current_user.phone_number = normalized_phone
    current_user.phone_verification_sent_at = now.isoformat()
    current_user.phone_verification_attempts = 0
    db.commit()

    audit_logger.info(f"Phone verification code dispatched to {normalized_phone[:5]}*** for user {current_user.email}")
    return MessageResponse(
        message=msg,
        detail=f"Provider: {meta.get('provider', 'standard')} (Real Provider: {meta.get('is_real_provider', False)})"
    )

@router.post("/auth/phone/verify-code", response_model=PhoneStatusOut, dependencies=[Depends(limit_phone_verify)])
async def verify_phone_code(
    req: PhoneVerifyCodeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verifies the submitted SMS code with the provider.
    Marks phone_verified=True on successful validation.
    """
    is_valid, normalized_phone, err_msg = phone_service.normalize_and_validate(req.phone_number)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)

    # Check brute-force attempt limits
    if current_user.phone_verification_attempts >= 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum verification attempts exceeded for this phone number. Please request a new code."
        )

    success, msg, meta = await phone_service.verify_code(normalized_phone, req.code)
    if not success:
        current_user.phone_verification_attempts += 1
        db.commit()
        audit_logger.warning(f"Failed phone verification attempt for user {current_user.email}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    now = datetime.datetime.now(datetime.timezone.utc)
    current_user.phone_number = normalized_phone
    current_user.phone_verified = True
    current_user.phone_verified_at = now.isoformat()
    current_user.phone_verification_attempts = 0
    db.commit()
    db.refresh(current_user)

    audit_logger.info(f"Phone {normalized_phone[:5]}*** successfully verified for user {current_user.email}")
    return PhoneStatusOut(
        phone_number=current_user.phone_number,
        phone_verified=current_user.phone_verified,
        phone_verified_at=current_user.phone_verified_at,
        provider=meta.get("provider"),
        is_real_provider=meta.get("is_real_provider", False)
    )

@router.get("/auth/phone/status", response_model=PhoneStatusOut)
def get_phone_status(current_user: User = Depends(get_current_user)):
    """Retrieves current user's phone verification status and configured provider."""
    return PhoneStatusOut(
        phone_number=current_user.phone_number,
        phone_verified=bool(current_user.phone_verified),
        phone_verified_at=current_user.phone_verified_at,
        provider="twilio_verify" if phone_service.is_provider_configured else "mock_development_simulation",
        is_real_provider=phone_service.is_provider_configured
    )


# ==============================================================================
# DASHBOARD (Requires Verified User)
# ==============================================================================

@router.get("/dashboard/summary", response_model=DashboardSummaryOut)
def dashboard_summary(range: str = "week", current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(
        Scan.user_id == current_user.id,
        Scan.status.in_(["completed", "completed_with_errors"])
    ).order_by(Scan.created_at.desc()).all()
    
    if not scans:
        trend = DashboardTrend(
            labels=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
            mine=[0]*7, all=[0]*7, trendLabels=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], trend=[0]*7,
            websites=0, requests=0, response=0
        )
        return DashboardSummaryOut(
            security_score=0, last_scan=None, last_target=None,
            vulnerabilities=0, warnings=0, passed_checks=0, issues=0, total_scans=0,
            breakdown={"security": 0, "performance": 0, "seo": 0},
            range=trend
        )

    latest = scans[0]
    total_scans = len(scans)
    
    findings = db.query(Finding).filter(Finding.scan_id == latest.id).all()
    c = aggregate_finding_counts(findings, scan=latest)

    trend = DashboardTrend(
        labels=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        mine=[1]*7, all=[2]*7, trendLabels=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], trend=[75]*7,
        websites=len(set([urlparse(s.target_url).hostname or s.target_url for s in scans])), requests=total_scans*120, response=180
    )
    
    return DashboardSummaryOut(
        security_score=latest.security_score or 0,
        last_scan=latest.finished_at or latest.created_at,
        last_target=latest.target_url,
        vulnerabilities=c["high"],
        warnings=c["medium"] + c["low"],
        passed_checks=c["not_detected"],
        issues=c["total"],
        total_scans=total_scans,
        breakdown={"security": latest.security_score or 0, "performance": max(40, (latest.security_score or 0) - 7), "seo": min(100, (latest.security_score or 0) + 3)},
        range=trend
    )

# ==============================================================================
# SCAN TARGETS (Requires Verified User)
# ==============================================================================

@router.post("/targets", response_model=TargetOut)
def create_target(target_in: TargetCreate, current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    parsed = urlparse(target_in.url)
    if parsed.scheme not in ["http", "https"]:
        raise HTTPException(status_code=400, detail="Target URL must use http or https scheme")
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Invalid target URL structure")
    
    target = ScanTarget(user_id=current_user.id, url=target_in.url, authorized=False)
    db.add(target)
    db.commit()
    db.refresh(target)
    return target

@router.get("/targets", response_model=List[TargetOut])
def list_targets(current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    return db.query(ScanTarget).filter(ScanTarget.user_id == current_user.id).all()

@router.get("/targets/{id}", response_model=TargetOut)
def get_target(id: str, current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    target = db.query(ScanTarget).filter(ScanTarget.id == id, ScanTarget.user_id == current_user.id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target

@router.delete("/targets/{id}")
def delete_target(id: str, current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    target = db.query(ScanTarget).filter(ScanTarget.id == id, ScanTarget.user_id == current_user.id).first()
    if target:
        db.delete(target)
        db.commit()
    return {"ok": True}

# ==============================================================================
# SCANS (Requires Verified User & Ownership Isolation)
# ==============================================================================

@router.post("/scans", dependencies=[Depends(limit_scans)])
def create_scan(scan_in: ScanCreate, current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    if not scan_in.authorized:
        raise HTTPException(status_code=403, detail="You must authorize the scan")
        
    target = db.query(ScanTarget).filter(ScanTarget.id == scan_in.target_id, ScanTarget.user_id == current_user.id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    chosen_depth = scan_in.depth
    if not chosen_depth:
        user_settings = db.query(UserSettings).filter(UserSettings.user_id == current_user.id).first()
        if user_settings and user_settings.default_scan_depth:
            chosen_depth = user_settings.default_scan_depth
    chosen_depth = (chosen_depth or "standard").lower()

    new_scan = Scan(
        user_id=current_user.id,
        target_url=target.url,
        depth=chosen_depth,
        modules=scan_in.modules or {},
        status="queued",
        auth_context_1=scan_in.auth_context_1,
        auth_context_2=scan_in.auth_context_2
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    audit_logger.info(f"Scan created (ID: {new_scan.id}) by user {current_user.email} for target {target.url}")
    return {"scan_id": new_scan.id, "status": new_scan.status}

@router.post("/scans/{id}/start", dependencies=[Depends(limit_scans)])
def start_scan(id: str, background_tasks: BackgroundTasks, current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status != "queued":
        raise HTTPException(status_code=400, detail="Scan is already running or completed")
        
    scan.status = "running"
    db.commit()
    
    background_tasks.add_task(run_scan_task, scan.id)
    audit_logger.info(f"Scan started (ID: {scan.id}) by user {current_user.email}")
    return {"scan_id": scan.id, "status": "started"}

@router.post("/scans/{id}/cancel")
def cancel_scan(id: str, current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("completed", "failed", "cancelled", "completed_with_errors"):
        scan.status = "cancelled"
        scan.stage = "Scan cancelled by user"
        scan.finished_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        db.commit()
    return {"ok": True, "status": scan.status, "message": "Scan cancelled"}

@router.get("/scans")
def list_scans(limit: int = 100, current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()).limit(limit).all()
    
    scan_list = []
    for s in scans:
        findings = db.query(Finding).filter(Finding.scan_id == s.id).all()
        c = aggregate_finding_counts(findings, scan=s)
        
        scan_list.append({
            "id": s.id,
            "target": s.target_url,
            "status": s.status,
            "depth": s.depth,
            "created_at": s.created_at,
            "finished_at": s.finished_at,
            "security_score": s.security_score,
            "counts": c
        })
    return {"scans": scan_list, "total": len(scan_list)}

@router.delete("/scans")
def delete_all_scans(current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(Scan.user_id == current_user.id).all()
    count = len(scans)
    for s in scans:
        db.delete(s)
    db.commit()
    audit_logger.info(f"All scans ({count}) deleted by user {current_user.email}")
    return {"status": "success", "message": f"Deleted {count} scans"}

@router.get("/scans/{id}/status", response_model=ScanStatusOut)
def scan_status(id: str, current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    c = aggregate_finding_counts(findings, scan=scan)
    
    req_modules = scan.modules if (scan.modules and isinstance(scan.modules, dict)) else {}
    exec_checks = scan.checks if (scan.checks and isinstance(scan.checks, dict)) else {}
    
    # Extract detailed telemetry if available
    module_details = exec_checks.get("module_details")
    if not module_details:
        from scanner.registry import CANONICAL_MODULES, resolve_module_selection
        resolved = resolve_module_selection(req_modules)
        module_details = {
            mod_id: {
                "id": mod_id,
                "name": meta["name"],
                "description": meta["description"],
                "category": meta["owasp"],
                "type": meta["type"],
                "selected": resolved.get(mod_id, False),
                "status": "pending" if resolved.get(mod_id, False) else "skipped",
                "findings": 0,
                "started_at": None,
                "finished_at": None,
                "message": "Waiting for execution." if resolved.get(mod_id, False) else "Skipped — module was not selected."
            }
            for mod_id, meta in CANONICAL_MODULES.items()
        }

    timeline = exec_checks.get("timeline")
    pipeline_stages = exec_checks.get("pipeline_stages")
    completed_map = exec_checks.get("completed_checks")
    inventory = exec_checks.get("inventory")
    if not completed_map:
        completed_map = {k: v for k, v in exec_checks.items() if isinstance(v, bool)}
    
    return ScanStatusOut(
        scan_id=scan.id,
        target=scan.target_url,
        status=scan.status,
        progress=scan.progress,
        stage=scan.stage,
        depth=scan.depth,
        checks=req_modules if (len(req_modules) > 0) else (completed_map or {"misconfig": False, "https": False, "access_control": False, "auth": False, "sqli": False, "xss": False}),
        completed_checks=completed_map,
        modules=req_modules,
        module_details=module_details,
        timeline=timeline,
        pipeline_stages=pipeline_stages,
        findings_count=c,
        inventory=inventory,
        created_at=scan.created_at,
        finished_at=scan.finished_at
    )

@router.get("/scans/{id}/results", response_model=ScanResultOut)
def scan_results(id: str, current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("completed", "failed", "completed_with_errors"):
        raise HTTPException(status_code=409, detail="Scan is not completed yet")
        
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    c = aggregate_finding_counts(findings, scan=scan)

    module_details = None
    if scan.modules:
        if isinstance(scan.modules, dict):
            module_details = scan.modules.get("module_details", scan.modules)
        elif isinstance(scan.modules, str):
            try:
                m_obj = json.loads(scan.modules)
                module_details = m_obj.get("module_details", m_obj)
            except Exception:
                pass

    inventory = None
    if scan.checks and isinstance(scan.checks, dict):
        inventory = scan.checks.get("inventory")

    return ScanResultOut(
        scan_id=scan.id,
        target=scan.target_url,
        depth=scan.depth,
        status=scan.status,
        scanned_at=scan.finished_at or scan.created_at,
        security_score=scan.security_score,
        counts=ScanCounts(**c),
        findings=findings,
        module_details=module_details,
        inventory=inventory
    )

@router.delete("/scans/{id}")
def delete_scan(id: str, current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found or access denied")
    
    db.delete(scan)
    db.commit()
    audit_logger.info(f"Scan deleted (ID: {scan.id}) by user {current_user.email}")
    return {"status": "success", "message": "Scan deleted"}

# ==============================================================================
# FINDINGS (Requires Verified User & Scan Ownership)
# ==============================================================================

@router.get("/findings/{id}")
def get_finding(id: str, current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    finding = db.query(Finding).join(Scan).filter(Finding.id == id, Scan.user_id == current_user.id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding": finding}

# ==============================================================================
# USER PROFILE & SETTINGS
# ==============================================================================

@router.get("/user/profile", response_model=UserOut)
def user_profile(current_user: User = Depends(get_current_user)):
    return current_user

@router.put("/user/profile", response_model=UserOut)
def update_profile(updates: UserProfileUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if updates.full_name is not None:
        user.full_name = updates.full_name
    if updates.website is not None:
        user.website = updates.website
    if updates.avatar_url is not None:
        user.avatar_url = updates.avatar_url
    if updates.phone_number is not None:
        raw_phone = updates.phone_number.strip()
        if not raw_phone:
            user.phone_number = None
            user.phone_verified = False
            user.phone_verified_at = None
        elif raw_phone != user.phone_number:
            is_valid, normalized_phone, err_msg = phone_service.normalize_and_validate(raw_phone)
            if not is_valid:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)
            # Check unique constraint against other users
            existing_owner = db.query(User).filter(
                User.phone_number == normalized_phone,
                User.id != user.id
            ).first()
            if existing_owner:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="This phone number is already registered to another account."
                )
            user.phone_number = normalized_phone
            user.phone_verified = False
            user.phone_verified_at = None

    db.commit()
    db.refresh(user)
    return user

@router.get("/user/settings", response_model=UserSettingsOut)
def get_user_settings(current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    settings = db.query(UserSettings).filter(UserSettings.user_id == current_user.id).first()
    if not settings:
        settings = UserSettings(user_id=current_user.id)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings

@router.put("/user/settings", response_model=UserSettingsOut)
def update_user_settings(updates: UserSettingsUpdate, current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    settings = db.query(UserSettings).filter(UserSettings.user_id == current_user.id).first()
    if not settings:
        settings = UserSettings(user_id=current_user.id)
        db.add(settings)
    
    if updates.default_scan_depth is not None:
        settings.default_scan_depth = updates.default_scan_depth
    if updates.notif_scan_completed is not None:
        settings.notif_scan_completed = updates.notif_scan_completed
    if updates.notif_scan_failed is not None:
        settings.notif_scan_failed = updates.notif_scan_failed
    if updates.notif_security_findings is not None:
        settings.notif_security_findings = updates.notif_security_findings
        
    settings.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    db.commit()
    db.refresh(settings)
    return settings

# ==============================================================================
# REPORTS (Requires Verified User & Ownership Isolation)
# ==============================================================================

@router.get("/reports")
def list_reports(current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(
        Scan.user_id == current_user.id,
        Scan.status.in_(["completed", "completed_with_errors"])
    ).order_by(Scan.finished_at.desc()).all()
    reports = []
    for s in scans:
        findings = db.query(Finding).filter(Finding.scan_id == s.id).all()
        c = aggregate_finding_counts(findings, s)
        report_counts = {k: c.get(k, 0) for k in ["high", "medium", "low", "not_detected", "scanner_error", "inconclusive", "critical", "info", "total"] if k in c}
        reports.append({
            "id": "r" + s.id,
            "scan_id": s.id,
            "target": s.target_url,
            "depth": s.depth,
            "security_score": s.security_score if s.security_score is not None else 0,
            "counts": report_counts,
            "generated_at": s.finished_at or s.created_at
        })
    return {"reports": reports}

@router.get("/reports/{id}")
async def get_report(id: str, current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    scan_id = id[1:] if id.startswith("r") else id
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id,
        Scan.status.in_(["completed", "completed_with_errors"])
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Report not found")
        
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    c = aggregate_finding_counts(findings, scan)
    report_counts = {k: c.get(k, 0) for k in ["high", "medium", "low", "not_detected", "scanner_error", "inconclusive", "critical", "info", "total"] if k in c}
    by_type = {}
    for f in findings:
        status = (f.status or "").upper()
        if f.type not in by_type:
            by_type[f.type] = {"name": f.type, "total": 0, "confirmed": 0}
        by_type[f.type]["total"] += 1
        if status not in ("NOT_DETECTED", "SCANNER_ERROR", "INCONCLUSIVE"):
            by_type[f.type]["confirmed"] += 1

    summary_data = await generate_executive_summary(scan, findings)
    executive_summary_md = format_executive_summary_markdown(summary_data)
    categories = [{"name": v["name"].replace("_", " ").title(), "score": max(0, int(((v["total"] - v["confirmed"]) / v["total"]) * 100))} for v in by_type.values()]
    
    return {
        "id": "r" + scan.id,
        "scan_id": scan.id,
        "target": scan.target_url,
        "depth": scan.depth,
        "security_score": scan.security_score,
        "counts": report_counts,
        "generated_at": scan.finished_at or scan.created_at,
        "executive_summary": executive_summary_md,
        "executive_summary_structured": summary_data,
        "categories": categories,
        "findings": findings
    }

@router.post("/reports/{id}/ai-summary", dependencies=[Depends(limit_ai)])
async def regenerate_report_ai_summary(
    id: str,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db)
):
    scan_id = id[1:] if id.startswith("r") else id
    scan = db.query(Scan).filter(
        Scan.id == scan_id,
        Scan.user_id == current_user.id,
        Scan.status.in_(["completed", "completed_with_errors"])
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Report not found")
        
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    summary_data = await generate_executive_summary(scan, findings)
    return {
        "scan_id": scan.id,
        "summary": summary_data,
        "markdown": format_executive_summary_markdown(summary_data)
    }

@router.get("/reports/{id}/export/json")
def export_report_json(
    id: str,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db)
):
    scan_id = id[1:] if id.startswith("r") else id
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Report not found")
    if scan.status not in ("completed", "completed_with_errors", "failed"):
        raise HTTPException(status_code=409, detail="Scan is still running; export is unavailable")

    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    c = aggregate_finding_counts(findings, scan)

    findings_data = []
    for f in findings:
        cat = map_finding_to_category(f)
        findings_data.append({
            "id": f.id,
            "type": f.type,
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "verification_status": f.verification_status or f.status,
            "category": cat,
            "confidence": f.confidence,
            "url": f.url,
            "parameter": f.parameter,
            "http_method": f.http_method,
            "evidence": f.evidence,
            "impact": f.impact,
            "remediation": f.remediation,
            "owasp": f.owasp,
            "cwe": f.cwe,
            "created_at": f.created_at
        })

    report_data = {
        "report_id": "r" + scan.id,
        "scan_id": scan.id,
        "target_url": scan.target_url,
        "depth": scan.depth,
        "status": scan.status,
        "security_score": scan.security_score,
        "counts": c,
        "created_at": scan.created_at,
        "finished_at": scan.finished_at,
        "findings": findings_data
    }
    content = json.dumps(report_data, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="ethiosec_report_{scan.id}.json"'}
    )

@router.get("/reports/{id}/export/csv")
def export_report_csv(
    id: str,
    current_user: User = Depends(get_current_verified_user),
    db: Session = Depends(get_db)
):
    scan_id = id[1:] if id.startswith("r") else id
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Report not found")
    if scan.status not in ("completed", "completed_with_errors", "failed"):
        raise HTTPException(status_code=409, detail="Scan is still running; export is unavailable")

    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow([
        "Finding ID", "Type", "Title", "Severity", "Category", "Status",
        "URL", "Parameter", "HTTP Method", "Evidence", "Remediation", "OWASP", "CWE"
    ])
    for f in findings:
        cat = map_finding_to_category(f)
        rem = "; ".join(f.remediation) if isinstance(f.remediation, list) else str(f.remediation or "")
        writer.writerow([
            f.id,
            f.type or "",
            f.title or "",
            f.severity or "",
            cat,
            f.status or "",
            f.url or "",
            f.parameter or "",
            f.http_method or "",
            f.evidence or "",
            rem,
            f.owasp or "",
            f.cwe or ""
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="ethiosec_report_{scan.id}.csv"'}
    )

@router.get("/scans/{id}/export/json")
def export_scan_json(id: str, current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    return export_report_json(id=id, current_user=current_user, db=db)

@router.get("/scans/{id}/export/csv")
def export_scan_csv(id: str, current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    return export_report_csv(id=id, current_user=current_user, db=db)

# ==============================================================================
# AI ASSISTANT (Requires Verified User & Isolation)
# ==============================================================================

from ai import (
    ask_ai, build_finding_context, build_scan_summary_context, build_general_context,
    aggregate_finding_counts, generate_executive_summary, format_executive_summary_markdown,
    map_finding_to_category
)

@router.post("/ai/chat", response_model=AIResponse, dependencies=[Depends(limit_ai)])
async def ai_chat(req: AIRequest, current_user: User = Depends(get_current_verified_user), db: Session = Depends(get_db)):
    if req.finding_id:
        finding = db.query(Finding).filter(Finding.id == req.finding_id).first()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
            
        scan = db.query(Scan).filter(Scan.id == finding.scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Parent scan not found")
            
        if scan.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized to access this finding")
            
        context = build_finding_context(finding, scan)
        
    elif req.scan_id:
        scan = db.query(Scan).filter(Scan.id == req.scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
            
        if scan.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Not authorized to access this scan")
            
        findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
        context = build_scan_summary_context(scan, findings)
        
    else:
        # General cybersecurity question
        context = build_general_context()
        
    reply = await ask_ai(context, req.message, history=req.history)
    return {"reply": reply, "scan_id": req.scan_id, "finding_id": req.finding_id}

@router.post("/ai-assistant", dependencies=[Depends(limit_ai)])
async def ai_assistant_sse(req: AIAssistantRequestNew, current_user: User = Depends(get_current_verified_user)):
    import json
    from fastapi.responses import StreamingResponse

    system_prompt = (
        "You are a senior Application Security Engineer. Analyze the provided evidence and return "
        "a plain-language explanation of the real-world business risk, followed by specific, actionable remediation code."
    )
    user_prompt = f"CWE ID: {req.cwe_id}\nSeverity: {req.severity}\nTarget Endpoint: {req.target_endpoint}\nHTTP Response Snippet:\n{req.response_snippet}"

    async def sse_generator():
        try:
            reply = await ask_ai(system_prompt, user_prompt)
            payload = json.dumps({"text": reply})
            yield f"data: {payload}\n\n"
        except Exception as e:
            payload = json.dumps({"error": "Failed to generate AI analysis."})
            yield f"data: {payload}\n\n"

    return StreamingResponse(sse_generator(), media_type="text/event-stream")
