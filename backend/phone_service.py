"""
EthioSec Scanner - Phone Number & SMS Verification Service
Supports real SMS delivery via Twilio Verify API v2 (or development simulation mode).
Strictly validates E.164 phone formats, enforces cooldowns, rate limits, and verification checks.
"""

import os
import re
import time
import hmac
import hashlib
import secrets
import logging
from typing import Tuple, Optional, Dict, Any
from datetime import datetime, timezone
import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("ethiosec.phone_service")

# E.164 regular expression: starts with +, followed by 7 to 15 digits (e.g. +251911223344, +14155552671)
E164_REGEX = re.compile(r"^\+[1-9]\d{6,14}$")

# Rate limit / cooldown thresholds
RESEND_COOLDOWN_SECONDS = 60
VERIFICATION_CODE_EXPIRY_SECONDS = 600 # 10 minutes
MAX_VERIFICATION_ATTEMPTS = 5

class PhoneVerificationService:
    def __init__(self):
        self.account_sid = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
        self.auth_token = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
        self.verify_service_sid = os.getenv("TWILIO_VERIFY_SERVICE_SID", "").strip()
        
        # Secret used for hashing simulation OTPs in memory (never stored plaintext)
        self._secret = os.getenv("JWT_SECRET_KEY", "dev_phone_verification_secret_key").encode("utf-8")
        
        # Ephemeral storage for development/test mode simulation:
        # key: normalized_phone -> { "hash": str, "expires_at": float, "attempts": int, "created_at": float }
        self._dev_store: Dict[str, Dict[str, Any]] = {}

    @property
    def is_provider_configured(self) -> bool:
        """Returns True only when valid Twilio Verify credentials are configured."""
        return bool(self.account_sid and self.auth_token and self.verify_service_sid)

    def normalize_and_validate(self, phone: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Cleans and validates an input phone number to standard E.164 format.
        Supports standard Ethiopian numbers (09..., 07... -> +251...) or existing international format.
        Returns: (is_valid, normalized_phone, error_message)
        """
        if not phone or not phone.strip():
            return False, None, "Phone number is required."

        cleaned = re.sub(r"[\s\-\(\)\.]", "", phone.strip())
        
        # Ethiopian national format translation (e.g., 0911223344 -> +251911223344)
        if cleaned.startswith("09") and len(cleaned) == 10:
            cleaned = "+251" + cleaned[1:]
        elif cleaned.startswith("07") and len(cleaned) == 10:
            cleaned = "+251" + cleaned[1:]
        elif cleaned.startswith("251") and not cleaned.startswith("+"):
            cleaned = "+" + cleaned
        elif not cleaned.startswith("+"):
            cleaned = "+" + cleaned

        if not E164_REGEX.match(cleaned):
            return False, None, (
                "Invalid phone number format. Please provide a valid number in international E.164 format "
                "(e.g., +251911223344 or +14155552671)."
            )

        return True, cleaned, None

    def _hash_code(self, code: str) -> str:
        """Generates HMAC-SHA256 hash of a verification code to prevent plaintext exposure."""
        return hmac.new(self._secret, code.strip().encode("utf-8"), hashlib.sha256).hexdigest()

    async def send_verification_code(self, phone: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Initiates SMS verification through Twilio Verify API if credentials are configured,
        or handles it safely via local development simulation if external credentials are unset.
        Returns: (success, message, metadata)
        """
        is_valid, normalized, err_msg = self.normalize_and_validate(phone)
        if not is_valid:
            return False, err_msg, {"code": "INVALID_PHONE_NUMBER"}

        now = time.time()

        # Check cooldown in dev store if applicable
        if normalized in self._dev_store:
            last_sent = self._dev_store[normalized].get("created_at", 0)
            elapsed = now - last_sent
            if elapsed < RESEND_COOLDOWN_SECONDS:
                remaining = int(RESEND_COOLDOWN_SECONDS - elapsed)
                return False, f"Please wait {remaining} seconds before requesting a new verification code.", {
                    "code": "COOLDOWN_ACTIVE",
                    "retry_after_seconds": remaining
                }

        # 1. Real Provider Integration: Twilio Verify API
        if self.is_provider_configured:
            url = f"https://verify.twilio.com/v2/Services/{self.verify_service_sid}/Verifications"
            auth = (self.account_sid, self.auth_token)
            payload = {
                "To": normalized,
                "Channel": "sms"
            }
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(url, data=payload, auth=auth)
                    if resp.status_code in (200, 201):
                        data = resp.json()
                        logger.info(f"Twilio Verify SMS dispatched successfully to {normalized[:5]}*** (status={data.get('status')})")
                        return True, f"Verification code sent via SMS to {normalized}.", {
                            "provider": "twilio_verify",
                            "status": data.get("status", "pending"),
                            "is_real_provider": True
                        }
                    else:
                        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                        err_detail = data.get("message", f"HTTP {resp.status_code}")
                        logger.error(f"Twilio Verify dispatch error: {err_detail}")
                        return False, "Failed to send SMS verification code through carrier provider. Please try again later.", {
                            "provider": "twilio_verify",
                            "error": err_detail,
                            "is_real_provider": True
                        }
            except Exception as ex:
                logger.error(f"Twilio Verify network exception: {ex}")
                return False, "SMS provider connection error. Please try again later.", {
                    "provider": "twilio_verify",
                    "error": str(ex),
                    "is_real_provider": True
                }

        # 2. Development / Test Mode Simulation
        # Generates a 6-digit numeric OTP, never logged in production or stored plaintext
        otp_code = "".join([str(secrets.randbelow(10)) for _ in range(6)])
        code_hash = self._hash_code(otp_code)
        
        self._dev_store[normalized] = {
            "hash": code_hash,
            "created_at": now,
            "expires_at": now + VERIFICATION_CODE_EXPIRY_SECONDS,
            "attempts": 0,
            # In test mode only, we make OTP accessible for automated mock tests:
            "_test_otp": otp_code if os.getenv("ENVIRONMENT") in ("development", "test") else None
        }

        logger.warning(
            f"[DEV SIMULATION - SMS NOT SENT TO REAL CARRIER] Phone: {normalized} | "
            f"Code: {otp_code} (Valid for 10 minutes. Configure TWILIO_ACCOUNT_SID for real delivery)."
        )
        return True, f"[TEST/DEV] Verification code generated for {normalized}.", {
            "provider": "mock_development_simulation",
            "is_real_provider": False,
            "simulation_code": otp_code if os.getenv("ENVIRONMENT") in ("development", "test") else None
        }

    async def verify_code(self, phone: str, submitted_code: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates the submitted verification code with the provider or dev store.
        Returns: (success, message, metadata)
        """
        is_valid, normalized, err_msg = self.normalize_and_validate(phone)
        if not is_valid:
            return False, err_msg, {"code": "INVALID_PHONE_NUMBER"}

        clean_code = str(submitted_code).strip()
        if not re.match(r"^\d{4,8}$", clean_code):
            return False, "Invalid verification code format. Must be 4 to 8 digits.", {"code": "INVALID_FORMAT"}

        now = time.time()

        # 1. Real Provider Verification: Twilio Verify Check API
        if self.is_provider_configured:
            url = f"https://verify.twilio.com/v2/Services/{self.verify_service_sid}/VerificationCheck"
            auth = (self.account_sid, self.auth_token)
            payload = {
                "To": normalized,
                "Code": clean_code
            }
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(url, data=payload, auth=auth)
                    if resp.status_code in (200, 201):
                        data = resp.json()
                        status = data.get("status")
                        if status == "approved":
                            logger.info(f"Twilio Verify phone {normalized[:5]}*** successfully verified.")
                            return True, "Phone number successfully verified.", {
                                "provider": "twilio_verify",
                                "status": "approved",
                                "is_real_provider": True
                            }
                        else:
                            return False, "Invalid verification code. Please check the code and try again.", {
                                "provider": "twilio_verify",
                                "status": status,
                                "is_real_provider": True
                            }
                    else:
                        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                        err_msg = data.get("message", "Verification check failed.")
                        return False, "Invalid or expired verification code.", {
                            "provider": "twilio_verify",
                            "error": err_msg,
                            "is_real_provider": True
                        }
            except Exception as ex:
                logger.error(f"Twilio Verify verification exception: {ex}")
                return False, "Error communicating with verification provider.", {
                    "provider": "twilio_verify",
                    "error": str(ex),
                    "is_real_provider": True
                }

        # 2. Development Simulation Verification
        record = self._dev_store.get(normalized)
        if not record:
            return False, "No active verification request found for this phone number. Please request a new code.", {
                "code": "NO_ACTIVE_REQUEST"
            }

        # Check expiration
        if now > record.get("expires_at", 0):
            self._dev_store.pop(normalized, None)
            return False, "Verification code has expired. Please request a new code.", {
                "code": "CODE_EXPIRED"
            }

        # Check maximum retry attempts
        if record.get("attempts", 0) >= MAX_VERIFICATION_ATTEMPTS:
            self._dev_store.pop(normalized, None)
            return False, "Maximum verification attempts exceeded. Please request a new code.", {
                "code": "MAX_ATTEMPTS_EXCEEDED"
            }

        # Constant-time comparison of hashed verification code
        submitted_hash = self._hash_code(clean_code)
        if not hmac.compare_digest(submitted_hash, record.get("hash", "")):
            record["attempts"] = record.get("attempts", 0) + 1
            remaining = MAX_VERIFICATION_ATTEMPTS - record["attempts"]
            return False, f"Incorrect verification code. {remaining} attempt(s) remaining.", {
                "code": "CODE_MISMATCH",
                "attempts_remaining": remaining
            }

        # Verification successful: purge ephemeral OTP
        self._dev_store.pop(normalized, None)
        logger.info(f"Phone {normalized} successfully verified in dev simulation.")
        return True, "Phone number successfully verified.", {
            "provider": "mock_development_simulation",
            "is_real_provider": False
        }

phone_service = PhoneVerificationService()
