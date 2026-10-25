import os
import smtplib
import ssl
import logging
import secrets
import string
import hashlib
import hmac
from email.message import EmailMessage
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple

logger = logging.getLogger("ethiosec.email")

# Cryptographic salt / secret for hashing codes
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "supersecretethioskey_replace_me_in_production")

def hash_verification_secret(secret: str) -> str:
    """Hash verification codes and reset tokens using HMAC-SHA256."""
    return hmac.new(SECRET_KEY.encode("utf-8"), secret.strip().encode("utf-8"), hashlib.sha256).hexdigest()

def verify_secret_hash(provided_secret: str, stored_hash: Optional[str]) -> bool:
    """Constant-time verification of a secret against its stored HMAC-SHA256 hash."""
    if not stored_hash or not provided_secret:
        return False
    computed_hash = hash_verification_secret(provided_secret)
    return hmac.compare_digest(computed_hash, stored_hash)

class EmailService:
    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.smtp_from = os.getenv("SMTP_FROM", "no-reply@ethiosec.local")
        self.smtp_tls = os.getenv("SMTP_TLS", "true").lower() == "true"
        
        # Test / dev capture storage (email -> {"code": str, "type": str, "timestamp": str})
        self._sent_messages: Dict[str, Dict[str, Any]] = {}

    def generate_verification_code(self) -> str:
        """Generate a cryptographically secure 6-digit numeric verification code."""
        return "".join(secrets.choice(string.digits) for _ in range(6))

    def generate_reset_token(self) -> str:
        """Generate a cryptographically secure URL-safe password reset token."""
        return secrets.token_urlsafe(32)

    def send_verification_email(self, to_email: str, code: str) -> bool:
        """
        Send an email verification code.
        If SMTP is configured, sends via SMTP.
        In test/dev environments without SMTP, safely captures in memory.
        """
        subject = "EthioSec Scanner — Verify Your Email Address"
        body = (
            f"Hello,\n\n"
            f"Thank you for registering with EthioSec Scanner.\n"
            f"Your verification code is: {code}\n\n"
            f"This code will expire in 15 minutes. If you did not create an EthioSec account, please ignore this message.\n\n"
            f"— EthioSec Security Team"
        )
        
        # Always record in local memory for dev/test verification
        self._sent_messages[to_email.lower().strip()] = {
            "code": code,
            "type": "verification",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        if self.smtp_host and self.smtp_user and self.smtp_password:
            return self._send_smtp(to_email, subject, body)
        else:
            logger.info(f"Email delivery: Captured verification email for {to_email} (Dev/Test mode, SMTP not configured)")
            print("\n" + "="*68, flush=True)
            print(f"[ETHIOSEC DEV EMAIL] Verification Code for {to_email}: {code}", flush=True)
            print("="*68 + "\n", flush=True)
            return True

    def send_password_reset_email(self, to_email: str, reset_token: str) -> bool:
        """
        Send a password reset token.
        """
        subject = "EthioSec Scanner — Password Reset Request"
        body = (
            f"Hello,\n\n"
            f"A password reset was requested for your EthioSec Scanner account.\n"
            f"Your reset token is: {reset_token}\n\n"
            f"This token is valid for 15 minutes and can only be used once.\n"
            f"If you did not request this reset, your account is safe; please ignore this email.\n\n"
            f"— EthioSec Security Team"
        )

        self._sent_messages[to_email.lower().strip()] = {
            "token": reset_token,
            "type": "password_reset",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        if self.smtp_host and self.smtp_user and self.smtp_password:
            return self._send_smtp(to_email, subject, body)
        else:
            logger.info(f"Email delivery: Captured password reset email for {to_email} (Dev/Test mode, SMTP not configured)")
            print("\n" + "="*68, flush=True)
            print(f"[ETHIOSEC DEV EMAIL] Reset Token for {to_email}: {reset_token}", flush=True)
            print("="*68 + "\n", flush=True)
            return True

    def _send_smtp(self, to_email: str, subject: str, body: str) -> bool:
        try:
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = self.smtp_from
            msg["To"] = to_email
            msg.set_content(body)

            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                if self.smtp_tls:
                    server.starttls(context=context)
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            logger.info(f"Email delivered via SMTP to {to_email}")
            return True
        except Exception as e:
            logger.error(f"Failed to deliver email to {to_email} via SMTP: {e}", exc_info=False)
            return False

    def get_last_sent_code(self, email: str) -> Optional[str]:
        """Test/dev helper to retrieve the last captured code in automated test fixtures."""
        record = self._sent_messages.get(email.lower().strip())
        return record.get("code") if record else None

    def get_last_sent_token(self, email: str) -> Optional[str]:
        """Test/dev helper to retrieve the last captured reset token in automated test fixtures."""
        record = self._sent_messages.get(email.lower().strip())
        return record.get("token") if record else None

    def clear_sent_messages(self):
        """Clear test captured messages."""
        self._sent_messages.clear()

# Global singleton
email_service = EmailService()
