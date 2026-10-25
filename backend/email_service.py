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
        self.reload_config()
        # Test / dev capture storage (email -> {"code": str, "token": str, "type": str, "timestamp": str})
        self._sent_messages: Dict[str, Dict[str, Any]] = {}

    def reload_config(self):
        """Reload configuration from environment variables."""
        self.environment = os.getenv("ENVIRONMENT", "development").strip().lower()
        self.smtp_host = os.getenv("SMTP_HOST")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER")
        raw_password = os.getenv("SMTP_PASSWORD")
        # Strip all whitespace from Google App Passwords (e.g. 'abcd efgh ijkl mnop' -> 'abcdefghijklmnop')
        self.smtp_password = raw_password.replace(" ", "") if raw_password else None
        self.smtp_from = os.getenv("SMTP_FROM", "EthioSec Security <no-reply@ethiosec.local>")
        self.smtp_tls = os.getenv("SMTP_TLS", "true").lower() == "true"
        self.frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5500").rstrip("/")

    def is_smtp_configured(self) -> bool:
        """Returns True if full SMTP delivery credentials are provided."""
        return bool(self.smtp_host and self.smtp_user and self.smtp_password)

    def generate_verification_code(self) -> str:
        """Generate a cryptographically secure 6-digit numeric verification code."""
        return "".join(secrets.choice(string.digits) for _ in range(6))

    def generate_reset_token(self) -> str:
        """Generate a cryptographically secure URL-safe password reset token."""
        return secrets.token_urlsafe(32)

    def _build_verification_html(self, code: str) -> str:
        """Generate responsive dark-and-red HTML verification email."""
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Email — EthioSec Scanner</title>
</head>
<body style="margin:0; padding:0; background-color:#080808; font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color:#F5F5F5;">
    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="table-layout:fixed; background-color:#080808; padding: 40px 10px;">
        <tr>
            <td align="center">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width:540px; background-color:#0D0E11; border:1px solid #242833; border-radius:12px; overflow:hidden; box-shadow:0 10px 40px rgba(0,0,0,0.8);">
                    <tr>
                        <td style="padding: 32px 36px; border-bottom: 1px solid #1F222B;">
                            <div style="font-size:20px; font-weight:800; letter-spacing:0.5px; color:#FFFFFF;">
                                ETHIOSEC <span style="color:#FF2028;">SCANNER</span>
                            </div>
                            <div style="font-size:12px; color:#888888; margin-top:4px;">
                                Secure Today, Safer Tomorrow
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 36px 36px 24px 36px;">
                            <h1 style="font-size:22px; font-weight:700; color:#FFFFFF; margin:0 0 14px 0;">
                                Verify Your Email Address
                            </h1>
                            <p style="font-size:14px; line-height:1.6; color:#A6A6A6; margin:0 0 24px 0;">
                                Welcome to EthioSec Scanner. Please enter the following 6-digit verification code to activate your security workspace:
                            </p>
                            <div style="background-color:#13151A; border:1px solid #FF2028; border-radius:8px; padding:20px; text-align:center; margin:0 0 24px 0;">
                                <span style="font-size:32px; font-weight:800; letter-spacing:10px; color:#FF2028; font-family:monospace; display:inline-block; padding-left:10px;">
                                    {code}
                                </span>
                            </div>
                            <p style="font-size:13px; line-height:1.5; color:#888888; margin:0 0 8px 0;">
                                ⏱️ This verification code is valid for <strong>15 minutes</strong> and can only be used once.
                            </p>
                            <p style="font-size:13px; line-height:1.5; color:#888888; margin:0;">
                                If you did not create an EthioSec Scanner account, you can safely ignore this email.
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 24px 36px; background-color:#090A0D; border-top:1px solid #1A1D24; text-align:center; font-size:11.5px; color:#555555;">
                            &copy; 2025 EthioSec Scanner. All rights reserved.<br>
                            Evidence-based web application security scanning platform.
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>"""

    def _build_password_reset_html(self, to_email: str, reset_token: str) -> str:
        """Generate responsive dark-and-red HTML password reset email."""
        reset_link = f"{self.frontend_url}/reset-password.html?email={to_email}&token={reset_token}"
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password — EthioSec Scanner</title>
</head>
<body style="margin:0; padding:0; background-color:#080808; font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color:#F5F5F5;">
    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="table-layout:fixed; background-color:#080808; padding: 40px 10px;">
        <tr>
            <td align="center">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width:540px; background-color:#0D0E11; border:1px solid #242833; border-radius:12px; overflow:hidden; box-shadow:0 10px 40px rgba(0,0,0,0.8);">
                    <tr>
                        <td style="padding: 32px 36px; border-bottom: 1px solid #1F222B;">
                            <div style="font-size:20px; font-weight:800; letter-spacing:0.5px; color:#FFFFFF;">
                                ETHIOSEC <span style="color:#FF2028;">SCANNER</span>
                            </div>
                            <div style="font-size:12px; color:#888888; margin-top:4px;">
                                Secure Today, Safer Tomorrow
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 36px 36px 24px 36px;">
                            <h1 style="font-size:22px; font-weight:700; color:#FFFFFF; margin:0 0 14px 0;">
                                Password Reset Request
                            </h1>
                            <p style="font-size:14px; line-height:1.6; color:#A6A6A6; margin:0 0 20px 0;">
                                A password recovery request was received for your EthioSec Scanner account. Click the button below to update your password:
                            </p>
                            <div style="text-align:center; margin: 28px 0;">
                                <a href="{reset_link}" target="_blank" style="background-color:#FF2028; color:#FFFFFF; text-decoration:none; padding:13px 28px; font-size:14px; font-weight:700; border-radius:8px; display:inline-block; box-shadow:0 4px 15px rgba(255, 32, 40, 0.4);">
                                    Reset My Password
                                </a>
                            </div>
                            <div style="background-color:#13151A; border:1px solid #22252F; border-radius:8px; padding:16px; margin:20px 0;">
                                <div style="font-size:12px; color:#888888; margin-bottom:6px;">Your Single-Use Reset Token:</div>
                                <code style="font-size:13px; color:#FF2028; word-break:break-all; font-family:monospace;">{reset_token}</code>
                            </div>
                            <p style="font-size:13px; line-height:1.5; color:#888888; margin:0 0 8px 0;">
                                ⏱️ This reset link is valid for <strong>15 minutes</strong> and will automatically expire once used.
                            </p>
                            <p style="font-size:13px; line-height:1.5; color:#888888; margin:0;">
                                If you did not initiate this request, your account remains secure; please disregard this email.
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 24px 36px; background-color:#090A0D; border-top:1px solid #1A1D24; text-align:center; font-size:11.5px; color:#555555;">
                            &copy; 2025 EthioSec Scanner. All rights reserved.
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>"""

    def send_verification_email(self, to_email: str, code: str) -> bool:
        """
        Send an email verification code.
        If SMTP is configured, sends via real SMTP transport (STARTTLS).
        In production without SMTP: fails safely and logs error.
        In test/dev environments without SMTP: safely records in test memory.
        """
        self.reload_config()
        subject = "EthioSec Scanner — Verify Your Email Address"
        body = (
            f"Hello,\n\n"
            f"Thank you for registering with EthioSec Scanner.\n"
            f"Your verification code is: {code}\n\n"
            f"This code will expire in 15 minutes.\n"
            f"If you did not create an EthioSec account, please ignore this message.\n\n"
            f"— EthioSec Security Team"
        )
        html_body = self._build_verification_html(code)

        # Record in test/dev memory
        self._sent_messages[to_email.lower().strip()] = {
            "code": code,
            "type": "verification",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        if self.is_smtp_configured():
            return self._send_smtp(to_email, subject, body, html_body)
        else:
            if self.environment == "production":
                logger.error(f"Refusing to send verification email to {to_email}: SMTP credentials are not configured in production.")
                return False
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
        self.reload_config()
        subject = "EthioSec Scanner — Password Reset Request"
        reset_link = f"{self.frontend_url}/reset-password.html?email={to_email}&token={reset_token}"
        body = (
            f"Hello,\n\n"
            f"A password reset was requested for your EthioSec Scanner account.\n"
            f"Reset Link: {reset_link}\n"
            f"Your reset token is: {reset_token}\n\n"
            f"This token is valid for 15 minutes and can only be used once.\n"
            f"If you did not request this reset, your account is safe; please ignore this email.\n\n"
            f"— EthioSec Security Team"
        )
        html_body = self._build_password_reset_html(to_email, reset_token)

        self._sent_messages[to_email.lower().strip()] = {
            "token": reset_token,
            "type": "password_reset",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        if self.is_smtp_configured():
            return self._send_smtp(to_email, subject, body, html_body)
        else:
            if self.environment == "production":
                logger.error(f"Refusing to send password reset email to {to_email}: SMTP credentials are not configured in production.")
                return False
            else:
                logger.info(f"Email delivery: Captured password reset email for {to_email} (Dev/Test mode, SMTP not configured)")
                print("\n" + "="*68, flush=True)
                print(f"[ETHIOSEC DEV EMAIL] Reset Token for {to_email}: {reset_token}", flush=True)
                print("="*68 + "\n", flush=True)
                return True

    def _send_smtp(self, to_email: str, subject: str, body: str, html_body: Optional[str] = None) -> bool:
        try:
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = self.smtp_from
            msg["To"] = to_email
            msg.set_content(body)
            if html_body:
                msg.add_alternative(html_body, subtype="html")

            # Remove spaces if user entered 16-char Google App Password as 4 groups
            password = self.smtp_password.replace(" ", "") if self.smtp_password else ""

            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                if self.smtp_tls:
                    server.starttls(context=context)
                server.login(self.smtp_user, password)
                server.send_message(msg)
            logger.info(f"Email successfully delivered via SMTP ({self.smtp_host}:{self.smtp_port}) to {to_email}")
            return True
        except Exception as e:
            # Strictly NEVER log credentials or tokens
            logger.error(f"Failed to deliver email to {to_email} via SMTP ({self.smtp_host}:{self.smtp_port}): {type(e).__name__} - {e}", exc_info=False)
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
