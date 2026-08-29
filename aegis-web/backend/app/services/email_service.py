"""app/services/email_service.py — Async email sending with HTML templates.

Uses aiosmtplib for async SMTP.
Supports Gmail with App Passwords (recommended) and any SMTP server.

Setup for Gmail:
  1. Enable 2-Step Verification on your Google account
  2. Go to: myaccount.google.com/apppasswords
  3. Create an App Password for "Mail"
  4. Set smtp_user = your_email@gmail.com
     Set smtp_password = the 16-char app password (no spaces)
     Set smtp_from_email = your_email@gmail.com
     Set email_enabled = true
"""
from __future__ import annotations

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from app.core.config import get_settings

settings = get_settings()
logger   = logging.getLogger(__name__)


async def send_email(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: str = "",
) -> bool:
    """Send an email. Returns True on success, False on failure."""
    if not settings.email_enabled:
        # Dev mode — just log the content
        logger.info(
            "EMAIL (not sent — email_enabled=false)\nTo: %s\nSubject: %s\n%s",
            to_email, subject, text_body or "[html only]"
        )
        return True

    if not settings.smtp_user or not settings.smtp_password:
        logger.warning("Email not configured (smtp_user/smtp_password missing)")
        return False

    try:
        import aiosmtplib

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"{settings.smtp_from_name} <{settings.smtp_from_email or settings.smtp_user}>"
        msg["To"]      = to_email

        if text_body:
            msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_user,
            password=settings.smtp_password,
            start_tls=True,
        )
        logger.info("Email sent to %s: %s", to_email, subject)
        return True

    except Exception as e:
        logger.error("Email send failed to %s: %s", to_email, e)
        return False


# ── Email templates ───────────────────────────────────────────────────────────

def _base_html(content: str) -> str:
    """Wrap content in a consistent dark-themed email template."""
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aegis AI</title>
</head>
<body style="margin:0;padding:0;background:#0d1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;padding:40px 16px;">
    <tr><td align="center">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;">

        <!-- Logo -->
        <tr><td align="center" style="padding-bottom:32px;">
          <div style="display:inline-flex;align-items:center;gap:10px;">
            <div style="width:40px;height:40px;background:#58a6ff1a;border:1px solid #58a6ff33;border-radius:10px;display:flex;align-items:center;justify-content:center;">
              <span style="font-size:20px;">🛡️</span>
            </div>
            <span style="font-size:20px;font-weight:600;color:#ffffff;">Aegis AI</span>
          </div>
        </td></tr>

        <!-- Card -->
        <tr><td style="background:#161b22;border:1px solid #21262d;border-radius:16px;padding:40px 36px;">
          {content}
        </td></tr>

        <!-- Footer -->
        <tr><td align="center" style="padding-top:24px;">
          <p style="color:#8b949e;font-size:12px;margin:0;">
            This email was sent by Aegis AI. If you didn't request this, you can safely ignore it.
          </p>
          <p style="color:#484f58;font-size:11px;margin:8px 0 0;">
            © 2026 Aegis AI — Cybersecurity Assistant
          </p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


# ── Verification email ────────────────────────────────────────────────────────

async def send_verification_email(
    to_email: str,
    display_name: str,
    verify_url: str,
) -> bool:
    content = f"""
      <h2 style="color:#ffffff;font-size:22px;font-weight:600;margin:0 0 8px;">Verify your email</h2>
      <p style="color:#8b949e;font-size:14px;margin:0 0 28px;">Hi {display_name}, welcome to Aegis AI!</p>

      <p style="color:#c9d1d9;font-size:14px;line-height:1.6;margin:0 0 28px;">
        Click the button below to verify your email address and activate your account.
        This link expires in <strong style="color:#e6edf3;">24 hours</strong>.
      </p>

      <div style="text-align:center;margin:0 0 32px;">
        <a href="{verify_url}"
           style="display:inline-block;background:#58a6ff;color:#ffffff;text-decoration:none;
                  font-size:14px;font-weight:600;padding:12px 32px;border-radius:8px;">
          Verify Email Address
        </a>
      </div>

      <p style="color:#8b949e;font-size:12px;margin:0;line-height:1.6;">
        Or copy this link into your browser:<br>
        <span style="color:#58a6ff;word-break:break-all;">{verify_url}</span>
      </p>

      <div style="border-top:1px solid #21262d;margin-top:28px;padding-top:20px;">
        <p style="color:#8b949e;font-size:12px;margin:0;">
          🔒 Once verified, you can scan links, check credentials, analyse profiles, and detect scams.
        </p>
      </div>
    """
    html = _base_html(content)
    text = (
        f"Hi {display_name},\n\n"
        f"Verify your Aegis AI account by visiting:\n{verify_url}\n\n"
        f"This link expires in 24 hours.\n\n"
        f"If you didn't create an account, ignore this email."
    )
    return await send_email(to_email, "Verify your Aegis AI account", html, text)


# ── Password reset email ──────────────────────────────────────────────────────

async def send_password_reset_email(
    to_email: str,
    display_name: str,
    reset_url: str,
) -> bool:
    content = f"""
      <h2 style="color:#ffffff;font-size:22px;font-weight:600;margin:0 0 8px;">Reset your password</h2>
      <p style="color:#8b949e;font-size:14px;margin:0 0 28px;">Hi {display_name},</p>

      <p style="color:#c9d1d9;font-size:14px;line-height:1.6;margin:0 0 28px;">
        We received a request to reset your Aegis AI password.
        This link expires in <strong style="color:#e6edf3;">1 hour</strong>.
      </p>

      <div style="background:#21262d;border:1px solid #30363d;border-radius:8px;padding:16px;margin:0 0 28px;">
        <p style="color:#8b949e;font-size:12px;margin:0 0 4px;text-transform:uppercase;letter-spacing:0.05em;">
          Requested for
        </p>
        <p style="color:#e6edf3;font-size:14px;margin:0;">{to_email}</p>
      </div>

      <div style="text-align:center;margin:0 0 28px;">
        <a href="{reset_url}"
           style="display:inline-block;background:#f85149;color:#ffffff;text-decoration:none;
                  font-size:14px;font-weight:600;padding:12px 32px;border-radius:8px;">
          Reset Password
        </a>
      </div>

      <div style="background:#ff000011;border:1px solid #f8514933;border-radius:8px;padding:14px;margin:0 0 8px;">
        <p style="color:#f85149;font-size:12px;margin:0;">
          ⚠️ If you did NOT request a password reset, ignore this email.
          Your password will not change.
        </p>
      </div>
    """
    html = _base_html(content)
    text = (
        f"Hi {display_name},\n\n"
        f"Reset your Aegis AI password:\n{reset_url}\n\n"
        f"This link expires in 1 hour.\n\n"
        f"If you didn't request this, ignore this email."
    )
    return await send_email(to_email, "Reset your Aegis AI password", html, text)


# ── Welcome email (after verification) ───────────────────────────────────────

async def send_welcome_email(to_email: str, display_name: str) -> bool:
    content = f"""
      <h2 style="color:#ffffff;font-size:22px;font-weight:600;margin:0 0 8px;">
        Welcome to Aegis AI! 🛡️
      </h2>
      <p style="color:#8b949e;font-size:14px;margin:0 0 28px;">Hi {display_name}, your account is ready.</p>

      <p style="color:#c9d1d9;font-size:14px;line-height:1.6;margin:0 0 24px;">
        You can now use Aegis AI to:
      </p>

      <table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 28px;">
        {"".join(f'''
        <tr><td style="padding:6px 0;">
          <span style="color:#58a6ff;">{icon}</span>
          <span style="color:#c9d1d9;font-size:14px;margin-left:10px;">{label}</span>
        </td></tr>''' for icon, label in [
            ("🔗", "Scan links for malware, phishing, and threats"),
            ("🔑", "Check emails and passwords for data breaches"),
            ("👤", "Analyse social media profiles for fraud"),
            ("📩", "Detect SMS scam messages"),
            ("🎭", "Detect AI-generated deepfake images"),
        ])}
      </table>

      <div style="text-align:center;">
        <a href="{settings.frontend_url}/chat"
           style="display:inline-block;background:#58a6ff;color:#ffffff;text-decoration:none;
                  font-size:14px;font-weight:600;padding:12px 32px;border-radius:8px;">
          Start Using Aegis AI
        </a>
      </div>
    """
    html = _base_html(content)
    text = f"Hi {display_name},\n\nYour Aegis AI account is ready!\nStart here: {settings.frontend_url}/chat"
    return await send_email(to_email, "Welcome to Aegis AI!", html, text)
