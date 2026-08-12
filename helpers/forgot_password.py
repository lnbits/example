"""
Forgot-password flow for the siLNt extension.

Generates LNbits-compatible reset keys (same algorithm as the admin endpoint
in user_api.py) and emails them as a clickable link to the user's registered
email address.
"""

import base64
import json
import time
from http import HTTPStatus

from fastapi import APIRouter, HTTPException, Request
from loguru import logger
from pydantic import BaseModel

from lnbits.core.crud import get_account_by_email
from lnbits.core.services.notifications import send_email_notification
from lnbits.helpers import encrypt_internal_message
from lnbits.settings import settings

def _generate_reset_key(user_id: str) -> str:
    """Generate the same kind of signed reset key LNbits's admin endpoint produces."""
    reset_data = ["reset", user_id, int(time.time())]
    reset_data_json = json.dumps(reset_data, separators=(",", ":"), ensure_ascii=False)
    enc = encrypt_internal_message(reset_data_json)
    if not enc:
        raise RuntimeError("Cannot generate reset key.")
    reset_key_b64 = base64.b64encode(enc.encode()).decode()
    return f"reset_key_{reset_key_b64}"

async def request_password_reset(email: str, request: Request) -> dict:
    """
    Look up account by email, generate reset key, email the link.
    Always returns success-style response — never reveals whether the
    email exists (prevents email enumeration).
    All exceptions caught at the top level to guarantee a dict response.
    """
    generic = {
        "success": True,
        "message": "If an account with that email exists, a reset link has been sent.",
    }

    try:
        # ── Look up account ───────────────────────────────────────────────────
        account = None
        try:
            account = await get_account_by_email(email)
        except Exception as exc:
            logger.warning(f"Forgot-password lookup failed for {email}: {exc}")
            return generic

        if not account:
            return generic
        if account.id == settings.super_user:
            logger.warning("Forgot-password attempted for superuser — ignoring.")
            return generic
        if not account.email:
            logger.warning(f"Account {account.id} has no email on file.")
            return generic

        # ── Generate reset key ────────────────────────────────────────────────
        try:
            reset_key = _generate_reset_key(account.id)
        except Exception as exc:
            logger.error(f"Reset key generation failed: {exc}")
            return generic

        # ── Build reset URL from the canonical frontend origin ─────────────────
        # Prefers SILNT_FRONTEND_URL so reset links work for the mobile app too
        # (no Origin header → the request-derived fallback would hit the API host
        # and 404 on the SPA /reset route).
        from .appenv import frontend_base_url

        origin = frontend_base_url(request)
        reset_url = f"{origin}/reset?key={reset_key}"

        # ── Compose email ─────────────────────────────────────────────────────
        subject = "Thrilla — Password reset request"
        body = (
            f"Hi {account.username or 'there'},\n\n"
            f"Someone (hopefully you) requested a password reset for your account.\n\n"
            f"Click this link to set a new password:\n{reset_url}\n\n"
            f"If you didn't request this, you can safely ignore this email.\n\n"
            f"— Thrilla"
        )

        # ── Send ──────────────────────────────────────────────────────────────
        if not settings.lnbits_email_notifications_enabled:
            logger.error("Password reset requested but email notifications disabled in LNbits.")
            return generic

        try:
            result = await send_email_notification(
                to_emails=[account.email],
                message=body,
                subject=subject,
            )
            if result.get("status") != "ok":
                logger.error(f"Failed to send reset email: {result.get('message')}")
                return generic
            logger.info(f"Password reset email sent to {account.email}")
        except Exception as exc:
            logger.error(f"Failed to send reset email to {account.email}: {exc}")
            return generic

        return generic

    except Exception as exc:
        logger.error(f"Unexpected error in forgot-password flow: {exc}", exc_info=True)
        return generic