"""
Email-verified registration for the siLNt extension.

Flow:
  1. User submits registration → validate inputs, hash password
  2. Generate a signed token containing {username, email, password_hash, ts}
     and email it as a clickable link — NO account is created yet
  3. User clicks the link → decode/validate token (incl. 1-hour TTL)
  4. Create LNbits Account with a fresh uuid4 id + bcrypt password hash
  5. Enable LNBITS_USER_DEFAULT_EXTENSIONS on the new account, marking paid
     extensions as already-paid so they bypass the payment requirement

This guarantees the account is only created after email ownership is proven,
and that siLNt is fully active on first login (paid or not).
"""

import base64
import json
import time
from http import HTTPStatus
from typing import Optional
from uuid import uuid4
from fastapi import HTTPException, Request
from loguru import logger
from pydantic import BaseModel

from lnbits.core.crud import (    
    get_account_by_username_or_email,
    create_account
)
from lnbits.core.crud.extensions import (
    create_user_extension,
    update_user_extension,
    get_user_extension,
)
from lnbits.core.models import Account
from lnbits.core.models.extensions import UserExtension, UserExtensionInfo
from lnbits.core.services.notifications import send_email_notification
from lnbits.helpers import encrypt_internal_message, decrypt_internal_message
from lnbits.settings import settings, AuthMethods


# Token lifetime — how long verification link stays valid
VERIFICATION_TOKEN_TTL_SECONDS = 60 * 60  # 1 hour


class RegistrationRequest(BaseModel):
    username: str
    email:    str
    password: str


class VerifyRegistrationRequest(BaseModel):
    token: str


# ── Token helpers ─────────────────────────────────────────────────────────────

def _generate_verification_token(
    username: str, email: str, password: str
) -> str:
    """Sign a token carrying the pending registration data."""
    payload = {
        "kind":          "register",
        "username":      username,
        "email":         email,
        "password":      password,
        "ts":            int(time.time()),
    }
    payload_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    enc = encrypt_internal_message(payload_json)
    if not enc:
        raise RuntimeError("Cannot generate verification token.")
    return "verify_" + base64.urlsafe_b64encode(enc.encode()).decode().rstrip("=")


def _decode_verification_token(token: str) -> Optional[dict]:
    """Decode and validate a verification token. Returns None if invalid/expired."""
    if not token.startswith("verify_"):
        return None
    try:
        b64 = token[7:]
        padded = b64 + "=" * (-len(b64) % 4)
        enc = base64.urlsafe_b64decode(padded).decode()
        payload_json = decrypt_internal_message(enc)
        if not payload_json:
            return None
        payload = json.loads(payload_json)
    except Exception as exc:
        logger.warning(f"Invalid verification token: {exc}")
        return None

    if payload.get("kind") != "register":
        return None

    ts = payload.get("ts", 0)
    if int(time.time()) - int(ts) > VERIFICATION_TOKEN_TTL_SECONDS:
        return None

    return payload


# ── Start registration: send email ────────────────────────────────────────────

async def start_registration(
    data: RegistrationRequest, request: Request
) -> dict:
    """
    Validate inputs, check uniqueness, hash the password, generate a
    verification token, and email the link. Does NOT create the account yet.
    """
    if not settings.is_auth_method_allowed(AuthMethods.username_and_password):
        raise HTTPException(
            HTTPStatus.FORBIDDEN, "Username/password auth disabled."
        )

    username = data.username.strip()
    email    = data.email.strip().lower()

    if len(username) < 3 or len(username) > 32:
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Username must be 3–32 chars.")
    if "@" not in email:
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Invalid email.")
    if len(data.password) < 8:
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Password too short (min 8).")

    existing = await get_account_by_username_or_email(username) \
            or await get_account_by_username_or_email(email)
    if existing:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST,
            "Username or email already in use.",
        )    

    try:
        token = _generate_verification_token(username, email, data.password)
    except Exception as exc:
        logger.error(f"Token generation failed: {exc}")
        raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR, "Could not start registration.")

    # Resolve the Thrilla web-app origin. Prefers SILNT_FRONTEND_URL so the link
    # is correct for mobile registrations too (mobile sends no Origin header, so
    # the request-derived fallback would point at the API host and 404).
    from .appenv import frontend_base_url

    origin = frontend_base_url(request)
    verify_url = f"{origin}/verify?token={token}"

    subject = "Thrilla — Verify your email"
    body = (
        f"Hi {username},\n\n"
        f"Thanks for registering for Thrilla. Click the link below to "
        f"activate your account:\n\n"
        f"{verify_url}\n\n"
        f"This link expires in {VERIFICATION_TOKEN_TTL_SECONDS // 60} minutes.\n\n"
        f"If you didn't request this, you can safely ignore this email.\n\n"
        f"— Thrilla"
    )

    if not settings.lnbits_email_notifications_enabled:
        raise HTTPException(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "Email notifications disabled — cannot complete registration.",
        )

    try:
        result = await send_email_notification(
            to_emails=[email],
            message=body,
            subject=subject,
        )
        if result.get("status") != "ok":
            logger.error(f"Email send failed: {result.get('message')}")
            raise HTTPException(
                HTTPStatus.BAD_GATEWAY,
                "Could not send verification email — please try again later.",
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Email send raised: {exc}")
        raise HTTPException(
            HTTPStatus.BAD_GATEWAY,
            "Could not send verification email — please try again later.",
        )

    logger.info(f"Verification email sent to {email} for pending username {username}")
    return {
        "success": True,
        "message": "Verification email sent. Check your inbox to complete registration.",
        "email":   email,
    }


# ── Complete registration: create account + enable extensions ─────────────────

async def complete_registration(token: str) -> dict:
    payload = _decode_verification_token(token)
    if not payload:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST,
            "Verification link is invalid or has expired. Please register again.",
        )

    username     = payload["username"]
    email        = payload["email"]
    raw_password = payload["password"]      # ← raw password from the token

    existing = await get_account_by_username_or_email(username) \
            or await get_account_by_username_or_email(email)
    if existing:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST,
            "Username or email is no longer available — please register again with a different one.",
        )

    try:
        account = Account(
            id       = uuid4().hex,
            username = username,
            email    = email,
        )
        account.hash_password(raw_password)     # ← LNbits-correct, id-bound hashing
        await create_account(account)      # ← the working creation path
        account_id = account.id
        logger.info(f"Email-verified account created: {username} ({email}) id={account_id}")

        # Enable default extensions (paid bypass) — unchanged
        try:
            default_exts = settings.lnbits_user_default_extensions or []
            for ext_id in default_exts:
                user_ext = UserExtension(
                    user=account_id,
                    extension=ext_id,
                    active=True,
                    extra=UserExtensionInfo(
                        paid_to_enable=True,
                        payment_hash_to_enable="default_enabled",
                    ),
                )
                existing_ext = await get_user_extension(account_id, ext_id)
                if existing_ext:
                    await update_user_extension(user_extension=user_ext)
                else:
                    await create_user_extension(user_extension=user_ext)
                logger.info(f"Enabled default extension '{ext_id}' for {account_id} (paid bypass)")
        except Exception as exc:
            logger.warning(f"Could not enable default extensions for {account_id}: {exc}")

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Account creation failed for {username}: {exc}")
        raise HTTPException(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "Failed to create account. Please try again.",
        )

    # ── Send welcome email — non-fatal if it fails ────────────────────────────
    try:
        welcome_subject = "Welcome to Thrilla"
        welcome_body = (
            f"Hi {username},\n\n"
            f"Your Thrilla account is now active. You can sign in any time at the "
            f"URL below using your username and password.\n\n"
            f"What you can do with Thrilla:\n"
            f"  • Create Silent Payment (BIP-352) wallets — private by default\n"
            f"  • Scan the chain for incoming payments via your BlindBit oracle\n"
            f"  • Send to sp1… / bc1q… / BIP-353 (alice@domain) recipients\n"
            f"  • Register a BIP-353 human-readable address for your wallet\n\n"
            f"Wallet keys are stored ONLY on your device — never on the server. "
            f"Keep your mnemonic safe; without it your funds can't be recovered.\n\n"
            f"If you ever need to reset your password, use the 'Forgot password' "
            f"link on the sign-in screen.\n\n"
            f"— Thrilla"
        )
        if settings.lnbits_email_notifications_enabled:
            res = await send_email_notification(
                to_emails=[email],
                message=welcome_body,
                subject=welcome_subject,
            )
            if res.get("status") == "ok":
                logger.info(f"Welcome email sent to {email}")
            else:
                logger.warning(f"Welcome email send returned: {res.get('message')}")
    except Exception as exc:
        # Welcome email failure must not block account activation
        logger.warning(f"Could not send welcome email to {email}: {exc}")

    return {
        "success":  True,
        "username": username,
        "email":    email,
    }
