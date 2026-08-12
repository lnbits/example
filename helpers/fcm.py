# Firebase Cloud Messaging (FCM HTTP v1) sender.
#
# Sends push notifications to users' devices — e.g. "payment received" when a
# background scan finds funds while the app is closed.
#
# SETUP (server side):
#   1. Create a Firebase project and a service account with the
#      "Firebase Cloud Messaging API" enabled; download its JSON key.
#   2. Put the JSON on the server and set:  SILNT_FCM_CREDENTIALS=/path/to/key.json
#      (either exported into LNbits' environment or as a line in the .env LNbits
#      loads — both are supported).
#   If the value is unset or the file is missing, push is simply disabled
#   (sends are no-ops) — the rest of the app is unaffected.
#
# No 'google-auth' install is required: access tokens are minted here by signing
# a JWT with the service account's key using 'cryptography' (already an LNbits
# dependency).
import asyncio
import base64
import json
import os
import time
from typing import Optional

import httpx
from loguru import logger

_SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]

_creds = None  # cached _ServiceAccount


_ENV_KEY = "SILNT_FCM_CREDENTIALS"


def _resolve_credentials_path():
    """Where the service-account JSON lives, and where we found it. Read at
    call-time (not import-time) so a restart reliably picks up a freshly-added
    value. Order: process env → LNbits settings object → LNbits .env file."""
    from .appenv import clean, read_from_env_files

    p = clean(os.environ.get(_ENV_KEY, ""))
    if p:
        return p, "process environment"
    try:
        from lnbits.settings import settings as _s

        v = getattr(_s, "silnt_fcm_credentials", None)
        if v:
            return clean(str(v)), "LNbits settings"
    except Exception:
        pass
    v, source = read_from_env_files(_ENV_KEY)
    if v:
        return v, f".env ({source})"
    return "", ""


def _load_credentials():
    """Return (creds, reason). On failure creds is None and reason is a
    human-readable explanation of exactly which link is broken — so callers can
    tell 'env unset' from 'file missing' from 'wrong/invalid credentials file'."""
    global _creds
    if _creds is not None:
        return _creds, ""
    path, source = _resolve_credentials_path()
    if not path:
        from .appenv import candidate_env_files

        checked = ", ".join(candidate_env_files()) or "(none found)"
        return None, (
            f"SILNT_FCM_CREDENTIALS not found in the process environment, "
            f"LNbits settings, or any .env checked ({checked}). Confirm the key "
            f"name is exactly SILNT_FCM_CREDENTIALS in the .env LNbits loads, "
            f"then restart."
        )
    if not os.path.exists(path):
        return None, (
            f"SILNT_FCM_CREDENTIALS (from {source}) points to a path with no "
            f"readable file from the LNbits process: {path} (check it's absolute "
            f"and readable by the LNbits user)."
        )
    try:
        with open(path, "r", encoding="utf-8") as fh:
            info = json.load(fh)
    except Exception as e:
        return None, (
            f"Found the credentials file but couldn't read it as JSON: {e}."
        )
    if (
        info.get("type") != "service_account"
        or not info.get("client_email")
        or not info.get("private_key")
    ):
        return None, (
            "The credentials file isn't a service-account key (needs "
            "type=service_account, client_email and private_key). If you "
            "downloaded google-services.json for the app, that's the wrong "
            "file — you need a service-account key from Project settings → "
            "Service accounts."
        )
    try:
        _creds = _ServiceAccount(info)
    except Exception as e:
        return None, (
            f"Found the service-account file but couldn't initialise it: {e} "
            f"(is 'cryptography' available and the private_key valid?)."
        )
    return _creds, ""


def _get_credentials():
    creds, reason = _load_credentials()
    if creds is None and reason:
        logger.warning(f"FCM: {reason}")
    return creds


def push_enabled() -> bool:
    return _load_credentials()[0] is not None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class _ServiceAccount:
    """Minimal service-account OAuth2 client for FCM. Mints access tokens by
    signing a JWT with the account's RSA key and exchanging it at Google's token
    endpoint — using only 'cryptography' (already an LNbits dependency), so no
    'google-auth' install is needed in the LNbits venv."""

    def __init__(self, info: dict):
        from cryptography.hazmat.primitives import serialization

        self.client_email = info["client_email"]
        self.project_id = info.get("project_id") or ""
        self.token_uri = info.get("token_uri") or "https://oauth2.googleapis.com/token"
        # Raises here if the key is malformed / cryptography is unavailable, so a
        # bad key is reported clearly at load time.
        self._key = serialization.load_pem_private_key(
            info["private_key"].encode("utf-8"), password=None
        )
        self._token: Optional[str] = None
        self._exp: float = 0.0

    def _sign(self, message: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        return self._key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    def access_token(self) -> str:
        """Return a cached token, minting a fresh one when it's within 60s of
        expiry. Blocking (does one HTTPS POST) — call via run_in_executor."""
        now = time.time()
        if self._token and now < self._exp - 60:
            return self._token

        issued = int(now)
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": self.client_email,
            "scope": " ".join(_SCOPES),
            "aud": self.token_uri,
            "iat": issued,
            "exp": issued + 3600,
        }
        signing_input = (
            _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
            + "."
            + _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
        ).encode("ascii")
        assertion = (
            signing_input.decode("ascii") + "." + _b64url(self._sign(signing_input))
        )
        resp = httpx.post(
            self.token_uri,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
            },
            timeout=10.0,
        )
        resp.raise_for_status()
        body = resp.json()
        self._token = body["access_token"]
        self._exp = time.time() + int(body.get("expires_in", 3600))
        return self._token


def _fresh_access_token(creds) -> str:
    # Blocking refresh — call via run_in_executor.
    return creds.access_token()


async def send_fcm(
    tokens: list, title: str, body: str, data: Optional[dict] = None
) -> None:
    """Send a notification to each token via FCM HTTP v1. Best-effort — never
    raises. Tokens FCM reports as unregistered/invalid are pruned from the DB."""
    creds = _get_credentials()
    if not creds or not tokens:
        return
    try:
        loop = asyncio.get_event_loop()
        access_token = await loop.run_in_executor(None, _fresh_access_token, creds)
        project_id = creds.project_id
    except Exception as e:
        logger.warning(f"FCM: token refresh failed: {e}")
        return

    from ..crud import remove_fcm_token

    url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload_data = {str(k): str(v) for k, v in (data or {}).items()}

    async with httpx.AsyncClient(timeout=10.0) as client:
        for token in tokens:
            msg = {
                "message": {
                    "token": token,
                    "notification": {"title": title, "body": body},
                    "data": payload_data,
                    "android": {"priority": "high"},
                }
            }
            try:
                r = await client.post(url, headers=headers, json=msg)
                if r.status_code == 200:
                    continue
                txt = r.text.lower()
                if r.status_code in (400, 404) and (
                    "unregistered" in txt
                    or "not-registered" in txt
                    or "invalid-argument" in txt
                    or "invalid registration" in txt
                ):
                    await remove_fcm_token(token)
                else:
                    logger.warning(f"FCM send {r.status_code}: {r.text[:200]}")
            except Exception as e:
                logger.warning(f"FCM send error: {e}")


async def send_fcm_report(
    tokens: list, title: str, body: str, data: Optional[dict] = None
) -> dict:
    """Like send_fcm but returns a structured report for diagnostics, so a test
    endpoint can tell the user *why* nothing arrived (no credentials, no
    registered device, or a specific FCM rejection). Never raises. Invalid
    tokens are still pruned from the DB.

    Returns: {
        push_enabled: bool,   # server has SILNT_FCM_CREDENTIALS loaded
        tokens: int,          # how many device tokens were tried
        sent: int,            # accepted by FCM (200)
        pruned: int,          # removed because FCM said unregistered/invalid
        errors: [str],        # human-readable failure reasons
    }
    """
    report = {"push_enabled": False, "tokens": len(tokens), "sent": 0,
              "pruned": 0, "errors": []}

    creds, reason = _load_credentials()
    if not creds:
        report["errors"].append(reason or "Server has no FCM credentials.")
        return report
    report["push_enabled"] = True
    if not tokens:
        report["errors"].append("No device tokens registered for this user.")
        return report

    try:
        loop = asyncio.get_event_loop()
        access_token = await loop.run_in_executor(None, _fresh_access_token, creds)
        project_id = creds.project_id
    except Exception as e:
        report["errors"].append(f"OAuth token refresh failed: {e}")
        return report

    from ..crud import remove_fcm_token

    url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload_data = {str(k): str(v) for k, v in (data or {}).items()}

    async with httpx.AsyncClient(timeout=10.0) as client:
        for token in tokens:
            msg = {
                "message": {
                    "token": token,
                    "notification": {"title": title, "body": body},
                    "data": payload_data,
                    "android": {"priority": "high"},
                }
            }
            try:
                r = await client.post(url, headers=headers, json=msg)
                if r.status_code == 200:
                    report["sent"] += 1
                    continue
                txt = r.text.lower()
                if r.status_code in (400, 404) and (
                    "unregistered" in txt
                    or "not-registered" in txt
                    or "invalid-argument" in txt
                    or "invalid registration" in txt
                ):
                    await remove_fcm_token(token)
                    report["pruned"] += 1
                    report["errors"].append(
                        f"Token …{token[-8:]} was invalid/unregistered (pruned)."
                    )
                else:
                    report["errors"].append(
                        f"FCM {r.status_code}: {r.text[:160]}"
                    )
            except Exception as e:
                report["errors"].append(f"send error: {e}")
    return report
