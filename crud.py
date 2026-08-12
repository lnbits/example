import json
import time
import secrets
import os
import hashlib
import hmac
from typing import Optional, Tuple, List
from lnbits.db import Database
from lnbits.helpers import urlsafe_short_hash
from .helpers.appenv import silnt_env
from .models import (
    Config,
    BackendConfig,
    WalletAccount,
    UTXORecord,
    WalletAddress,
    CloudflareConfig,
    NtfyConfig,
    UpdateUtxoLabel,
    TrustedDevice,
    UserPrefs,
    AdminAlert,
    Bip353Request,
    BoltzSwapRecord
)

from .models import PayjoinDescriptor, PayjoinRequest, PayjoinContact
from embit.descriptor import Descriptor, Key
from embit.descriptor.arguments import AllowedDerivation
from embit.networks import NETWORKS
from datetime import datetime, timedelta, timezone

db = Database("ext_silnt")

# Singleton row ID for the global blindbit config
DEFAULT_CONFIG_NETWORK = "signet"
CF_CONFIG_ID = "cloudflare_config"
NTFY_CONFIG_ID = "ntfy_config"
BIP352_CHANGE_LABEL_INDEX = 1

async def create_silnt_wallet(wallet: WalletAccount) -> WalletAccount:
    await db.insert("silnt.wallets", wallet)
    return wallet


async def get_silnt_wallet(wallet_id: str) -> Optional[WalletAccount]:
    return await db.fetchone(
        "SELECT * FROM silnt.wallets WHERE id = :id",
        {"id": wallet_id},
        WalletAccount,
    )


async def get_silnt_wallets(
    user: str, network: Optional[str] = None
) -> list[WalletAccount]:
    if network:
        return await db.fetchall(
            'SELECT * FROM silnt.wallets WHERE "user" = :user AND network = :network ORDER BY network, title',
            {"user": user, "network": network},
            WalletAccount,
        )
    return await db.fetchall(
        'SELECT * FROM silnt.wallets WHERE "user" = :user ORDER BY network, title',
        {"user": user},
        WalletAccount,
    )


async def delete_silnt_wallet(wallet_id: str) -> None:
    await db.execute(
        "DELETE FROM silnt.wallets WHERE id = :id",
        {"id": wallet_id},
    )
    # A deleted wallet must not keep a stored scan key on the server.
    await db.execute(
        "DELETE FROM silnt.background_scan WHERE wallet_id = :id",
        {"id": wallet_id},
    )


# ── Background scanning (opt-in "Remote Scanner") ─────────────────────────────
# Stores ONLY the scan private key (detection capability), encrypted at rest.
# Presence of a row == opted in. The spend key is never stored.
async def enable_background_scan(wallet_id: str, scan_secret_hex: str) -> None:
    enc = _pj_encrypt(scan_secret_hex)
    await db.execute(
        """INSERT INTO silnt.background_scan (wallet_id, scan_secret)
           VALUES (:wid, :sk)
           ON CONFLICT (wallet_id) DO UPDATE SET scan_secret = EXCLUDED.scan_secret""",
        {"wid": wallet_id, "sk": enc},
    )


async def disable_background_scan(wallet_id: str) -> None:
    await db.execute(
        "DELETE FROM silnt.background_scan WHERE wallet_id = :wid", {"wid": wallet_id}
    )


async def disable_all_background_scans_for_user(user_id: str) -> None:
    """Remove the uploaded scan key for every wallet the user owns. Used by the
    mobile duress action so a coerced unlock also revokes server-side scanning."""
    await db.execute(
        """DELETE FROM silnt.background_scan
           WHERE wallet_id IN (SELECT id FROM silnt.wallets WHERE "user" = :uid)""",
        {"uid": user_id},
    )


async def is_background_scan_enabled(wallet_id: str) -> bool:
    row = await db.fetchone(
        "SELECT 1 FROM silnt.background_scan WHERE wallet_id = :wid", {"wid": wallet_id}
    )
    return row is not None


async def get_background_scan_secret(wallet_id: str) -> Optional[str]:
    row = await db.fetchone(
        "SELECT scan_secret FROM silnt.background_scan WHERE wallet_id = :wid",
        {"wid": wallet_id},
    )
    if not row:
        return None
    try:
        sk = _pj_decrypt(row["scan_secret"]) or ""
    except Exception:
        return None
    # A 32-byte key is 64 hex chars — exactly AES-block-aligned — so AESCipher can
    # leave a trailing padding block on the decrypted string. Extract just the
    # leading 64-hex key so bytes.fromhex() doesn't choke on trailing bytes.
    import re
    m = re.match(r"[0-9a-fA-F]{64}", sk.strip())
    return m.group(0) if m else None


async def list_background_scan_wallet_ids() -> list:
    rows = await db.fetchall("SELECT wallet_id FROM silnt.background_scan")
    return [r["wallet_id"] for r in rows]


async def list_background_scan_networks() -> list:
    """Distinct networks among wallets opted into background scanning. Lets the
    scan loop poll one chain tip per active network per tick, instead of one per
    wallet."""
    rows = await db.fetchall(
        """SELECT DISTINCT w.network
             FROM silnt.background_scan b
             JOIN silnt.wallets w ON w.id = b.wallet_id"""
    )
    return [r["network"] for r in rows if r["network"]]


# ── Push (FCM) device tokens ─────────────────────────────────────────────────
async def register_fcm_token(user_id: str, token: str) -> None:
    """Associate a device push token with a user. Re-registering a token that was
    seen under another user (device reassigned) moves it to the current user."""
    await db.execute(
        """INSERT INTO silnt.fcm_tokens (token, user_id)
           VALUES (:tok, :uid)
           ON CONFLICT (token) DO UPDATE SET user_id = EXCLUDED.user_id""",
        {"tok": token, "uid": user_id},
    )


async def remove_fcm_token(token: str) -> None:
    await db.execute(
        "DELETE FROM silnt.fcm_tokens WHERE token = :tok", {"tok": token}
    )


async def list_fcm_tokens_for_user(user_id: str) -> list:
    rows = await db.fetchall(
        "SELECT token FROM silnt.fcm_tokens WHERE user_id = :uid", {"uid": user_id}
    )
    return [r["token"] for r in rows]


async def delete_utxos_for_wallet(wallet_id: str) -> None:
    await db.execute(
        "DELETE FROM silnt.utxos WHERE wallet_id = :wallet_id",
        {"wallet_id": wallet_id},
    )


async def get_sp_address(wallet_id: str) -> str:
    return await db.fetchall(
        """
        SELECT sp_address FROM silnt.wallets WHERE id = :wallet_id        
        """,
        {"wallet_id": wallet_id},
        str,
    )


async def get_hr_address(wallet_id: str) -> str:
    return await db.fetchall(
        """
        SELECT hr_address FROM silnt.wallets WHERE id = :wallet_id        
        """,
        {"wallet_id": wallet_id},
        str,
    )


async def update_hr_address(wallet_id: str, hr_address: str) -> Optional[WalletAccount]:
    await db.execute(
        "UPDATE silnt.wallets SET hr_address = :hra WHERE id = :wid",
        {"hra": hr_address, "wid": wallet_id},
    )
    return await db.fetchone(
        "SELECT * FROM silnt.wallets WHERE id = :wid",
        {"wid": wallet_id},
        WalletAccount,
    )


async def update_last_height(
    wallet_id: str, last_height: int
) -> Optional[WalletAccount]:
    await db.execute(
        "UPDATE silnt.wallets SET last_height = :lh WHERE id = :wid",
        {"lh": last_height, "wid": wallet_id},
    )
    return await db.fetchone(
        "SELECT * FROM silnt.wallets WHERE id = :wid",
        {"wid": wallet_id},
        WalletAccount,
    )


async def update_balance(wallet_id: str, balance: int) -> Optional[WalletAccount]:
    await db.execute(
        "UPDATE silnt.wallets SET balance = :bal WHERE id = :wid",
        {"bal": balance, "wid": wallet_id},
    )
    return await db.fetchone(
        "SELECT * FROM silnt.wallets WHERE id = :wid",
        {"wid": wallet_id},
        WalletAccount,
    )


async def update_title(wallet_id: str, title: str) -> Optional[WalletAccount]:
    await db.execute(
        "UPDATE silnt.wallets SET title = :ttl WHERE id = :wid",
        {"ttl": title, "wid": wallet_id},
    )
    return await db.fetchone(
        "SELECT * FROM silnt.wallets WHERE id = :wid",
        {"wid": wallet_id},
        WalletAccount,
    )


async def get_utxos_for_wallet(wallet_id: str) -> list[UTXORecord]:
    return await db.fetchall(
        "SELECT * FROM silnt.utxos WHERE wallet_id = :wallet_id ORDER BY timestamp DESC",
        {"wallet_id": wallet_id},
        UTXORecord,
    )


async def insert_utxos_for_wallet(wallet_id: str, utxos: list) -> tuple:
    """Upsert the given UTXOs. Returns (count, amount_sats) of rows that were
    NEWLY inserted — re-detecting a UTXO that already exists (e.g. on a rescan)
    is an UPDATE, not a discovery, so it must not be counted as "found". The
    amount is the summed value of just those new rows (used for notifications)."""
    newly_inserted = 0
    newly_amount = 0
    for utxo in utxos:
        row = utxo.to_db_row(wallet_id)
        # Tolerate rows from a to_db_row() that predates the label_index column
        # (avoids a missing-bind-parameter error if scan.py isn't updated yet).
        row.setdefault("label_index", None)
        already = await db.fetchone(
            "SELECT 1 FROM silnt.utxos "
            "WHERE txid = :txid AND vout = :vout AND wallet_id = :wallet_id",
            {"txid": row["txid"], "vout": row["vout"], "wallet_id": wallet_id},
        )
        await db.execute(
            """INSERT INTO silnt.utxos
                 (txid, vout, amount, priv_key_tweak, pub_key, utxo_state, timestamp, wallet_id, label, label_index)
               VALUES
                 (:txid, :vout, :amount, :priv_key_tweak, :pub_key, :utxo_state, :timestamp, :wallet_id, :label, :label_index)
               ON CONFLICT (txid, vout, wallet_id) DO UPDATE SET
                 amount         = EXCLUDED.amount,
                 priv_key_tweak = EXCLUDED.priv_key_tweak,
                 pub_key        = EXCLUDED.pub_key,
                 utxo_state     = CASE
                     WHEN silnt.utxos.utxo_state IN ('spent', 'unconfirmed_spent')
                     THEN silnt.utxos.utxo_state
                     ELSE EXCLUDED.utxo_state
                 END,
                 label = COALESCE(silnt.utxos.label, EXCLUDED.label),
                 label_index = COALESCE(silnt.utxos.label_index, EXCLUDED.label_index)
            """,
            row,
        )
        if not already:
            newly_inserted += 1
            try:
                newly_amount += int(row.get("amount") or 0)
            except (TypeError, ValueError):
                pass
    return newly_inserted, newly_amount


async def update_unconfirmed_utxo(wallet_id: str, txid: str):
    await db.execute(
        "UPDATE silnt.utxos SET utxo_state = 'unconfirmed_spent' WHERE txid = :txid AND wallet_id = :wallet_id",
        {"txid": txid, "wallet_id": wallet_id},
    )


async def get_wallet_addresses(wallet_id: str) -> list:
    return await db.fetchall(
        "SELECT * FROM silnt.wallet_addresses WHERE wallet_id = :wallet_id ORDER BY label_index ASC",
        {"wallet_id": wallet_id},
    )

async def get_wallet_address(id: str) -> Optional[WalletAddress]:
    return await db.fetchone(
        "SELECT * FROM silnt.wallet_addresses WHERE id = :id",
        {"id": id},
        WalletAddress
    )
    
async def count_wallet_addresses(wallet_id: str) -> int:
    row = await db.fetchone(
        "SELECT COUNT(*) as cnt FROM silnt.wallet_addresses WHERE wallet_id = :wallet_id",
        {"wallet_id": wallet_id},
    )
    return row["cnt"] if row else 0


async def insert_wallet_address(
    wallet_id: str, sp_address: str, label_index: int, address_id
) -> None:
    await db.execute(
        """INSERT INTO silnt.wallet_addresses (id, wallet_id, sp_address, label_index, created_at)
           VALUES (:id, :wallet_id, :sp_address, :label_index, :created_at)""",
        {
            "id": address_id,
            "wallet_id": wallet_id,
            "sp_address": sp_address,
            "label_index": label_index,
            "created_at": int(time.time()),
        },
    )


async def delete_wallet_label_addresses(wallet_id: str) -> None:
    await db.execute(
        "DELETE FROM silnt.wallet_addresses WHERE wallet_id = :wallet_id",
        {"wallet_id": wallet_id},
    )


async def delete_wallet_label_address(address_id: str, wallet_id: str) -> None:
    await db.execute(
        "DELETE FROM silnt.wallet_addresses WHERE id = :id AND wallet_id = :wallet_id",
        {"id": address_id, "wallet_id": wallet_id},
    )


# ── Global admin-only backend config ───────────────────────────────────────


async def get_backend_config(network: str) -> BackendConfig:
    row = await db.fetchone(
        "SELECT json_data FROM silnt.backend_config WHERE id = :id",
        {"id": network},
    )
    if not row:
        return BackendConfig()
    return BackendConfig(**json.loads(row["json_data"]))


async def update_backend_config(config: BackendConfig, network: str) -> BackendConfig:
    json_data = config.json()
    existing = await db.fetchone(
        "SELECT id FROM silnt.backend_config WHERE id = :id",
        {"id": network},
    )
    if existing:
        await db.execute(
            "UPDATE silnt.backend_config SET json_data = :json_data WHERE id = :id",
            {"json_data": json_data, "id": network},
        )
    else:
        await db.execute(
            "INSERT INTO silnt.backend_config (id, json_data) VALUES (:id, :json_data)",
            {"id": network, "json_data": json_data},
        )
    return config


async def get_cloudflare_config() -> CloudflareConfig:
    row = await db.fetchone(
        "SELECT json_data FROM silnt.backend_config WHERE id = :id",
        {"id": CF_CONFIG_ID},
    )
    cfg = CloudflareConfig(**json.loads(row["json_data"])) if row else CloudflareConfig()
    # BitMail/DNS domain is deployment config, not an admin-editable field.
    # Source it from SILNT_BITMAIL_DOMAIN when set; otherwise keep whatever is
    # stored (back-compat). Strip a leading dot in case someone reuses the
    # cookie-domain form (".thrilla.me" → "thrilla.me").
    env_domain = silnt_env("SILNT_BITMAIL_DOMAIN").strip().lstrip(".")
    if env_domain:
        cfg.domain = env_domain
    return cfg


async def update_cloudflare_config(config: CloudflareConfig) -> CloudflareConfig:
    # Domain is not admin-editable — force it from the env var (or keep the
    # currently-effective value), ignoring whatever the client sent.
    env_domain = silnt_env("SILNT_BITMAIL_DOMAIN").strip().lstrip(".")
    if env_domain:
        config.domain = env_domain
    else:
        # No env override: preserve the existing stored domain rather than let
        # the client change it.
        existing = await db.fetchone(
            "SELECT json_data FROM silnt.backend_config WHERE id = :id",
            {"id": CF_CONFIG_ID},
        )
        if existing:
            try:
                config.domain = CloudflareConfig(**json.loads(existing["json_data"])).domain
            except Exception:
                pass
    json_data = config.json()
    existing = await db.fetchone(
        "SELECT id FROM silnt.backend_config WHERE id = :id",
        {"id": CF_CONFIG_ID},
    )
    if existing:
        await db.execute(
            "UPDATE silnt.backend_config SET json_data = :json_data WHERE id = :id",
            {"json_data": json_data, "id": CF_CONFIG_ID},
        )
    else:
        await db.execute(
            "INSERT INTO silnt.backend_config (id, json_data) VALUES (:id, :json_data)",
            {"id": CF_CONFIG_ID, "json_data": json_data},
        )
    return config



async def get_ntfy_config() -> NtfyConfig:
    row = await db.fetchone(
        "SELECT json_data FROM silnt.backend_config WHERE id = :id",
        {"id": NTFY_CONFIG_ID},
    )
    return NtfyConfig(**json.loads(row["json_data"])) if row else NtfyConfig()


async def update_ntfy_config(config: NtfyConfig) -> NtfyConfig:
    json_data = config.json()
    existing = await db.fetchone(
        "SELECT id FROM silnt.backend_config WHERE id = :id",
        {"id": NTFY_CONFIG_ID},
    )
    if existing:
        await db.execute(
            "UPDATE silnt.backend_config SET json_data = :json_data WHERE id = :id",
            {"json_data": json_data, "id": NTFY_CONFIG_ID},
        )
    else:
        await db.execute(
            "INSERT INTO silnt.backend_config (id, json_data) VALUES (:id, :json_data)",
            {"id": NTFY_CONFIG_ID, "json_data": json_data},
        )
    return config


async def send_ntfy_notification(
    title: str, message: str, tags: Optional[list] = None, priority: Optional[str] = None
) -> dict:
    """
    Publish a notification to all configured ntfy topics. Best-effort: never
    raises — returns a small summary so callers/endpoints can report status.
    Does nothing (and reports disabled) when ntfy is off or misconfigured.
    """
    import httpx

    cfg = await get_ntfy_config()
    if not cfg.enabled:
        return {"sent": 0, "skipped": "disabled"}
    server = (cfg.server_url or "https://ntfy.sh").rstrip("/")
    topics = [t.strip() for t in (cfg.topics or []) if t and t.strip()]
    if not server or not topics:
        return {"sent": 0, "skipped": "not_configured"}

    # The ntfy Title is sent as an HTTP header, which must be ASCII. A non-ASCII
    # char (e.g. an emoji) would make httpx raise and drop the notification, so
    # coerce it to ASCII here (emoji belong in Tags/'body, not the title header).
    safe_title = (title or "").encode("ascii", "ignore").decode("ascii").strip() or "siLNt"
    headers = {"Title": safe_title, "Priority": priority or cfg.priority or "default"}
    if tags:
        headers["Tags"] = ",".join(tags)
    # Auth: HTTP Basic (username/password) for self-hosted servers that require
    # it; fall back to a bearer access token if that's how the server is set up.
    auth = None
    if cfg.username:
        auth = (cfg.username, cfg.password or "")
    elif cfg.access_token:
        headers["Authorization"] = f"Bearer {cfg.access_token}"

    sent, errors = 0, []
    async with httpx.AsyncClient(timeout=10.0) as c:
        for topic in topics:
            try:
                r = await c.post(
                    f"{server}/{topic}",
                    content=message.encode("utf-8"),
                    headers=headers,
                    auth=auth,
                )
                if r.status_code < 300:
                    sent += 1
                else:
                    errors.append(f"{topic}: HTTP {r.status_code}")
            except Exception as e:
                errors.append(f"{topic}: {e}")
    return {"sent": sent, "topics": len(topics), "errors": errors}


HEALTH_STATE_ID = "service_health_state"


async def notify_service_health_change(service: str, is_up: bool, detail: str = "") -> None:
    """
    Fire an ntfy notification ONLY when a service's up/down state changes
    (up→down or down→up), so a persistently-down service doesn't spam on every
    health poll. Last-known state is stored as a small JSON blob in the config
    table. Best-effort — never raises.
    """
    try:
        from loguru import logger as _logger
        _logger.warning(f"[health] {service} reported {'UP' if is_up else 'DOWN'} (detail={detail!r})")
    except Exception:
        pass
    # Per-service row id, so BlindBit and Fulcrum checks (which run as separate,
    # near-concurrent requests) never do a racy read-modify-write on ONE shared
    # row and clobber each other's state — which silently swallows a service's
    # up/down transitions (the cause of Fulcrum's recovery ntfy going missing).
    state_id = f"{HEALTH_STATE_ID}:{service}"
    try:
        row = await db.fetchone(
            "SELECT json_data FROM silnt.backend_config WHERE id = :id",
            {"id": state_id},
        )
        prev = json.loads(row["json_data"]).get("up") if row else None
    except Exception:
        prev = None

    if prev is not None and prev == is_up:
        return                          # no change → no notification

    # Persist the new state first (so a send failure doesn't cause repeat sends).
    try:
        payload = json.dumps({"up": is_up})
        exists = await db.fetchone(
            "SELECT id FROM silnt.backend_config WHERE id = :id", {"id": state_id}
        )
        if exists:
            await db.execute(
                "UPDATE silnt.backend_config SET json_data = :j WHERE id = :id",
                {"j": payload, "id": state_id},
            )
        else:
            await db.execute(
                "INSERT INTO silnt.backend_config (id, json_data) VALUES (:id, :j)",
                {"id": state_id, "j": payload},
            )
    except Exception:
        pass

    # First-ever observation (prev is None): stay quiet if UP (normal startup),
    # but DO alert if it's already DOWN.
    if prev is None and is_up:
        return

    if is_up:
        await send_ntfy_notification(
            title=f"{service} recovered",
            message=f"{service} is reachable again." + (f" {detail}" if detail else ""),
            tags=["white_check_mark"],
            priority="default",
        )
    else:
        await send_ntfy_notification(
            title=f"{service} is DOWN",
            message=f"{service} is not reachable." + (f" {detail}" if detail else ""),
            tags=["rotating_light"],
            priority="high",
        )


async def reset_service_health_state() -> None:
    """Delete the stored service health-state row so up/down tracking restarts
    clean (the next health check is treated as a first observation). Called when
    ntfy config is saved, so stale state can't permanently suppress alerts."""
    await db.execute(
        "DELETE FROM silnt.backend_config WHERE id = :id", {"id": HEALTH_STATE_ID}
    )

async def count_silnt_wallets(user: str, network: Optional[str] = None) -> int:
    if network:
        row = await db.fetchone(
            'SELECT COUNT(*) AS c FROM silnt.wallets WHERE "user" = :user AND network = :network',
            {"user": user, "network": network},
        )
    else:
        row = await db.fetchone(
            'SELECT COUNT(*) AS c FROM silnt.wallets WHERE "user" = :user',
            {"user": user},
        )
    return row["c"] if row else 0

async def update_utxo_label_by_txid(
    txid: str, label: Optional[str], wallet_id: Optional[str]
) -> int:
    """
    Set or clear the label on UTXO(s) matching the given txid.
    Returns the number of rows updated. Empty string label is treated as NULL.
    Optionally scoped to a specific wallet_id for safety.
    """
    label_value = (label or "").strip() or None
    if wallet_id:
        result = await db.execute(
            """UPDATE silnt.utxos SET label = :label
               WHERE txid = :txid AND wallet_id = :wallet_id""",
            {"label": label_value, "txid": txid, "wallet_id": wallet_id},
        )
    else:
        result = await db.execute(
            "UPDATE silnt.utxos SET label = :label WHERE txid = :txid",
            {"label": label_value, "txid": txid},
        )
    return getattr(result, "rowcount", 0) or 0


async def get_utxos_by_txid(txid: str) -> list:
    """Return all UTXO rows for a given txid (may have multiple vouts)."""
    rows = await db.fetchall(
        "SELECT * FROM silnt.utxos WHERE txid = :txid", {"txid": txid}
    )
    return [UTXORecord(**dict(r)) for r in rows]

async def get_next_label_index(wallet_id: str) -> int:
    """
    Return the LOWEST free label index >= 2 for this wallet (m=0 is the BIP-352
    change label, m=1 is the legacy change index, both reserved). Using the lowest
    free index — rather than MAX+1 — means deleting a labeled address (e.g. m=2)
    frees that slot, so the next generated address reuses it instead of skipping
    to m=4 and leaving a permanent hole (and drifting past the wallet's small
    labeled-address range).
    """
    rows = await db.fetchall(
        "SELECT label_index FROM silnt.wallet_addresses WHERE wallet_id = :wid",
        {"wid": wallet_id},
    )
    used = {int(r["label_index"]) for r in rows if r["label_index"] is not None}
    idx = BIP352_CHANGE_LABEL_INDEX + 1   # start at 2
    while idx in used:
        idx += 1
    return idx


async def address_exists(wallet_id: str, sp_address: str) -> bool:
    row = await db.fetchone(
        """SELECT 1 FROM silnt.wallet_addresses
           WHERE wallet_id = :wid AND sp_address = :addr""",
        {"wid": wallet_id, "addr": sp_address},
    )
    return row is not None

async def label_index_taken(wallet_id: str, label_index: int) -> bool:
    row = await db.fetchone(
        """SELECT 1 FROM silnt.wallet_addresses
           WHERE wallet_id = :wid AND label_index = :idx""",
        {"wid": wallet_id, "idx": label_index},
    )
    return row is not None


async def ensure_labeled_address_row(
    wallet_id: str, sp_address: str, label_index: int
) -> bool:
    """
    Idempotently ensure a wallet_addresses row exists for a labeled address that
    a scan actually found funds on. Used to restore labeled-address rows after a
    seed reimport WITHOUT over-creating: only labels the wallet genuinely used
    (received on) come back, so count_wallet_addresses stays accurate and the
    per-wallet address limit isn't falsely tripped. Returns True if a new row was
    inserted. Never touches the change label (m=1) or base (m=0).

    NOTE: wallet_addresses' primary key is sp_address ALONE, so the same SP
    address can exist only once table-wide. An SP address is deterministic from
    the seed, so after a delete+reimport the same labeled address re-derives while
    a stale row (old wallet_id) may still exist. We therefore check by sp_address
    globally and, if a row exists under a different wallet_id, re-point it to this
    wallet rather than attempting a duplicate insert (which would violate the PK).
    """
    if label_index is None or label_index <= BIP352_CHANGE_LABEL_INDEX:
        return False
    existing = await db.fetchone(
        "SELECT wallet_id, label_index FROM silnt.wallet_addresses WHERE sp_address = :addr",
        {"addr": sp_address},
    )
    if existing is not None:
        # Heal a stale row from a previous incarnation: re-point it to the
        # current wallet (and set the label index if it was missing). Preserves
        # any user-set label already on the row.
        if existing["wallet_id"] != wallet_id or existing["label_index"] != label_index:
            await db.execute(
                """UPDATE silnt.wallet_addresses
                      SET wallet_id = :wid, label_index = :idx
                    WHERE sp_address = :addr""",
                {"wid": wallet_id, "idx": label_index, "addr": sp_address},
            )
        return False
    # No row anywhere for this address, and the index isn't already used here.
    if await label_index_taken(wallet_id, label_index):
        return False
    await insert_wallet_address(wallet_id, sp_address, label_index, urlsafe_short_hash())
    return True

async def save_wallet_address(
    wallet_id: str,
    sp_address: str,
    label: Optional[str],
    label_index: int,
) -> dict:
    addr_id = secrets.token_urlsafe(16)
    now     = int(time.time())
    await db.execute(
        """INSERT INTO silnt.wallet_addresses
              (id, wallet_id, sp_address, label, label_index, created_at)
           VALUES (:id, :wid, :addr, :label, :idx, :ts)""",
        {
            "id":    addr_id,
            "wid":   wallet_id,
            "addr":  sp_address,
            "label": (label or "").strip() or None,
            "idx":   label_index,
            "ts":    now,
        },
    )
    return {
        "id":          addr_id,
        "wallet_id":   wallet_id,
        "sp_address":  sp_address,
        "label":       label,
        "label_index": label_index,
        "created_at":  now,
    }

async def get_unspent_dust_check(wallet_id: str) -> list[dict]:
    rows = await db.fetchall(
        """SELECT txid, vout, amount, suspected_dust FROM silnt.utxos
           WHERE wallet_id = :wid AND utxo_state = 'unspent'""",
        {"wid": wallet_id}        
    )
    return [dict(r) for r in rows]

async def update_utxo_dust_flag(txid: str, vout: int, flag: bool) -> None:
    await db.execute(
        """UPDATE silnt.utxos SET suspected_dust = :flag
           WHERE txid = :txid AND vout = :vout""",
        {"flag": flag, "txid": txid, "vout": vout},
    )


async def update_utxo_frozen(txid: str, vout: int, frozen: bool) -> None:
    await db.execute(
        """UPDATE silnt.utxos SET frozen = :frozen
           WHERE txid = :txid AND vout = :vout""",
        {"frozen": frozen, "txid": txid, "vout": vout},
    )

async def owner_check_dust(txid: str, vout: int):
    return await db.fetchone(
        "SELECT wallet_id FROM silnt.utxos WHERE txid = :txid AND vout = :vout",
        {"txid": txid, "vout": vout},
    )

async def get_eligible_utxos(
    wallet_id: str,
    txid_vout_pairs: list[tuple[str, int]],
) -> list[dict]:
    """
    Return rows from silnt.utxos that are:
      - belong to wallet_id
      - state = 'unspent'
      - NOT frozen
      - match one of the (txid, vout) pairs supplied
    """
    if not txid_vout_pairs:
        return []

    # Build a parameterized IN-clause using row tuples
    placeholders = []
    params = {"wid": wallet_id}
    for i, (txid, vout) in enumerate(txid_vout_pairs):
        placeholders.append(f"(:t{i}, :v{i})")
        params[f"t{i}"] = txid
        params[f"v{i}"] = vout

    sql = f"""
        SELECT txid, vout, amount FROM silnt.utxos
        WHERE wallet_id = :wid
          AND utxo_state = 'unspent'
          AND COALESCE(frozen, FALSE) = FALSE
          AND (txid, vout) IN ({", ".join(placeholders)})
    """
    rows = await db.fetchall(sql, params)
    return [dict(r) for r in rows]

async def update_address_label(addr_id: str, label: Optional[str]) -> int:
    """
    Update only the label string on a labeled address. Returns rows affected.
    Empty string is stored as NULL.
    """
    label_value = (label or "").strip() or None
    result = await db.execute(
        "UPDATE silnt.wallet_addresses SET label = :label WHERE id = :id",
        {"label": label_value, "id": addr_id},
    )
    return getattr(result, "rowcount", 0) or 0

async def get_wallet_unspent_utxos_for_dust_check(wallet_id: str) -> list[dict]:
    rows = await db.fetchall(
        """SELECT txid, vout, amount, suspected_dust, label_index
           FROM silnt.utxos
           WHERE wallet_id = :wid AND utxo_state = 'unspent'""",
        {"wid": wallet_id},
    )
    return [dict(r) for r in rows]


async def get_wallet_owned_txids(wallet_id: str) -> set[str]:
    rows = await db.fetchall(
        "SELECT txid FROM silnt.utxos WHERE wallet_id = :wid",
        {"wid": wallet_id},
    )
    return {r["txid"] for r in rows}


async def mark_utxos_spent_by_tx(
    wallet_id:       str,
    input_outpoints: list[tuple[str, int]],
    spending_txid:   str,
) -> int:
    """Mark UTXOs as spent by a tx we broadcast — also records spent_at timestamp."""
    if not input_outpoints:
        return 0    
    now = int(time.time())

    placeholders = []
    params = {
        "wid":           wallet_id,
        "spending_txid": spending_txid,
        "spent_at":      now,
    }
    for i, (in_txid, in_vout) in enumerate(input_outpoints):
        placeholders.append(f"(:t{i}, :v{i})")
        params[f"t{i}"] = in_txid
        params[f"v{i}"] = in_vout

    sql = f"""
        UPDATE silnt.utxos
        SET utxo_state    = 'unconfirmed_spent',
            spent_in_txid = :spending_txid,
            spent_at      = :spent_at
        WHERE wallet_id = :wid
          AND (txid, vout) IN ({", ".join(placeholders)})
    """
    result = await db.execute(sql, params)
    return getattr(result, "rowcount", 0) or 0

async def mark_utxos_spent_by_outpoints(
    wallet_id:     str,
    outpoints:     list[tuple[str, int]],   # [(txid, vout), ...]
    spending_txid: str,
) -> int:
    if not outpoints:
        return 0
    now = int(time.time())
    affected = 0
    for (in_txid, in_vout) in outpoints:
        result = await db.execute(
            """UPDATE silnt.utxos
                  SET utxo_state    = 'unconfirmed_spent',
                      spent_in_txid = :stxid,
                      spent_at      = :ts
                WHERE wallet_id = :wid
                  AND txid      = :txid
                  AND vout      = :vout
                  AND utxo_state IN ('unspent', 'unconfirmed')""",
            {"wid": wallet_id, "txid": in_txid, "vout": int(in_vout),
             "stxid": spending_txid, "ts": now},
        )
        affected += getattr(result, "rowcount", 0) or 0
    return affected

async def is_own_sent_tx(wallet_id: str, txid: str) -> bool:
    """
    Check if this wallet has broadcast a transaction with this txid.
    A row exists with spent_in_txid = txid iff we broadcast it.
    """
    row = await db.fetchone(
        """SELECT 1 FROM silnt.utxos
           WHERE wallet_id = :wid AND spent_in_txid = :txid
           LIMIT 1""",
        {"wid": wallet_id, "txid": txid},
    )
    return row is not None

async def get_wallet_owned_outpoints(wallet_id: str) -> set[tuple[str, int]]:
    """
    All (txid, vout) outpoints this wallet has ever owned, regardless of state.
    Used to classify funding-tx inputs as self-send vs external.
    """
    rows = await db.fetchall(
        "SELECT txid, vout FROM silnt.utxos WHERE wallet_id = :wid",
        {"wid": wallet_id},
    )
    return {(r["txid"], int(r["vout"])) for r in rows}

async def get_utxo_freeze_reason(txid: str, vout: int) -> Optional[str]:
    """Return current freeze_reason ('auto'|'manual'|None) for a UTXO."""
    row = await db.fetchone(
        "SELECT freeze_reason FROM silnt.utxos WHERE txid = :txid AND vout = :vout",
        {"txid": txid, "vout": vout},
    )
    return row["freeze_reason"] if row else None

async def set_utxo_freeze_auto(txid: str, vout: int) -> None:
    """
    Mark a UTXO as auto-frozen (dust eval owns this lock). Only acts on UTXOs that
    are not user-owned: freeze_reason NULL or already 'auto'. A 'manual' freeze or
    a 'manual_unfrozen' override is left untouched.
    """
    await db.execute(
        """UPDATE silnt.utxos
           SET frozen = TRUE, freeze_reason = 'auto'
           WHERE txid = :txid AND vout = :vout
             AND (freeze_reason IS NULL OR freeze_reason = 'auto')
        """,
        {"txid": txid, "vout": vout},
    )

async def set_utxo_freeze_manual(txid: str, vout: int) -> None:
    """Mark a UTXO as manually frozen (user owns this lock)."""
    await db.execute(
        """UPDATE silnt.utxos
           SET frozen = TRUE, freeze_reason = 'manual'
           WHERE txid = :txid AND vout = :vout""",
        {"txid": txid, "vout": vout},
    )
    
async def clear_utxo_freeze_manual(txid: str, vout: int) -> None:
    """
    User-initiated unfreeze. Clears the frozen flag regardless of who set it, and
    records freeze_reason = 'manual_unfrozen' so the dust evaluator knows this was
    a deliberate user override and must NOT auto-re-freeze it.
    """
    await db.execute(
        """UPDATE silnt.utxos
           SET frozen = FALSE, freeze_reason = 'manual_unfrozen'
           WHERE txid = :txid AND vout = :vout""",
        {"txid": txid, "vout": vout},
    )


async def clear_utxo_freeze_auto(txid: str, vout: int) -> None:
    """
    Clear an auto-freeze. NO-OP if the UTXO was manually frozen — only the
    user (via the unfreeze endpoint) can clear those.
    """
    await db.execute(
        """UPDATE silnt.utxos
           SET frozen = FALSE, freeze_reason = NULL
           WHERE txid = :txid AND vout = :vout AND freeze_reason = 'auto'""",
        {"txid": txid, "vout": vout},
    )


async def clear_utxo_freeze_manual(txid: str, vout: int) -> None:
    """User-initiated unfreeze — clears regardless of who set it."""
    await db.execute(
        """UPDATE silnt.utxos
           SET frozen = FALSE, freeze_reason = NULL
           WHERE txid = :txid AND vout = :vout""",
        {"txid": txid, "vout": vout},
    )

async def normalize_unfrozen_override(txid: str, vout: int) -> None:
    """Once a UTXO is no longer dust, drop a lingering 'manual_unfrozen' marker."""
    await db.execute(
        """UPDATE silnt.utxos SET freeze_reason = NULL
           WHERE txid = :txid AND vout = :vout AND freeze_reason = 'manual_unfrozen'""",
        {"txid": txid, "vout": vout},
    )

async def get_wallet_receives(wallet_id: str) -> list[dict]:
    """
    Group all owned UTXOs by funding txid. Each row = one tx where we received.
    Returns: [{txid, timestamp, output_sum, output_count, labels[]}, ...]
    """
    rows = await db.fetchall(
        """
        SELECT
            txid,
            MIN(timestamp)             AS timestamp,
            SUM(amount)                AS output_sum,
            COUNT(*)                   AS output_count,
            ARRAY_REMOVE(ARRAY_AGG(DISTINCT label), NULL) AS labels
        FROM silnt.utxos
        WHERE wallet_id = :wid
        GROUP BY txid
        """,
        {"wid": wallet_id},
    )
    return [
        {
            "txid":         r["txid"],
            "timestamp":    int(r["timestamp"] or 0),
            "output_sum":   int(r["output_sum"] or 0),
            "output_count": int(r["output_count"] or 0),
            "labels":       list(r["labels"] or []),
        }
        for r in rows
    ]


async def get_wallet_sends(wallet_id: str) -> list[dict]:
    """
    Group all UTXOs we've spent by spent_in_txid. Each row = one tx we sent.
    Returns: [{txid, spent_at, input_sum, input_count}, ...]
    """
    rows = await db.fetchall(
        """
        SELECT
            spent_in_txid              AS txid,
            MIN(spent_at)              AS spent_at,
            SUM(amount)                AS input_sum,
            COUNT(*)                   AS input_count
        FROM silnt.utxos
        WHERE wallet_id = :wid AND spent_in_txid IS NOT NULL
        GROUP BY spent_in_txid
        """,
        {"wid": wallet_id},
    )
    return [
        {
            "txid":        r["txid"],
            "spent_at":    int(r["spent_at"] or 0),
            "input_sum":   int(r["input_sum"] or 0),
            "input_count": int(r["input_count"] or 0),
        }
        for r in rows
    ]


async def get_utxos_for_txid(wallet_id: str, txid: str) -> list[dict]:
    """All UTXOs we own at a given funding txid (for the detail view)."""
    rows = await db.fetchall(
        """SELECT txid, vout, amount, label, label_index, utxo_state, timestamp
           FROM silnt.utxos
           WHERE wallet_id = :wid AND txid = :txid
           ORDER BY vout""",
        {"wid": wallet_id, "txid": txid},
    )
    return [dict(r) for r in rows]


async def get_utxos_spent_in_tx(wallet_id: str, txid: str) -> list[dict]:
    """All UTXOs we spent in a given tx (for the detail view's input list)."""
    rows = await db.fetchall(
        """SELECT txid, vout, amount, label, label_index, utxo_state, timestamp, spent_at
           FROM silnt.utxos
           WHERE wallet_id = :wid AND spent_in_txid = :txid
           ORDER BY timestamp""",
        {"wid": wallet_id, "txid": txid},
    )
    return [dict(r) for r in rows]


async def get_owned_pubkeys(wallet_id: str) -> set[str]:
    """All x-only output pubkeys this wallet has ever owned — used to filter
    out own change from a send tx's outputs (anything not in this set is
    treated as a recipient)."""
    rows = await db.fetchall(
        "SELECT pub_key FROM silnt.utxos WHERE wallet_id = :wid",
        {"wid": wallet_id},
    )
    return {r["pub_key"] for r in rows if r["pub_key"]}

async def add_trusted_device(
    user_id:    str,
    device_id:  str,
    user_agent: Optional[str],
    ip:         Optional[str],
    label:      Optional[str] = None,
) -> dict:
    now = int(time.time())
    row_id = secrets.token_urlsafe(16)
    await db.execute(
        """INSERT INTO silnt.trusted_devices
              (id, user_id, device_id, user_agent, ip, label, confirmed_at, last_seen_at)
           VALUES (:id, :uid, :did, :ua, :ip, :label, :ts, :ts)
           ON CONFLICT (user_id, device_id) DO UPDATE
              SET last_seen_at = EXCLUDED.last_seen_at,
                  user_agent   = EXCLUDED.user_agent,
                  ip           = EXCLUDED.ip""",
        {
            "id":    row_id,
            "uid":   user_id,
            "did":   device_id,
            "ua":    (user_agent or "")[:512],
            "ip":    (ip or "")[:64],
            "label": label,
            "ts":    now,
        },
    )
    return {"id": row_id, "device_id": device_id, "confirmed_at": now}


async def get_trusted_device(user_id: str, device_id: str) -> Optional[TrustedDevice]:
    row = await db.fetchone(
        """SELECT * FROM silnt.trusted_devices
           WHERE user_id = :uid AND device_id = :did""",
        {"uid": user_id, "did": device_id},
    )
    return TrustedDevice(**dict(row)) if row else None


async def list_trusted_devices(user_id: str) -> List[TrustedDevice]:
    rows = await db.fetchall(
        """SELECT * FROM silnt.trusted_devices
           WHERE user_id = :uid
           ORDER BY confirmed_at DESC""",
        {"uid": user_id},
    )
    return [TrustedDevice(**dict(r)) for r in rows]


async def count_trusted_devices(user_id: str) -> int:
    row = await db.fetchone(
        "SELECT COUNT(*) AS c FROM silnt.trusted_devices WHERE user_id = :uid",
        {"uid": user_id},
    )
    return int(row["c"] or 0)


async def revoke_trusted_device(user_id: str, device_row_id: str) -> int:
    result = await db.execute(
        """DELETE FROM silnt.trusted_devices
           WHERE user_id = :uid AND id = :id""",
        {"uid": user_id, "id": device_row_id},
    )
    return getattr(result, "rowcount", 0) or 0


async def revoke_all_other_devices(user_id: str, keep_device_id: str) -> int:
    result = await db.execute(
        """DELETE FROM silnt.trusted_devices
           WHERE user_id = :uid AND device_id != :keep""",
        {"uid": user_id, "keep": keep_device_id},
    )
    return getattr(result, "rowcount", 0) or 0


async def touch_trusted_device(user_id: str, device_id: str) -> None:
    """Update last_seen_at when the device makes a request."""
    await db.execute(
        """UPDATE silnt.trusted_devices
           SET last_seen_at = :ts
           WHERE user_id = :uid AND device_id = :did""",
        {"uid": user_id, "did": device_id, "ts": int(time.time())},
    )

async def get_user_prefs(user_id: str) -> Optional[UserPrefs]:
    row = await db.fetchone(
        "SELECT * FROM silnt.user_prefs WHERE user_id = :uid",
        {"uid": user_id},
    )
    return UserPrefs(**dict(row)) if row else None


async def upsert_user_prefs(
    user_id:             str,
    dust_threshold_sats: Optional[int],
) -> UserPrefs:
    now = int(time.time())
    await db.execute(
        """INSERT INTO silnt.user_prefs (user_id, dust_threshold_sats, updated_at)
           VALUES (:uid, :dts, :ts)
           ON CONFLICT (user_id) DO UPDATE
             SET dust_threshold_sats = EXCLUDED.dust_threshold_sats,
                 updated_at          = EXCLUDED.updated_at""",
        {"uid": user_id, "dts": dust_threshold_sats, "ts": now},
    )
    return UserPrefs(
        user_id             = user_id,
        dust_threshold_sats = dust_threshold_sats,
        updated_at          = now,
    )



async def get_effective_dust_threshold(
    user_id: str, network: str = DEFAULT_CONFIG_NETWORK
) -> int:
    """
    Resolve the dust threshold for a user.
    Priority:
      1. User's own prefs.dust_threshold_sats (if non-NULL and > 0)
      2. Admin's BackendConfig.dust_threshold_sats for `network` (if non-zero)
      3. Hard fallback: 5000 sats
    """
    prefs = await get_user_prefs(user_id)
    if prefs and prefs.dust_threshold_sats and prefs.dust_threshold_sats > 0:
        return int(prefs.dust_threshold_sats)
    backend = await get_backend_config(network)
    return int(backend.dust_threshold_sats or 5000)

async def create_bip353_request(
    user_id:            str,
    wallet_id:          str,
    sp_address:         str,    
    requested_username: str,
    message:            Optional[str],
    address_id:         Optional[str] = None,
) -> Bip353Request:
    row_id = secrets.token_urlsafe(16)
    now    = int(time.time())
    await db.execute(
        """INSERT INTO silnt.bip353_requests
              (id, user_id, wallet_id, address_id, sp_address, requested_username, message,
               status, created_at)
           VALUES (:id, :uid, :wid, :aid, :sp, :uname, :msg, 'pending', :ts)""",
        {
            "id":    row_id,
            "uid":   user_id,
            "wid":   wallet_id,
            "aid":   address_id,
            "sp":    sp_address,
            "uname": requested_username,
            "msg":   message,
            "ts":    now,
        },
    )
    return Bip353Request(
        id=row_id, user_id=user_id, wallet_id=wallet_id, address_id=address_id,
        sp_address=sp_address, requested_username=requested_username, message=message,
        status="pending", created_at=now,
    )

async def address_has_approved_bitmail(wallet_id: str, address_id: Optional[str]) -> bool:
    """
    True if this specific SP address (base = NULL address_id, or a labeled
    address row) has EVER had an approved BitMail. Enforces 'assign once' per
    address — the slot stays burned even after removal.
    """
    if address_id is None:
        row = await db.fetchone(
            """SELECT 1 FROM silnt.bip353_requests
               WHERE wallet_id = :wid AND address_id IS NULL AND status = 'approved'
               LIMIT 1""",
            {"wid": wallet_id},
        )
    else:
        row = await db.fetchone(
            """SELECT 1 FROM silnt.bip353_requests
               WHERE wallet_id = :wid AND address_id = :aid AND status = 'approved'
               LIMIT 1""",
            {"wid": wallet_id, "aid": address_id},
        )
    return row is not None

async def update_label_hr_address(address_id: str, hr_address: str) -> None:
    await db.execute(
        "UPDATE silnt.wallet_addresses SET hr_address = :hra WHERE id = :id",
        {"hra": hr_address, "id": address_id},
    )

async def clear_label_hr_address(address_id: str) -> None:
    await db.execute(
        "UPDATE silnt.wallet_addresses SET hr_address = NULL WHERE id = :id",
        {"id": address_id},
    )
# Also check the existing wallets.hr_address column (base addresses)
    row = await db.fetchone(
        """SELECT 1 FROM silnt.wallets
           WHERE LOWER(hr_address) LIKE LOWER(:pat)""",
        {"pat": f"{username}@%"},
    )
    if row:
        return True
    # And labeled-address BitMails (wallet_addresses.hr_address)
    row = await db.fetchone(
        """SELECT 1 FROM silnt.wallet_addresses
           WHERE LOWER(hr_address) LIKE LOWER(:pat)""",
        {"pat": f"{username}@%"},
    )
    return row is not None

async def get_user_hr_addresses(user_id: str) -> list[str]:
    rows = await db.fetchall(
        'SELECT hr_address FROM silnt.wallets '
        'WHERE "user" = :uid AND hr_address IS NOT NULL AND hr_address <> \'\'',
        {"uid": user_id},
    )
    out = [r["hr_address"] for r in rows if r["hr_address"]]
    # Labeled-address BitMails belonging to this user's wallets, too.
    label_rows = await db.fetchall(
        '''SELECT wa.hr_address FROM silnt.wallet_addresses wa
           JOIN silnt.wallets w ON w.id = wa.wallet_id
           WHERE w."user" = :uid AND wa.hr_address IS NOT NULL AND wa.hr_address <> \'\'''',
        {"uid": user_id},
    )
    out.extend(r["hr_address"] for r in label_rows if r["hr_address"])
    return out

async def get_bip353_request(req_id: str) -> Optional[Bip353Request]:
    row = await db.fetchone(
        "SELECT * FROM silnt.bip353_requests WHERE id = :id",
        {"id": req_id},
    )
    return Bip353Request(**dict(row)) if row else None


async def list_user_bip353_requests(user_id: str) -> List[Bip353Request]:
    rows = await db.fetchall(
        """SELECT * FROM silnt.bip353_requests
           WHERE user_id = :uid
           ORDER BY created_at DESC""",
        {"uid": user_id},
    )
    return [Bip353Request(**dict(r)) for r in rows]


async def list_pending_bip353_requests() -> List[Bip353Request]:
    rows = await db.fetchall(
        """SELECT * FROM silnt.bip353_requests
           WHERE status = 'pending'
           ORDER BY created_at ASC"""
    )
    return [Bip353Request(**dict(r)) for r in rows]


async def is_username_taken(username: str) -> bool:
    """Check if username is already approved + active for someone."""
    row = await db.fetchone(
        """SELECT 1 FROM silnt.bip353_requests
           WHERE (
                 (status = 'approved' AND LOWER(final_username)     = LOWER(:uname))
                OR (status = 'pending'  AND LOWER(requested_username) = LOWER(:uname))
                 )""",
        {"uname": username},
    )
    if row:
        return True
    # Also check the existing wallets.hr_address column (legacy addresses)
    row = await db.fetchone(
        """SELECT 1 FROM silnt.wallets
           WHERE LOWER(hr_address) LIKE LOWER(:pat)""",
        {"pat": f"{username}@%"},
    )
    return row is not None

async def is_username_approved_elsewhere(username: str, exclude_req_id: str) -> bool:
    """True if some OTHER approved request already holds this username."""
    row = await db.fetchone(
        """SELECT 1 FROM silnt.bip353_requests
           WHERE status = 'approved'
             AND LOWER(final_username) = LOWER(:uname)
             AND id <> :rid""",
        {"uname": username, "rid": exclude_req_id},
    )
    return row is not None

async def sp_address_has_approved_bitmail(sp_address: str) -> bool:
    """True if this Silent Payment address has EVER had an approved BitMail —
    keyed by the SP address itself, which is stable across delete+re-add of a
    labeled address (address_id is not). Enforces the permanent 'assign once'
    rule even if the user removes and re-creates the labeled address."""
    if not sp_address:
        return False
    row = await db.fetchone(
        """SELECT 1 FROM silnt.bip353_requests
           WHERE sp_address = :sp AND status = 'approved'
           LIMIT 1""",
        {"sp": sp_address},
    )
    return row is not None
    
async def update_bip353_request_status(
    req_id:        str,
    status:        str,
    processed_by:  str,
    final_username: Optional[str] = None,
    reject_reason:  Optional[str] = None,
) -> int:
    now = int(time.time())
    result = await db.execute(
        """UPDATE silnt.bip353_requests
           SET status         = :status,
               final_username = :final_username,
               reject_reason  = :reject_reason,
               processed_at   = :ts,
               processed_by   = :by
           WHERE id = :id""",
        {
            "id":             req_id,
            "status":         status,
            "final_username": final_username,
            "reject_reason":  reject_reason,
            "ts":             now,
            "by":             processed_by,
        },
    )
    return getattr(result, "rowcount", 0) or 0


async def cancel_user_request(req_id: str, user_id: str) -> int:
    """User cancels their own pending request."""
    result = await db.execute(
        """UPDATE silnt.bip353_requests
           SET status = 'cancelled', processed_at = :ts
           WHERE id = :id AND user_id = :uid AND status = 'pending'""",
        {"id": req_id, "uid": user_id, "ts": int(time.time())},
    )
    return getattr(result, "rowcount", 0) or 0

async def get_wallet_active_request(wallet_id: str) -> Optional[Bip353Request]:
    """Return the currently pending request for THIS wallet, if any."""
    row = await db.fetchone(
        """SELECT * FROM silnt.bip353_requests
           WHERE wallet_id = :wid AND status = 'pending'
           ORDER BY created_at DESC LIMIT 1""",
        {"wid": wallet_id},
    )
    return Bip353Request(**dict(row)) if row else None


async def get_wallet_last_rejected_request(wallet_id: str) -> Optional[Bip353Request]:
    """Last rejection for THIS wallet — used for per-wallet cooldown."""
    row = await db.fetchone(
        """SELECT * FROM silnt.bip353_requests
           WHERE wallet_id = :wid AND status = 'rejected'
           ORDER BY processed_at DESC LIMIT 1""",
        {"wid": wallet_id},
    )
    return Bip353Request(**dict(row)) if row else None

async def get_utxo(wallet_id: str, txid: str, vout: int) -> Optional[dict]:
    """
    Fetch a single UTXO by (wallet_id, txid, vout).
    Returns a dict with txid, vout, spent_in_txid, utxo_state — or None if absent.
    """
    rows = await db.fetchall(
        """SELECT txid, vout, spent_in_txid, utxo_state
             FROM silnt.utxos
            WHERE wallet_id = :wid AND txid = :txid AND vout = :vout""",
        {"wid": wallet_id, "txid": txid, "vout": vout},
    )
    return rows[0] if rows else None


async def restore_utxo_to_unspent(wallet_id: str, txid: str, vout: int) -> int:
    """
    Restore an unconfirmed_spent UTXO back to unspent (clears spend metadata).
    Only affects rows currently in 'unconfirmed_spent' state. Returns rowcount.
    """
    result = await db.execute(
        """UPDATE silnt.utxos
              SET utxo_state = 'unspent', spent_in_txid = NULL, spent_at = NULL
            WHERE wallet_id = :wid AND txid = :txid AND vout = :vout
              AND utxo_state = 'unconfirmed_spent'""",
        {"wid": wallet_id, "txid": txid, "vout": vout},
    )
    return getattr(result, "rowcount", 0) or 0


async def get_wallet_unspent_balance(wallet_id: str) -> int:
    """Sum of all 'unspent' UTXO amounts for a wallet."""
    rows = await db.fetchall(
        "SELECT amount FROM silnt.utxos WHERE wallet_id = :wid AND utxo_state = 'unspent'",
        {"wid": wallet_id},
    )
    return sum(r["amount"] for r in rows)

async def delete_all_silnt_data_for_user(user_id: str) -> dict:
    """
    Remove every siLNt artifact belonging to a user across ALL networks: UTXOs,
    addresses, and wallet rows. Network-agnostic — selects the user's wallets
    directly so it doesn't depend on enumerating networks. Returns counts.
    """
    wallet_rows = await db.fetchall(
        'SELECT id FROM silnt.wallets WHERE "user" = :uid',
        {"uid": user_id},
    )
    wallet_ids = [r["id"] for r in wallet_rows]
    if not wallet_ids:
        return {"wallets_deleted": 0}

    for wid in wallet_ids:
        await db.execute("DELETE FROM silnt.utxos WHERE wallet_id = :wid", {"wid": wid})
        await db.execute("DELETE FROM silnt.wallet_addresses WHERE wallet_id = :wid", {"wid": wid})
        await db.execute("DELETE FROM silnt.wallets WHERE id = :wid", {"wid": wid})

    # Per-user data (keyed by user_id, not wallet_id) — these must be cleaned even
    # if the user somehow had no wallets, so do them unconditionally.
    await db.execute("DELETE FROM silnt.bip353_requests WHERE user_id = :uid", {"uid": user_id})
    await db.execute("DELETE FROM silnt.trusted_devices  WHERE user_id = :uid", {"uid": user_id})
    await db.execute("DELETE FROM silnt.user_prefs        WHERE user_id = :uid", {"uid": user_id})
    # Admin alerts reference the user only inside their meta JSON (no column), so
    # clean them via the meta-aware helper rather than a DELETE ... WHERE.
    await delete_admin_alerts_for_user(user_id)
    # Boltz swaps for the user's wallets.
    for wid in wallet_ids:
        await db.execute("DELETE FROM silnt.boltz_swaps WHERE silnt_wallet_id = :wid", {"wid": wid})
    # PayJoin: requests where the user is either side, their imported descriptors,
    # connection rows where they're requester or target, and their private labels.
    await db.execute(
        "DELETE FROM silnt.payjoin_requests WHERE sender_user_id = :uid OR receiver_user_id = :uid",
        {"uid": user_id},
    )
    await db.execute("DELETE FROM silnt.payjoin_descriptors WHERE user_id = :uid", {"uid": user_id})
    await db.execute(
        "DELETE FROM silnt.payjoin_contacts WHERE requester_user_id = :uid OR target_user_id = :uid",
        {"uid": user_id},
    )
    await db.execute("DELETE FROM silnt.payjoin_contact_labels WHERE labeler_user_id = :uid", {"uid": user_id})
    # SP send contacts (private address book).
    await db.execute("DELETE FROM silnt.sp_contacts WHERE user_id = :uid", {"uid": user_id})

    return {"wallets_deleted": len(wallet_ids), "wallet_ids": wallet_ids}


async def list_silnt_user_ids_for_network(network: str) -> list[str]:
    """User_ids that have siLNt presence ON a specific network — i.e. a wallet or
    a PayJoin descriptor whose network matches. Used by the network-locked admin
    Accounts page so the mainnet portal doesn't list signet-only users.
    (trusted_devices and bip353_requests are network-agnostic, so they are not
    used to scope network membership.)"""
    ids: set[str] = set()
    for sql, col in (
        ('SELECT DISTINCT "user" FROM silnt.wallets WHERE "user" IS NOT NULL AND network = :net', "user"),
        ("SELECT DISTINCT user_id FROM silnt.payjoin_descriptors WHERE network = :net", "user_id"),
    ):
        try:
            rows = await db.fetchall(sql, {"net": network})
        except Exception:
            continue
        for r in rows:
            v = r[col]
            if v:
                ids.add(v)
    return sorted(ids)
    
async def clear_wallet_hr_address(wallet_id: str) -> None:
    """Blank a wallet's hr_address after its BitMail DNS record is removed."""
    await db.execute(
        "UPDATE silnt.wallets SET hr_address = '' WHERE id = :wid",
        {"wid": wallet_id},
    )

async def count_approved_bip353_for_wallet(wallet_id: str) -> int:
    """How many times this wallet has been granted a BitMail address (approved)."""
    row = await db.fetchone(
        "SELECT COUNT(*) AS c FROM silnt.bip353_requests "
        "WHERE wallet_id = :wid AND status = 'approved'",
        {"wid": wallet_id},
    )
    # db.fetchone shape may be a mapping or a Row; handle both.
    if row is None:
        return 0
    try:
        return int(row["c"])
    except (KeyError, TypeError):
        return int(row[0])

async def create_boltz_swap(rec: BoltzSwapRecord) -> BoltzSwapRecord:
    await db.execute(
        """
        INSERT INTO silnt.boltz_swaps
            (id, wallet_id, silnt_wallet_id, status, timeout_block_height, json_data)
        VALUES (:id, :wallet_id, :silnt_wallet_id, :status, :timeout, :json_data)
        """,
        {
            "id": rec.id,
            "wallet_id": rec.wallet_id,
            "silnt_wallet_id": rec.silnt_wallet_id,
            "status": rec.status,
            "timeout": rec.timeout_block_height,
            "json_data": rec.json(),
        },
    )
    return rec

async def get_boltz_swap(swap_id: str) -> Optional[BoltzSwapRecord]:
    row = await db.fetchone(
        "SELECT json_data FROM silnt.boltz_swaps WHERE id = :id", {"id": swap_id}
    )
    return BoltzSwapRecord(**json.loads(row["json_data"])) if row else None

async def update_boltz_swap(rec: BoltzSwapRecord) -> BoltzSwapRecord:
    await db.execute(
        """
        UPDATE silnt.boltz_swaps
        SET status = :status, timeout_block_height = :timeout,
            updated_at = now(), json_data = :json_data
        WHERE id = :id
        """,
        {"status": rec.status, "timeout": rec.timeout_block_height,
         "json_data": rec.json(), "id": rec.id},
    )
    return rec

async def list_boltz_swaps_by_status(status: str) -> list[BoltzSwapRecord]:
    rows = await db.fetchall(
        "SELECT json_data FROM silnt.boltz_swaps WHERE status = :status",
        {"status": status},
    )
    return [BoltzSwapRecord(**json.loads(r["json_data"])) for r in rows]

async def list_boltz_swaps_for_wallet(
    wallet_id: str, silnt_wallet_id: str | None = None
) -> list[BoltzSwapRecord]:
    rows = await db.fetchall(
        """
        SELECT json_data FROM silnt.boltz_swaps
        WHERE wallet_id = :w OR silnt_wallet_id = :s
        ORDER BY created_at DESC
        """,
        {"w": wallet_id, "s": silnt_wallet_id or wallet_id},
    )
    return [BoltzSwapRecord(**json.loads(r["json_data"])) for r in rows]


async def delete_boltz_swap(swap_id: str) -> None:
    await db.execute(
        "DELETE FROM silnt.boltz_swaps WHERE id = :id",
        {"id": swap_id},
    )

async def mark_utxos_confirmed_spent_by_tx(wallet_id: str, spending_txid: str) -> int:
    """
    Finalize a confirmed send: move this wallet's inputs spent in `spending_txid`
    from 'unconfirmed_spent' to 'spent'. Returns rows affected. Idempotent —
    re-running on an already-'spent' tx changes nothing.
    """
    result = await db.execute(
        """UPDATE silnt.utxos
              SET utxo_state = 'spent'
            WHERE wallet_id = :wid
              AND spent_in_txid = :txid
              AND utxo_state = 'unconfirmed_spent'""",
        {"wid": wallet_id, "txid": spending_txid},
    )
    return getattr(result, "rowcount", 0) or 0

async def cancel_pending_request_for_address(
    wallet_id: str, address_id: Optional[str], sp_address: Optional[str] = None
) -> int:
    """Cancel any PENDING BitMail request bound to a specific address (a label,
    or the wallet base when address_id is None). Used when the address/wallet is
    deleted so the request doesn't linger in the admin queue. Approved rows are
    left intact (they preserve the wallet's lifetime cap and keep the username
    reserved).

    Matches on address_id AND, when provided, the address's sp_address. The
    sp_address fallback is important because a labeled-address row can be
    re-created by a scan with a NEW row id (BIP-352 addresses are deterministic
    from the seed, but the wallet_addresses.id is random), which would otherwise
    orphan a request whose stored address_id points at the old row id."""
    ts = int(time.time())
    if address_id is None and not sp_address:
        result = await db.execute(
            """UPDATE silnt.bip353_requests
               SET status = 'cancelled', processed_at = :ts
               WHERE wallet_id = :wid AND address_id IS NULL AND status = 'pending'""",
            {"wid": wallet_id, "ts": ts},
        )
    else:
        # Build the OR-match in Python so each bind param only appears in a typed
        # comparison (col = :param). Using ':param IS NOT NULL' in SQL leaves the
        # param's type indeterminate for asyncpg → IndeterminateDatatypeError.
        clauses = []
        params = {"wid": wallet_id, "ts": ts}
        if address_id is not None:
            clauses.append("address_id = :aid")
            params["aid"] = address_id
        if sp_address:
            clauses.append("sp_address = :sp")
            params["sp"] = sp_address
        where_match = " OR ".join(clauses)
        result = await db.execute(
            f"""UPDATE silnt.bip353_requests
                SET status = 'cancelled', processed_at = :ts
                WHERE wallet_id = :wid AND status = 'pending'
                  AND ({where_match})""",
            params,
        )
    return getattr(result, "rowcount", 0) or 0


async def cancel_all_pending_requests_for_wallet(wallet_id: str) -> int:
    """Cancel ALL pending BitMail requests for a wallet (any address). Used when
    the whole wallet is deleted."""
    result = await db.execute(
        """UPDATE silnt.bip353_requests
           SET status = 'cancelled', processed_at = :ts
           WHERE wallet_id = :wid AND status = 'pending'""",
        {"wid": wallet_id, "ts": int(time.time())},
    )
    return getattr(result, "rowcount", 0) or 0

async def delete_bip353_requests_for_wallet(wallet_id: str) -> int:
    """Delete ALL BitMail requests (any status) tied to a wallet. Called when the
    wallet itself is deleted, so approved BitMails don't linger in
    list_approved_bitmails() (which drives the tamper sweep) after their owning
    wallet is gone. The wallet's live DNS records are removed separately by the
    delete endpoint before this runs."""
    if not wallet_id:
        return 0
    result = await db.execute(
        "DELETE FROM silnt.bip353_requests WHERE wallet_id = :wid",
        {"wid": wallet_id},
    )
    return getattr(result, "rowcount", 0) or 0

async def list_all_bip353_requests(limit: int = 13, offset: int = 0) -> list[Bip353Request]:
    """All BitMail requests (any status), newest first, paginated. Admin history."""
    rows = await db.fetchall(
        """SELECT * FROM silnt.bip353_requests
           ORDER BY created_at DESC
           LIMIT :limit OFFSET :offset""",
        {"limit": limit, "offset": offset},
    )
    return [Bip353Request(**r) for r in rows]

async def delete_bip353_request_if_terminal(req_id: str) -> int:
    """Delete a single request ONLY if it is rejected or cancelled. Approved and
    pending rows are protected (approved = burned-slot/username record; pending =
    still in the queue). Returns rows deleted (0 if not terminal / not found)."""
    result = await db.execute(
        """DELETE FROM silnt.bip353_requests
           WHERE id = :id AND status IN ('rejected', 'cancelled')""",
        {"id": req_id},
    )
    return getattr(result, "rowcount", 0) or 0


async def delete_terminal_bip353_requests() -> int:
    """Bulk-delete ALL rejected/cancelled requests. Approved/pending untouched."""
    result = await db.execute(
        """DELETE FROM silnt.bip353_requests
           WHERE status IN ('rejected', 'cancelled')"""
    )
    return getattr(result, "rowcount", 0) or 0

# ── descriptor parsing ────────────────────────────────────────────────────────
def _embit_net(network: str):
    n = network.lower()
    if n == "mainnet":
        return NETWORKS["main"]
    if n == "regtest":
        return NETWORKS["regtest"]
    return NETWORKS["test"]


def _fmt_path(derivation: list[int]) -> str:
    """[84',1',0'] ints -> '84h/1h/0h'."""
    H = 0x80000000
    parts = []
    for i in derivation:
        if i >= H:
            parts.append(f"{i - H}h")
        else:
            parts.append(str(i))
    return "/".join(parts)


def _strip_checksum(descriptor: str) -> str:
    """Remove BIP-380 '#checksum' so a Sparrow export pasted verbatim parses.
    Checksum is a trailing '#'+8 chars; xpubs/paths never contain '#'."""
    s = (descriptor or "").strip()
    if "#" in s:
        s = s[: s.rindex("#")].strip()
    return s

def _normalize_multipath(descriptor: str) -> str:
    """
    Repair the key-path branch spec so embit can parse it and so BOTH the receive
    (0) and change (1) chains are covered.

    Some clients mangle the literal '<0;1>' (it contains '<' '>') into an empty
    branch, e.g. '...xpub//*'. Others export a single chain '.../0/*'. Normalize
    all of these to the canonical multipath '.../<0;1>/*'.

    Operates on the checksum-stripped string. Only touches the key-path tail
    (after the xpub); never alters the xpub or the [origin] prefix.
    """
    s = _strip_checksum(descriptor)
    # The tail we care about is the '/.../*' after the xpub, before the closing ')'.
    # Repair the two known bad/!canonical forms:
    #   //*        (empty branch  -> the <0;1> was eaten)
    #   /<0;1>/*   (already canonical -> leave)
    #   /0/*       (single receive chain -> expand to multipath)
    if "//*" in s:
        s = s.replace("//*", "/<0;1>/*")
    elif "/<0;1>/*" in s:
        pass  # canonical
    elif "/0/*" in s and "/<0;1>/*" not in s:
        s = s.replace("/0/*", "/<0;1>/*")
    return s

def _prepare_descriptor(descriptor: str) -> str:
    """Checksum-stripped + multipath-normalized string for embit parsing."""
    return _normalize_multipath(descriptor)

# ── At-rest encryption for PayJoin descriptors/xpubs ──────────────────────────
# An account xpub is privacy-sensitive: anyone holding it can derive all of a
# wallet's addresses and reconstruct its full balance/history (watch-only, not
# spend). The PayJoin flow needs the descriptor server-side to coordinate, so we
# encrypt it AT REST. This protects a leaked DB dump/backup; it does NOT protect
# against a full host compromise (the attacker would also obtain the key). The
# key is the per-instance LNbits auth_secret.
def _payjoin_enc_key() -> str:
    """Resolve a stable per-instance secret to key at-rest encryption.

    LNbits has renamed this across versions, so probe the known attribute names,
    then environment variables, then derive a stable fallback from instance-level
    values. Encryption protects a leaked DB dump/backup, not a full host
    compromise (which would also expose the key)."""
    import os
    try:
        from lnbits.settings import settings as _s
    except Exception:
        _s = None
    if _s is not None:
        for attr in (
            "auth_secret_key",   # confirmed name on this instance (see device_auth.py)
            "auth_secret", "secret", "secret_key",
            "lnbits_secret",
        ):
            v = getattr(_s, attr, None)
            if v:
                return str(v)
    for env in ("LNBITS_AUTH_SECRET", "AUTH_SECRET", "LNBITS_SECRET_KEY", "SECRET_KEY"):
        v = os.environ.get(env)
        if v:
            return v
    # Last-resort stable fallback: derive from instance-level values that persist
    # across restarts (data dir + superuser id). Not as strong as a dedicated
    # secret, but deterministic so encrypted rows remain decryptable.
    import hashlib
    seed = ""
    if _s is not None:
        seed = (str(getattr(_s, "lnbits_data_folder", "") or "")
                + "|" + str(getattr(_s, "super_user", "") or ""))
    seed = seed or os.environ.get("LNBITS_DATA_FOLDER", "") or "silnt-static-fallback"
    return hashlib.sha256(("silnt-pj-enc|" + seed).encode()).hexdigest()

def _pj_encrypt(plaintext: str) -> str:
    from lnbits.utils.crypto import AESCipher
    return AESCipher(key=_payjoin_enc_key()).encrypt(plaintext.encode())

def _strip_residual_padding(s: str) -> str:
    """AESCipher can leave a residual PKCS7 padding block on the decrypted string
    when the plaintext was exactly block-aligned (a multiple of 16 bytes) — e.g.
    a 32-byte / 64-hex key. Every value we encrypt is printable text, so a
    trailing run of N identical control bytes (0x01–0x10) equal to N is that
    leftover padding, not data. Strip it so no caller has to. A cleanly-decrypted
    value never matches, so this is a no-op in the normal case."""
    if not s:
        return s
    last = ord(s[-1])
    if 1 <= last <= 16 and len(s) >= last and all(ord(c) == last for c in s[-last:]):
        return s[:-last]
    return s


def _pj_decrypt(ciphertext: str) -> str:
    from lnbits.utils.crypto import AESCipher
    return _strip_residual_padding(
        AESCipher(key=_payjoin_enc_key()).decrypt(ciphertext)
    )

def _xpub_fingerprint_hash(xpub: str) -> str:
    """Deterministic, non-reversible tag for dedup/equality lookups without
    storing the xpub in plaintext. SHA256 of an xpub can't be turned back into
    the xpub (so no address derivation), but equal xpubs map to equal tags."""
    import hashlib
    return hashlib.sha256(xpub.strip().encode()).hexdigest()

def _looks_encrypted(val: str) -> bool:
    """Heuristic: a stored value is ciphertext (base64 from AESCipher) rather than
    a plaintext descriptor/xpub. Real descriptors contain '(' and key-prefixes;
    xpubs start with x/t/y/z-pub. Base64 ciphertext does not."""
    if not val:
        return False
    v = val.strip()
    # Plaintext descriptor markers
    if "(" in v or v[:4] in ("wpkh", "pkh(", "tr(", "sh(", "combo", "addr", "raw("):
        return False
    # Plaintext xpub markers
    if v[:4].lower() in ("xpub", "tpub", "ypub", "zpub", "vpub", "upub"):
        return False
    return True

def _decrypt_descriptor_row(row: dict) -> dict:
    """Return a row dict with descriptor/xpub decrypted for model construction.
    Tolerates legacy plaintext rows (pre-encryption). If a value LOOKS encrypted
    but cannot be decrypted (e.g. encrypted under a now-unreachable key), raise —
    never hand raw base64 ciphertext downstream, which corrupts the descriptor
    parser with an 'invalid character' error."""
    out = dict(row)
    for field in ("descriptor", "xpub"):
        val = out.get(field)
        if not val:
            continue
        try:
            out[field] = _pj_decrypt(val)
        except Exception:
            if _looks_encrypted(val):
                raise RuntimeError(
                    f"PayJoin {field} is encrypted but could not be decrypted with the "
                    f"current key. The instance secret (auth_secret_key) likely changed "
                    f"since it was encrypted. Re-import this wallet descriptor."
                )
            # Otherwise it's genuine legacy plaintext — leave as-is.
    return out

def parse_descriptor(descriptor: str) -> dict:
    """
    Parse + validate a BIP-84 output descriptor (Sparrow export).
    Returns {xpub, master_fp, account_path, script_type}. Raises ValueError on
    anything that isn't a single-key wpkh descriptor.
    """
    try:
        d = Descriptor.from_string(_prepare_descriptor(descriptor))
    except Exception as e:
        raise ValueError(f"Could not parse descriptor: {e}")
    if not d.wpkh:
        raise ValueError("Only BIP-84 native SegWit (wpkh) descriptors are supported.")
    if len(d.keys) != 1:
        raise ValueError("Only single-key descriptors are supported.")
    k = d.keys[0]
    if k.origin is None:
        raise ValueError("Descriptor is missing key origin ([fingerprint/path]).")
    return {
        "xpub": str(k.key).split("/")[0],          # strip any /<0;1>/* suffix
        "master_fp": k.origin.fingerprint.hex(),
        "account_path": _fmt_path(k.origin.derivation),
        "script_type": "wpkh",
    }

def derive_descriptor_address(descriptor: str, network: str, chain: int, index: int) -> str:
    """Derive a concrete address from the descriptor: chain 0=receive,1=change."""
    d = Descriptor.from_string(_prepare_descriptor(descriptor))
    return d.derive(index, branch_index=chain).address(_embit_net(network))

# ── descriptors CRUD ──────────────────────────────────────────────────────────
async def create_payjoin_descriptor(
    user_id: str, descriptor: str, network: str, label: Optional[str] = None
) -> PayjoinDescriptor:
    parsed = parse_descriptor(descriptor)
    # Dedup on a non-reversible hash of the xpub (the xpub itself is stored
    # encrypted, so a plaintext equality match isn't possible).
    xhash = _xpub_fingerprint_hash(parsed["xpub"])
    existing = await db.fetchall(
        "SELECT id FROM silnt.payjoin_descriptors WHERE user_id = :uid AND xpub_sha256 = :xh",
        {"uid": user_id, "xh": xhash},
    )
    if existing:
        raise ValueError("This wallet (xpub) is already imported.")
    did = urlsafe_short_hash()
    # Encrypt the privacy-sensitive fields at rest. master_fp/account_path are
    # low-sensitivity (fingerprint + derivation path) and left as-is for display.
    enc_descriptor = _pj_encrypt(descriptor.strip())
    enc_xpub = _pj_encrypt(parsed["xpub"])
    await db.execute(
        """
        INSERT INTO silnt.payjoin_descriptors
            (id, user_id, label, descriptor, xpub, xpub_sha256, master_fp, account_path,
             script_type, network)
        VALUES
            (:id, :user_id, :label, :descriptor, :xpub, :xpub_sha256, :master_fp, :account_path,
             :script_type, :network)
        """,
        {
            "id": did, "user_id": user_id, "label": label,
            "descriptor": enc_descriptor, "xpub": enc_xpub, "xpub_sha256": xhash,
            "master_fp": parsed["master_fp"], "account_path": parsed["account_path"],
            "script_type": parsed["script_type"], "network": network,
        },
    )
    return await get_payjoin_descriptor(did)


async def get_payjoin_descriptor(did: str) -> Optional[PayjoinDescriptor]:
    row = await db.fetchone(
        "SELECT * FROM silnt.payjoin_descriptors WHERE id = :id", {"id": did}
    )
    return PayjoinDescriptor(**_decrypt_descriptor_row(row)) if row else None


async def list_payjoin_descriptors(user_id: str) -> list[PayjoinDescriptor]:
    rows = await db.fetchall(
        "SELECT * FROM silnt.payjoin_descriptors WHERE user_id = :uid ORDER BY created_at DESC",
        {"uid": user_id},
    )
    return [PayjoinDescriptor(**_decrypt_descriptor_row(r)) for r in rows]

async def list_payjoin_descriptor_user_ids(exclude_user_id: Optional[str] = None) -> list[str]:
    """Distinct user_ids that have imported at least one PayJoin descriptor
    (i.e. can actually receive a PayJoin). Optionally exclude the caller."""
    rows = await db.fetchall(
        "SELECT DISTINCT user_id FROM silnt.payjoin_descriptors", {}
    )
    ids = [r["user_id"] for r in rows]
    if exclude_user_id:
        ids = [i for i in ids if i != exclude_user_id]
    return ids

async def delete_payjoin_descriptor(did: str, user_id: str) -> None:
    await db.execute(
        "DELETE FROM silnt.payjoin_descriptors WHERE id = :id AND user_id = :uid",
        {"id": did, "uid": user_id},
    )


async def get_reserved_outpoints(user_id: str) -> set:
    """
    Outpoints (txid:vout) reserved by this user's PayJoins, so they can't be
    double-selected in another siLNt PayJoin and so the Create/Pay pickers agree
    with the wallet balance.

    Includes:
      - In-progress PayJoins (OPEN/CLAIMED/PROPOSED/ACCEPTED/CONTRIBUTED/FINALIZING).
      - BROADCAST PayJoins whose spend is still UNCONFIRMED. Fulcrum's listunspent
        keeps a being-spent UTXO until the spend confirms, while the wallet
        balance already subtracts it (unconfirmed). Without reserving these, the
        Create tab would still list the in-flight UTXO as available and show the
        pre-PayJoin amount — disagreeing with the Wallets balance. Once the spend
        confirms, Fulcrum drops the UTXO from listunspent, so it no longer appears
        regardless of status; over-reserving a confirmed-spent outpoint is
        therefore harmless (it isn't listed anymore).

    (Watch-only: this is siLNt-scope only; it can't stop the user spending the
    coins directly in their own wallet.)
    """
    rows = await db.fetchall(
        """
        SELECT sender_inputs, receiver_input FROM silnt.payjoin_requests
        WHERE (sender_user_id = :uid OR receiver_user_id = :uid)
          AND status IN ('OPEN','CLAIMED','PROPOSED','ACCEPTED','CONTRIBUTED','FINALIZING','BROADCAST')
        """,
        {"uid": user_id},
    )
    reserved = set()
    for r in rows:
        for col in ("sender_inputs", "receiver_input"):
            raw = r[col]
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except Exception:
                continue
            items = data if isinstance(data, list) else [data]
            for u in items:
                if isinstance(u, dict) and "txid" in u and "vout" in u:
                    reserved.add(f"{u['txid']}:{u['vout']}")
    return reserved

# ── requests CRUD ─────────────────────────────────────────────────────────────
async def create_payjoin_request(
    sender_user_id: str, sender_username: str, sender_descriptor_id: str,
    receiver_username: str, amount_sats: int, fee_rate: float,
    payment_address: str, sender_inputs: list[dict],
    receiver_user_id: Optional[str] = None, expiry_seconds: int = 3600,
) -> PayjoinRequest:
    rid = urlsafe_short_hash()
    # expires_at as a real datetime (TIMESTAMP column). Match however your other
    # CRUD writes datetimes — if they pass datetime objects, this is correct; if
    # they use db.timestamp_now + interval SQL, adapt accordingly.    
    expires_at = int(time.time()) + expiry_seconds
    await db.execute(
        """
        INSERT INTO silnt.payjoin_requests
            (id, status, sender_user_id, sender_username, sender_descriptor_id,
             receiver_user_id, receiver_username, amount_sats, fee_rate,
             payment_address, sender_inputs, expires_at)
        VALUES
            (:id, 'PROPOSED', :suid, :suser, :sdid, :ruid, :ruser, :amount,
             :fee_rate, :pay_addr, :sinputs, :expires)
        """,
        {
            "id": rid, "suid": sender_user_id, "suser": sender_username,
            "sdid": sender_descriptor_id, "ruid": receiver_user_id,
            "ruser": receiver_username, "amount": amount_sats, "fee_rate": fee_rate,
            "pay_addr": payment_address, "sinputs": json.dumps(sender_inputs),
            "expires": expires_at,
        },
    )
    return await get_payjoin_request(rid)


async def get_payjoin_request(rid: str) -> Optional[PayjoinRequest]:
    row = await db.fetchone(
        "SELECT * FROM silnt.payjoin_requests WHERE id = :id", {"id": rid}
    )
    return PayjoinRequest(**row) if row else None


async def create_payjoin_invoice(
    payee_user_id: str, payee_username: str, payee_descriptor_id: str,
    payee_input: dict, payment_address: str,
    payer_user_id: str, payer_username: str,
    amount_sats: int, fee_rate: float, memo: Optional[str] = None,
    expiry_seconds: int = 86400,
) -> PayjoinRequest:
    """
    A (payee) creates a directed invoice for payer B. Reuses payjoin_requests:
    receiver_* = payee A (set now, incl. A's one contributed input);
    sender_*   = payer B (identity set now; B's inputs filled when B pays).
    Status OPEN. Payment address is A's (next-unused) receive address.
    """
    rid = urlsafe_short_hash()
    expires_at = int(time.time()) + expiry_seconds
    await db.execute(
        """
        INSERT INTO silnt.payjoin_requests
            (id, status, sender_user_id, sender_username, sender_descriptor_id,
             receiver_user_id, receiver_username, receiver_descriptor_id,
             receiver_input, receiver_input_sats, amount_sats, fee_rate,
             payment_address, memo, expires_at)
        VALUES
            (:id, 'OPEN', :buid, :buser, :bdid, :auid, :auser, :adid,
             :ainput, :ain_sats, :amount, :fee_rate, :pay_addr, :memo, :expires)
        """,
        {
            "id": rid,
            "buid": payer_user_id, "buser": payer_username, "bdid": "",
            "auid": payee_user_id, "auser": payee_username, "adid": payee_descriptor_id,
            "ainput": json.dumps(payee_input), "ain_sats": int(payee_input["value"]),
            "amount": amount_sats, "fee_rate": fee_rate,
            "pay_addr": payment_address, "memo": memo, "expires": expires_at,
        },
    )
    return await get_payjoin_request(rid)


async def list_payjoin_invoices_for_payer(payer_user_id: str) -> list[PayjoinRequest]:
    """OPEN invoices directed to this user (as payer B)."""
    rows = await db.fetchall(
        "SELECT * FROM silnt.payjoin_requests "
        "WHERE sender_user_id = :uid AND status = 'OPEN' ORDER BY created_at DESC",
        {"uid": payer_user_id},
    )
    return [PayjoinRequest(**r) for r in rows]


# ── connections (consent-based curated list) ──────────────────────────────────
async def get_account_id_by_email(email: str):
    """
    Resolve an email -> (user_id, username) using the LNbits core accounts table.
    Prefers the core helper if present, else queries the core DB directly.
    Returns (user_id, username) or (None, None) if no such account. Email match
    is case-insensitive. Never raises on 'not found' (so callers can stay neutral
    and avoid an email-existence oracle).
    """
    em = (email or "").strip().lower()
    if not em or "@" not in em:
        return (None, None)
    # try core helper first
    try:
        from lnbits.core.crud import get_account_by_email  # may not exist in all versions
        acct = await get_account_by_email(em)
        if acct:
            return (acct.id, getattr(acct, "username", None) or em)
    except Exception:
        pass
    # fallback: direct query against the core accounts table
    try:
        from lnbits.core.db import db as core_db
        row = await core_db.fetchone(
            "SELECT id, username FROM accounts WHERE LOWER(email) = :em",
            {"em": em},
        )
        if row:
            return (row["id"], row["username"] or em)
    except Exception:
        pass
    return (None, None)


async def create_payjoin_contact(requester_user_id: str, target_user_id: str) -> "PayjoinContact":
    """Create a PENDING connection request (or return the existing row if one
    already exists between these two users in either direction). Stores only
    user_ids — usernames are resolved on demand for display."""
    existing = await db.fetchone(
        """SELECT * FROM silnt.payjoin_contacts
           WHERE (requester_user_id = :a AND target_user_id = :b)
              OR (requester_user_id = :b AND target_user_id = :a)""",
        {"a": requester_user_id, "b": target_user_id},
    )
    if existing:
        return PayjoinContact(**existing)
    cid = urlsafe_short_hash()
    await db.execute(
        """INSERT INTO silnt.payjoin_contacts
           (id, status, requester_user_id, target_user_id)
           VALUES (:id, 'PENDING', :ruid, :tuid)""",
        {"id": cid, "ruid": requester_user_id, "tuid": target_user_id},
    )
    return await get_payjoin_contact(cid)


async def get_payjoin_contact(cid: str) -> Optional["PayjoinContact"]:
    row = await db.fetchone("SELECT * FROM silnt.payjoin_contacts WHERE id = :id", {"id": cid})
    return PayjoinContact(**row) if row else None


async def set_payjoin_contact_status(cid: str, status: str) -> None:
    await db.execute(
        f"UPDATE silnt.payjoin_contacts SET status = :s, updated_at = {db.timestamp_now} WHERE id = :id",
        {"s": status, "id": cid},
    )


async def delete_payjoin_contact(cid: str) -> None:
    await db.execute("DELETE FROM silnt.payjoin_contacts WHERE id = :id", {"id": cid})
    # also drop any private labels attached to it
    await db.execute("DELETE FROM silnt.payjoin_contact_labels WHERE contact_id = :id", {"id": cid})


async def set_payjoin_contact_label(contact_id: str, labeler_user_id: str, label: str) -> None:
    """Set/clear a private per-side label for a connection (only the labeler sees
    it). Blank label clears it."""
    lbl = (label or "").strip()
    if not lbl:
        await db.execute(
            "DELETE FROM silnt.payjoin_contact_labels WHERE contact_id = :cid AND labeler_user_id = :uid",
            {"cid": contact_id, "uid": labeler_user_id},
        )
        return
    existing = await db.fetchone(
        "SELECT 1 FROM silnt.payjoin_contact_labels WHERE contact_id = :cid AND labeler_user_id = :uid",
        {"cid": contact_id, "uid": labeler_user_id},
    )
    if existing:
        await db.execute(
            f"UPDATE silnt.payjoin_contact_labels SET label = :lbl, updated_at = {db.timestamp_now} "
            "WHERE contact_id = :cid AND labeler_user_id = :uid",
            {"lbl": lbl, "cid": contact_id, "uid": labeler_user_id},
        )
    else:
        await db.execute(
            "INSERT INTO silnt.payjoin_contact_labels (contact_id, labeler_user_id, label) "
            "VALUES (:cid, :uid, :lbl)",
            {"cid": contact_id, "uid": labeler_user_id, "lbl": lbl},
        )


async def get_payjoin_contact_labels(labeler_user_id: str) -> dict:
    """Map {contact_id: label} of this user's private labels."""
    rows = await db.fetchall(
        "SELECT contact_id, label FROM silnt.payjoin_contact_labels WHERE labeler_user_id = :uid",
        {"uid": labeler_user_id},
    )
    return {r["contact_id"]: r["label"] for r in rows}


async def list_payjoin_contacts(user_id: str) -> dict:
    """All connections touching this user, grouped. Returns raw rows with the
    counterparty_user_id annotated; the endpoint resolves usernames for display
    (so usernames are never stored, only resolved on demand)."""
    rows = await db.fetchall(
        """SELECT * FROM silnt.payjoin_contacts
           WHERE requester_user_id = :uid OR target_user_id = :uid
           ORDER BY updated_at DESC""",
        {"uid": user_id},
    )
    accepted, incoming, outgoing, declined = [], [], [], []
    for r in rows:
        c = PayjoinContact(**r)
        other_id = c.requester_user_id if c.target_user_id == user_id else c.target_user_id
        d = c.dict()
        d["counterparty_user_id"] = other_id
        if c.status == "ACCEPTED":
            accepted.append(d)
        elif c.status == "PENDING" and c.target_user_id == user_id:
            incoming.append(d)
        elif c.status == "PENDING" and c.requester_user_id == user_id:
            outgoing.append(d)
        elif c.status == "DECLINED" and c.requester_user_id == user_id:
            declined.append(d)
    return {"accepted": accepted, "incoming": incoming, "outgoing": outgoing, "declined": declined}


async def list_accepted_contacts_with_ids(user_id: str) -> list[dict]:
    """ACCEPTED connections: [{contact_id, user_id}] where user_id is the
    counterparty. Lets the endpoint attach this user's private label + username."""
    rows = await db.fetchall(
        """SELECT * FROM silnt.payjoin_contacts
           WHERE status = 'ACCEPTED' AND (requester_user_id = :uid OR target_user_id = :uid)""",
        {"uid": user_id},
    )
    out = []
    for r in rows:
        c = PayjoinContact(**r)
        other = c.target_user_id if c.requester_user_id == user_id else c.requester_user_id
        out.append({"contact_id": c.id, "user_id": other})
    return out


async def list_accepted_contact_user_ids(user_id: str) -> list[str]:
    """user_ids of this user's ACCEPTED connections (counterparties)."""
    rows = await db.fetchall(
        """SELECT * FROM silnt.payjoin_contacts
           WHERE status = 'ACCEPTED' AND (requester_user_id = :uid OR target_user_id = :uid)""",
        {"uid": user_id},
    )
    out = []
    for r in rows:
        c = PayjoinContact(**r)
        out.append(c.target_user_id if c.requester_user_id == user_id else c.requester_user_id)
    return out


async def list_payjoin_requests_for_receiver(
    receiver_user_id: str, status: Optional[str] = None
) -> list[PayjoinRequest]:
    if status:
        rows = await db.fetchall(
            "SELECT * FROM silnt.payjoin_requests WHERE receiver_user_id = :uid "
            "AND status = :st ORDER BY created_at DESC",
            {"uid": receiver_user_id, "st": status},
        )
    else:
        rows = await db.fetchall(
            "SELECT * FROM silnt.payjoin_requests WHERE receiver_user_id = :uid "
            "ORDER BY created_at DESC",
            {"uid": receiver_user_id},
        )
    return [PayjoinRequest(**r) for r in rows]


async def list_payjoin_requests_for_sender(sender_user_id: str) -> list[PayjoinRequest]:
    rows = await db.fetchall(
        "SELECT * FROM silnt.payjoin_requests WHERE sender_user_id = :uid "
        "ORDER BY created_at DESC",
        {"uid": sender_user_id},
    )
    return [PayjoinRequest(**r) for r in rows]


async def update_payjoin_request(rid: str, **fields) -> Optional[PayjoinRequest]:
    """
    Generic field updater. Always bumps updated_at. Pass only columns that exist.
    e.g. update_payjoin_request(rid, status='CONTRIBUTED', psbt=..., fee_sats=...)
    """
    if not fields:
        return await get_payjoin_request(rid)
    fields_sql = ", ".join(f"{k} = :{k}" for k in fields)
    params = {**fields, "id": rid}
    await db.execute(
        f"UPDATE silnt.payjoin_requests SET {fields_sql}, "
        f"updated_at = {db.timestamp_now} WHERE id = :id",
        params,
    )
    return await get_payjoin_request(rid)

async def list_expired_payjoin_requests(now_ts: Optional[int] = None) -> list[PayjoinRequest]:
    """Non-terminal requests past their expiry — for the sweep. expires_at is
    Unix seconds (int)."""
    now_ts = now_ts if now_ts is not None else int(time.time())
    rows = await db.fetchall(
        "SELECT * FROM silnt.payjoin_requests "
        "WHERE status IN ('PROPOSED','CONTRIBUTED') AND expires_at IS NOT NULL "
        "AND expires_at < :now",
        {"now": now_ts},
    )
    return [PayjoinRequest(**r) for r in rows]

# ── SP send contacts (per-user private address book) ──────────────────────────
def _spc_hash(value: str) -> str:
    import hashlib
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()

def _classify_recipient(value: str) -> str:
    """'bitmail' if it's a name@domain, else 'sp' (raw SP address)."""
    return "bitmail" if "@" in (value or "") else "sp"

def _decrypt_sp_contact_row(row: dict) -> dict:
    out = dict(row)
    if out.get("value"):
        try:
            out["value"] = _pj_decrypt(out["value"])
        except Exception:
            pass  # legacy/plaintext tolerance
    return out

async def create_sp_contact(
    user_id: str, label: str, value: str, network: str
) -> "SpContact":
    from .models import SpContact
    value = (value or "").strip()
    if not value:
        raise ValueError("Recipient is required.")
    label = (label or "").strip() or value
    kind = _classify_recipient(value)
    vhash = _spc_hash(value)
    # Dedup within the same user AND network — the same recipient can legitimately
    # be saved on more than one network, so it's not a cross-network duplicate.
    existing = await db.fetchone(
        "SELECT id FROM silnt.sp_contacts WHERE user_id = :uid AND network = :net AND value_sha256 = :h",
        {"uid": user_id, "net": network, "h": vhash},
    )
    # A name must be unique within the user's per-network address book. Reject if
    # some OTHER contact already uses this label (case-insensitive) — this same
    # recipient keeping or changing its own label is fine (handled below).
    label_owner = await db.fetchone(
        "SELECT id FROM silnt.sp_contacts "
        "WHERE user_id = :uid AND network = :net AND LOWER(label) = LOWER(:l)",
        {"uid": user_id, "net": network, "l": label},
    )
    if label_owner and (not existing or label_owner["id"] != existing["id"]):
        raise ValueError(f'A contact named "{label}" already exists.')
    if existing:
        await db.execute(
            "UPDATE silnt.sp_contacts SET label = :l WHERE id = :id",
            {"l": label, "id": existing["id"]},
        )
        return await get_sp_contact(existing["id"])
    cid = urlsafe_short_hash()
    await db.execute(
        """
        INSERT INTO silnt.sp_contacts (id, user_id, network, label, kind, value, value_sha256)
        VALUES (:id, :uid, :net, :label, :kind, :value, :h)
        """,
        {"id": cid, "uid": user_id, "net": network, "label": label, "kind": kind,
         "value": _pj_encrypt(value), "h": vhash},
    )
    return await get_sp_contact(cid)

async def get_sp_contact(cid: str) -> Optional["SpContact"]:
    from .models import SpContact
    row = await db.fetchone("SELECT * FROM silnt.sp_contacts WHERE id = :id", {"id": cid})
    return SpContact(**_decrypt_sp_contact_row(row)) if row else None

async def list_sp_contacts(user_id: str, network: str) -> list:
    from .models import SpContact
    rows = await db.fetchall(
        "SELECT * FROM silnt.sp_contacts WHERE user_id = :uid AND network = :net "
        "ORDER BY last_used_at DESC NULLS LAST, label ASC",
        {"uid": user_id, "net": network},
    )
    return [SpContact(**_decrypt_sp_contact_row(r)) for r in rows]

async def update_sp_contact_label(cid: str, user_id: str, label: str) -> None:
    label = (label or "").strip()
    # Same uniqueness rule as create: a rename can't collide with another
    # contact's name in the same user+network address book.
    clash = await db.fetchone(
        "SELECT id FROM silnt.sp_contacts "
        "WHERE user_id = :uid AND id != :cid AND LOWER(label) = LOWER(:l) "
        "AND network = (SELECT network FROM silnt.sp_contacts WHERE id = :cid)",
        {"uid": user_id, "cid": cid, "l": label},
    )
    if clash:
        raise ValueError(f'A contact named "{label}" already exists.')
    await db.execute(
        "UPDATE silnt.sp_contacts SET label = :l WHERE id = :id AND user_id = :uid",
        {"l": label, "id": cid, "uid": user_id},
    )

async def touch_sp_contact(user_id: str, value: str, network: str) -> None:
    """Bump last_used_at when a saved recipient is sent to (for ordering)."""
    await db.execute(
        "UPDATE silnt.sp_contacts SET last_used_at = :ts "
        "WHERE user_id = :uid AND network = :net AND value_sha256 = :h",
        {"ts": int(time.time()), "uid": user_id, "net": network, "h": _spc_hash(value)},
    )

async def delete_sp_contact(cid: str, user_id: str) -> None:
    await db.execute(
        "DELETE FROM silnt.sp_contacts WHERE id = :id AND user_id = :uid",
        {"id": cid, "uid": user_id},
    )


async def list_silnt_user_ids() -> list[str]:
    """Distinct user_ids known to siLNt — anyone with a wallet, trusted device,
    imported PayJoin descriptor, or BitMail request. Used by the admin Accounts
    page to enumerate deletable users (scoped to siLNt users, not every LNbits
    account)."""
    ids: set[str] = set()
    # (query, column-name-as-returned) — read by real column name, matching how
    # the rest of this module reads db.fetchall rows (dict-like mappings).
    for sql, col in (
        ('SELECT DISTINCT "user" FROM silnt.wallets WHERE "user" IS NOT NULL', "user"),
        ("SELECT DISTINCT user_id FROM silnt.trusted_devices", "user_id"),
        ("SELECT DISTINCT user_id FROM silnt.payjoin_descriptors", "user_id"),
        ("SELECT DISTINCT user_id FROM silnt.bip353_requests", "user_id"),
    ):
        try:
            rows = await db.fetchall(sql, {})
        except Exception:
            continue  # a table may be absent on older schemas — skip that source
        for r in rows:
            v = r[col]
            if v:
                ids.add(v)
    return sorted(ids)


# ── Admin alerts ──────────────────────────────────────────────────────────────
async def create_admin_alert(
    kind: str, title: str, detail: str = "",
    severity: str = "warning", meta: Optional[str] = None,
) -> AdminAlert:
    """Record an admin-visible alert (surfaced in the Admin console)."""
    aid = urlsafe_short_hash()
    now = int(time.time())
    await db.execute(
        """INSERT INTO silnt.admin_alerts
             (id, kind, severity, title, detail, meta, acknowledged, created_at)
           VALUES (:id, :kind, :sev, :title, :detail, :meta, FALSE, :ts)""",
        {"id": aid, "kind": kind, "sev": severity, "title": title,
         "detail": detail, "meta": meta, "ts": now},
    )
    return AdminAlert(id=aid, kind=kind, severity=severity, title=title,
                      detail=detail, meta=meta, acknowledged=False, created_at=now)


async def list_admin_alerts(include_acknowledged: bool = False, limit: int = 100) -> list[AdminAlert]:
    if include_acknowledged:
        rows = await db.fetchall(
            "SELECT * FROM silnt.admin_alerts ORDER BY created_at DESC LIMIT :lim",
            {"lim": limit},
        )
    else:
        rows = await db.fetchall(
            """SELECT * FROM silnt.admin_alerts WHERE acknowledged = FALSE
               ORDER BY created_at DESC LIMIT :lim""",
            {"lim": limit},
        )
    return [AdminAlert(**dict(r)) for r in rows]


async def count_open_admin_alerts() -> int:
    row = await db.fetchone(
        "SELECT COUNT(*) AS c FROM silnt.admin_alerts WHERE acknowledged = FALSE"
    )
    return int(row["c"]) if row else 0


async def acknowledge_admin_alert(alert_id: str) -> bool:
    result = await db.execute(
        "UPDATE silnt.admin_alerts SET acknowledged = TRUE WHERE id = :id",
        {"id": alert_id},
    )
    return (getattr(result, "rowcount", 0) or 0) > 0


async def _delete_admin_alerts_where_meta(field: str, value: str) -> int:
    """Delete admin alerts whose meta JSON has meta[field] == value. The wallet_id
    and user_id an alert refers to live inside the meta JSON blob (there is no
    column for them), so we parse each row rather than filter in SQL. Alert volume
    is small, so scanning the table is fine."""
    if not value:
        return 0
    rows = await db.fetchall("SELECT id, meta FROM silnt.admin_alerts")
    removed = 0
    for r in rows:
        raw = r["meta"] or ""
        try:
            meta = json.loads(raw) if raw else {}
        except Exception:
            continue
        if meta.get(field) == value:
            await db.execute(
                "DELETE FROM silnt.admin_alerts WHERE id = :id", {"id": r["id"]}
            )
            removed += 1
    return removed


async def delete_admin_alerts_for_wallet(wallet_id: str) -> int:
    """Remove admin alerts raised for a wallet (matched via meta.wallet_id). Called
    on wallet deletion so a removed wallet leaves no orphan alerts behind."""
    return await _delete_admin_alerts_where_meta("wallet_id", wallet_id)


async def delete_admin_alerts_for_user(user_id: str) -> int:
    """Remove admin alerts raised for a user (matched via meta.user_id). Used when
    wiping all of a user's siLNt data."""
    return await _delete_admin_alerts_where_meta("user_id", user_id)


async def get_issued_bitmail_sp_address(username: str) -> Optional[str]:
    """Return the SP address siLNt recorded for an APPROVED BitMail issued on our
    own domain, matched by final_username. None if we never issued that name.
    Used to detect tampering: compare against what DNS resolves to at send time."""
    row = await db.fetchone(
        """SELECT sp_address FROM silnt.bip353_requests
           WHERE LOWER(final_username) = LOWER(:uname) AND status = 'approved'
           ORDER BY processed_at DESC NULLS LAST LIMIT 1""",
        {"uname": username},
    )
    return row["sp_address"] if row else None


async def list_approved_bitmails() -> list[dict]:
    """Every APPROVED BitMail siLNt issued: its final_username, the SP address we
    recorded, and the owning user_id/wallet_id. Used by the tamper sweep to
    resolve each via DNS and compare against the recorded SP."""
    rows = await db.fetchall(
        """SELECT final_username, sp_address, user_id, wallet_id
           FROM silnt.bip353_requests
           WHERE status = 'approved' AND final_username IS NOT NULL""",
    )
    return [dict(r) for r in rows]


async def open_alert_exists_for(kind: str, key: str) -> bool:
    """True if there's already an UNacknowledged alert of this kind whose meta
    references `key` (e.g. a bitmail). Prevents the sweep from re-alerting the
    same active tamper on every run — a new alert only fires once the admin
    acknowledges the previous one (or the tamper clears)."""
    rows = await db.fetchall(
        """SELECT meta FROM silnt.admin_alerts
           WHERE kind = :kind AND acknowledged = FALSE""",
        {"kind": kind},
    )
    for r in rows:
        m = r["meta"] or ""
        if key and key in m:
            return True
    return False


async def tamper_signature_alerted(bitmail: str, resolved_sp: str) -> bool:
    """True if we've ALREADY created an alert for this exact tamper — same
    bitmail redirected to the same rogue SP address — regardless of whether the
    admin has acknowledged it. This is the correct dedup for an ONGOING tamper:
    dismissing the alert must NOT cause the next sweep to re-insert/re-notify.
    A DIFFERENT rogue address (or a recurrence after the record was fixed) has a
    different signature, so it still alerts."""
    rows = await db.fetchall(
        "SELECT meta FROM silnt.admin_alerts WHERE kind = 'bitmail_tamper'",
    )
    for r in rows:
        m = r["meta"] or ""
        try:
            d = json.loads(m) if m else {}
        except Exception:
            continue
        if (d.get("bitmail") == bitmail
                and (d.get("resolved_sp") or "").lower() == (resolved_sp or "").lower()):
            return True
    return False


async def create_device_code(
    user_id: str, code: str, device_id: str,
    user_agent: Optional[str], ip: Optional[str], ttl_secs: int = 600,
) -> None:
    """Store a hashed device-confirmation code (one active per user; latest
    replaces any previous). The plaintext code is emailed, never stored."""
    import time as _t
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    now = int(_t.time())
    await db.execute(
        """INSERT INTO silnt.device_codes
              (user_id, code_hash, device_id, user_agent, ip, expires_at, attempts)
           VALUES (:uid, :ch, :did, :ua, :ip, :exp, 0)
           ON CONFLICT (user_id) DO UPDATE SET
              code_hash = :ch, device_id = :did, user_agent = :ua,
              ip = :ip, expires_at = :exp, attempts = 0""",
        {"uid": user_id, "ch": code_hash, "did": device_id, "ua": user_agent,
         "ip": ip, "exp": now + ttl_secs},
    )


async def verify_device_code(user_id: str, code: str, max_attempts: int = 5) -> Optional[dict]:
    """
    Verify a device-confirmation code for the user. Returns the pending device
    info dict {device_id, user_agent, ip} on success (and consumes the code), or
    None on failure. Enforces expiry and an attempt cap: after `max_attempts`
    wrong tries the code is invalidated (deleted), so a 6-digit code can't be
    brute-forced.
    """
    import time as _t
    row = await db.fetchone(
        "SELECT code_hash, device_id, user_agent, ip, expires_at, attempts "
        "FROM silnt.device_codes WHERE user_id = :uid",
        {"uid": user_id},
    )
    if not row:
        return None
    now = int(_t.time())
    if now > int(row["expires_at"]):
        await db.execute("DELETE FROM silnt.device_codes WHERE user_id = :uid", {"uid": user_id})
        return None
    if int(row["attempts"]) >= max_attempts:
        await db.execute("DELETE FROM silnt.device_codes WHERE user_id = :uid", {"uid": user_id})
        return None

    supplied = hashlib.sha256((code or "").encode()).hexdigest()
    if not hmac.compare_digest(supplied, row["code_hash"]):
        await db.execute(
            "UPDATE silnt.device_codes SET attempts = attempts + 1 WHERE user_id = :uid",
            {"uid": user_id},
        )
        return None

    # Success — consume the code (single-use).
    await db.execute("DELETE FROM silnt.device_codes WHERE user_id = :uid", {"uid": user_id})
    return {
        "device_id":  row["device_id"],
        "user_agent": row["user_agent"],
        "ip":         row["ip"],
    }


async def mark_self_revoke(user_id: str) -> None:
    """Record that the user just revoked their own current device. The login
    alert suppresses false positives within a short grace window after this —
    otherwise the user's own immediate re-login (right after self-revoking) would
    trigger a 'new device sign-in' email, which is confusing and not a break-in."""
    import time as _t
    now = int(_t.time())
    await db.execute(
        """INSERT INTO silnt.login_alerts (user_id, sig, last_alert_at)
           VALUES (:uid, '__revoke_grace__', :now)
           ON CONFLICT (user_id, sig)
           DO UPDATE SET last_alert_at = :now""",
        {"uid": user_id, "now": now},
    )


async def in_self_revoke_grace(user_id: str, grace_secs: int = 300) -> bool:
    """True if the user self-revoked within the last `grace_secs` (default 5 min)."""
    import time as _t
    row = await db.fetchone(
        "SELECT last_alert_at FROM silnt.login_alerts WHERE user_id = :uid AND sig = '__revoke_grace__'",
        {"uid": user_id},
    )
    if not row:
        return False
    return (int(_t.time()) - int(row["last_alert_at"])) < grace_secs


async def should_send_login_alert(user_id: str, sig: str, cooldown_secs: int = 43200) -> bool:
    """
    Return True if we should send an unauthorized-device login alert for this
    (user, device signature), and record that we're doing so. Deduplicated: once
    an alert is sent for a signature, we won't send another for the same
    signature until `cooldown_secs` has elapsed (default 12h). Prevents spamming
    the user when an untrusted device repeatedly hits device-check (refreshes,
    VPN flaps, dropped cookies).
    """
    import time as _t
    now = int(_t.time())
    row = await db.fetchone(
        "SELECT last_alert_at FROM silnt.login_alerts WHERE user_id = :uid AND sig = :sig",
        {"uid": user_id, "sig": sig},
    )
    if row and (now - int(row["last_alert_at"])) < cooldown_secs:
        return False
    await db.execute(
        """INSERT INTO silnt.login_alerts (user_id, sig, last_alert_at)
           VALUES (:uid, :sig, :now)
           ON CONFLICT (user_id, sig)
           DO UPDATE SET last_alert_at = :now""",
        {"uid": user_id, "sig": sig, "now": now},
    )
    return True


async def open_tamper_notified(kind: str, key: str) -> bool:
    """True if there's an open (unacknowledged) alert of this kind referencing
    `key` that we've ALREADY sent an ntfy for (meta contains '"notified": true')."""
    rows = await db.fetchall(
        """SELECT meta FROM silnt.admin_alerts
           WHERE kind = :kind AND acknowledged = FALSE""",
        {"kind": kind},
    )
    for r in rows:
        m = r["meta"] or ""
        if key and key in m and '"notified": true' in m:
            return True
    return False


async def mark_tamper_notified(kind: str, key: str) -> None:
    """Mark open alert(s) of this kind referencing `key` as notified, so the
    sweep doesn't re-send the ntfy on subsequent runs while the tamper persists."""
    rows = await db.fetchall(
        """SELECT id, meta FROM silnt.admin_alerts
           WHERE kind = :kind AND acknowledged = FALSE""",
        {"kind": kind},
    )
    for r in rows:
        m = r["meta"] or ""
        if not (key and key in m):
            continue
        try:
            d = json.loads(m) if m else {}
        except Exception:
            d = {}
        d["notified"] = True
        await db.execute(
            "UPDATE silnt.admin_alerts SET meta = :meta WHERE id = :id",
            {"meta": json.dumps(d), "id": r["id"]},
        )


async def resolve_open_alerts_for(kind: str, key: str) -> int:
    """Auto-acknowledge open alert(s) of this kind referencing `key`. Used by the
    tamper sweep when a previously-mismatched BitMail now resolves correctly (the
    DNS record was fixed), so the stale alert clears itself. Returns count cleared."""
    rows = await db.fetchall(
        """SELECT id, meta FROM silnt.admin_alerts
           WHERE kind = :kind AND acknowledged = FALSE""",
        {"kind": kind},
    )
    cleared = 0
    for r in rows:
        m = r["meta"] or ""
        if not (key and key in m):
            continue
        await db.execute(
            "UPDATE silnt.admin_alerts SET acknowledged = TRUE WHERE id = :id",
            {"id": r["id"]},
        )
        cleared += 1
    return cleared

