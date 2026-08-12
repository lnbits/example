"""
boltz_refund_api.py — detect failed/refundable swap-ins and broadcast refunds.

Ties together:
  - persisted swap records (boltz_swaps table / crud)
  - Boltz status (GET /v2/swap/submarine/{id})
  - the current chain height (mempool/esplora)
  - build_refund_tx() (the verified script-path refund builder)
  - broadcasting via mempool_url /api/tx (the path siLNt already uses)

A swap is REFUNDABLE when:
  - it has an on-chain lockup recorded (lockup_txid/vout/value set), AND
  - it has NOT completed (status != completed/refunded), AND
  - EITHER Boltz reports a failure status (invoice.failedToPay /
    transaction.lockupFailed / swap.expired), OR the chain height has reached
    the swap's timeout_block_height (script-path refund becomes valid).

Endpoints (mounted under /siLNt):
  GET  /api/v1/swap/refundable                 → list refundable swaps for the user
  POST /api/v1/swap/{id}/refund {address}      → build + broadcast the refund tx

Also exposes refund_due_swaps() for an optional background task that auto-refunds
after timeout (mirrors how the old Boltz extension retried refunds periodically).
"""

import json
from http import HTTPStatus
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from loguru import logger
from pydantic import BaseModel

from lnbits.core.models import WalletTypeInfo
from lnbits.decorators import require_admin_key
from lnbits.core.crud import get_standalone_payment

# siLNt-local imports — adjust paths to your layout
from .crud import (
    get_backend_config,
    DEFAULT_CONFIG_NETWORK,
    get_boltz_swap,
    update_boltz_swap,
    list_boltz_swaps_by_status,
    list_boltz_swaps_for_wallet,
    delete_boltz_swap    
)
from .boltz_refund import build_refund_tx
from .models import RefundRequest
from .swap_crypto import decrypt_refund_key

FAILURE_STATES = {
    "invoice.failedToPay",
    "transaction.lockupFailed",
    "swap.expired",
}
TERMINAL_STATES = {"transaction.claimed", "invoice.settled"}  # swap succeeded
# Statuses that are terminal/finished — safe to delete from history.
DELETABLE_STATES = {"completed", "refunded", "expired"}

silnt_refund_router = APIRouter()


# ── helpers ───────────────────────────────────────────────────────────────────
async def _boltz_base(network: str = DEFAULT_CONFIG_NETWORK) -> str:
    cfg = await get_backend_config(network)
    url = cfg.boltz_url
    if not url:
        raise HTTPException(HTTPStatus.SERVICE_UNAVAILABLE, "Boltz URL not configured.")
    return url


async def _mempool_base(network: str = DEFAULT_CONFIG_NETWORK) -> str:
    cfg = await get_backend_config(network)
    url = cfg.mempool_url
    if not url:
        raise HTTPException(HTTPStatus.SERVICE_UNAVAILABLE, "Mempool URL not configured.")
    return url

async def _invoice_paid(payment_hash: Optional[str]) -> bool:
    """
    Authoritative completion check: did the swap's Lightning invoice get paid?
    A submarine swap-in completes exactly when Boltz pays our invoice. This does
    NOT depend on Boltz still remembering the swap (Boltz 404s completed swaps
    after a retention window, which left them stuck as 'funded' forever).
    """
    if not payment_hash:
        return False
    try:        
        payment = await get_standalone_payment(payment_hash, incoming=True)
        if not payment:
            logger.info(f"[swap] invoice {payment_hash[:12]}…: no payment row found")
            return False
        paid = (
            getattr(payment, "success", None) is True
            or getattr(payment, "status", "") == "success"
        )
        logger.info(f"[swap] invoice {payment_hash[:12]}…: status={getattr(payment,'status','?')} success={getattr(payment,'success','?')} → paid={paid}")
        return paid
    except Exception as exc:
        logger.warning(f"invoice paid-check failed for {payment_hash}: {exc}")
        return False

async def _invoice_failed(payment_hash) -> bool:
    if not payment_hash:
        return False
    try:        
        p = await get_standalone_payment(payment_hash, incoming=True)
        if not p:
            return False
        return getattr(p, "status", "") == "failed" or getattr(p, "failed", None) is True
    except Exception:
        return False

async def _lockup_confirmed(rec) -> bool:
    """True only if the recorded lockup tx is confirmed on-chain."""
    if not rec.lockup_txid:
        return False
    try:
        base = await _mempool_base(rec.network or DEFAULT_CONFIG_NETWORK)
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(f"{base}/api/tx/{rec.lockup_txid}/status")
            return r.status_code == 200 and bool(r.json().get("confirmed"))
    except Exception:
        return False

async def _boltz_status(swap_id: str, network: str = DEFAULT_CONFIG_NETWORK) -> Optional[str]:
    base = await _boltz_base(network)
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.get(f"{base}/v2/swap/submarine/{swap_id}")
        if r.status_code != 200:
            logger.info(f"[boltz] status {swap_id}: HTTP {r.status_code}")
            return None
        state = r.json().get("status")
        logger.info(f"[boltz] status {swap_id}: {state}")
        return state


async def _chain_height(network: str = DEFAULT_CONFIG_NETWORK) -> int:
    base = await _mempool_base(network)
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.get(f"{base}/api/blocks/tip/height")
        r.raise_for_status()
        return int(r.text.strip())


async def _broadcast(tx_hex: str, network: str = DEFAULT_CONFIG_NETWORK) -> str:
    base = await _mempool_base(network)
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(f"{base}/api/tx", content=tx_hex)
        if r.status_code != 200:
            raise HTTPException(HTTPStatus.BAD_GATEWAY, f"Broadcast rejected: {r.text}")
        return r.text.strip()  # txid


async def _is_refundable(rec, height: int) -> tuple:
    """
    Returns (refundable: bool, reason: str). A swap is refundable if it has a
    recorded lockup, isn't terminal, and is either failed at Boltz or past timeout.
    """
    if rec.status in ("refunded", "completed"):
        return False, rec.status
    if not (rec.lockup_txid and rec.lockup_vout is not None and rec.lockup_value):
        logger.info(f"[refundable?] {rec.id}: NO lockup recorded (txid={rec.lockup_txid} vout={rec.lockup_vout} value={rec.lockup_value})")
        return False, "no lockup recorded (nothing was funded on-chain yet)"

    if await _invoice_paid(rec.payment_hash):
        logger.info(f"[refundable?] {rec.id}: NOT refundable — invoice paid (swap succeeded)")
        return False, "swap already succeeded (invoice paid)"
    status = await _boltz_status(rec.id, rec.network or DEFAULT_CONFIG_NETWORK)
    logger.info(f"[refundable?] {rec.id}: boltz_status={status} height={height} timeout={rec.timeout_block_height} lockup={rec.lockup_txid}")
    if status in TERMINAL_STATES:
        return False, "swap already succeeded"
    if status in FAILURE_STATES:
        return True, f"boltz status {status}"
    if rec.timeout_block_height and height >= rec.timeout_block_height:
        logger.info(f"[refundable?] {rec.id}: REFUNDABLE via timeout ({height} >= {rec.timeout_block_height})")
        return True, f"timeout reached ({height} >= {rec.timeout_block_height})"
    blocks_left = (rec.timeout_block_height or 0) - height
    logger.info(f"[refundable?] {rec.id}: NOT refundable — not yet timeout, ~{blocks_left} blocks left")
    return False, f"not yet refundable (status {status}, ~{blocks_left} blocks to timeout)"


# ── endpoints ─────────────────────────────────────────────────────────────────


@silnt_refund_router.get("/api/v1/swap/refundable")
async def api_list_refundable(key_info: WalletTypeInfo = Depends(require_admin_key)):
    """List the caller's swaps that are currently refundable + why."""
    height = await _chain_height()
    out = []
    # Pull candidate swaps in non-terminal states.
    for state in ("created", "funded", "failed"):
        for rec in await list_boltz_swaps_by_status(state):
            if rec.wallet_id != key_info.wallet.id and rec.silnt_wallet_id != key_info.wallet.id:
                logger.info(f"[refundable?] {rec.id}: SKIPPED ownership — rec.wallet_id={rec.wallet_id} rec.silnt_wallet_id={rec.silnt_wallet_id} key.wallet.id={key_info.wallet.id}")
                continue
            logger.info(f"[refundable?] {rec.id}: candidate (status={rec.status}) — checking…")
            try:
                ok, reason = await _is_refundable(rec, height)
            except Exception as exc:
                # A Boltz/network hiccup in _is_refundable must NOT hide a
                # potentially-refundable swap. Fall back to the local, fund-safe
                # signal: lockup recorded + past timeout + not already terminal.
                logger.warning(f"refundable check errored for {rec.id}: {exc}")
                local_ok = (
                    rec.status not in ("refunded", "completed")
                    and bool(rec.lockup_txid) and rec.lockup_vout is not None and bool(rec.lockup_value)
                    and rec.timeout_block_height and height >= rec.timeout_block_height
                )
                ok, reason = local_ok, "timeout reached (boltz status unavailable)"
            if ok:
                out.append({
                    "swap_id": rec.id,
                    "amount": rec.lockup_value,
                    "timeout_block_height": rec.timeout_block_height,
                    "reason": reason,
                })
    return {"refundable": out, "chain_height": height}


@silnt_refund_router.post("/api/v1/swap/{swap_id}/refund")
async def api_refund_swap(
    swap_id: str,
    data: RefundRequest,
    key_info: WalletTypeInfo = Depends(require_admin_key),
):
    """Build + broadcast a script-path refund for a failed/timed-out swap-in."""
    rec = await get_boltz_swap(swap_id)
    if not rec:
        raise HTTPException(HTTPStatus.NOT_FOUND, "Swap not found.")
    # ownership
    if rec.wallet_id != key_info.wallet.id and rec.silnt_wallet_id != key_info.wallet.id:
        raise HTTPException(HTTPStatus.FORBIDDEN, "Not your swap.")

    height = await _chain_height(rec.network or DEFAULT_CONFIG_NETWORK)
    ok, reason = await _is_refundable(rec, height)
    if not ok:
        raise HTTPException(HTTPStatus.BAD_REQUEST, f"Not refundable: {reason}")

    # Resolve the refund destination: explicit request address, else the address
    # stored when the swap was created. Must be a plain on-chain (non-SP) address.
    dest = (data.address or rec.refund_address or "").strip()
    if not dest:
        raise HTTPException(HTTPStatus.BAD_REQUEST, "No refund address available (none provided or stored).")
    if dest.lower().startswith(("sp1", "tsp1")):
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Refund address must be a plain on-chain address, not SP.")

    # Fund-critical: never guess the network. A missing network (e.g. a legacy
    # row from before the field existed) must fail loudly, not default — a wrong
    # network would build a wrong-encoding address for real funds.
    if not rec.network:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST,
            "This swap record has no network recorded — refusing to build a refund "
            "(cannot safely determine the address encoding).",
        )

    try:
        tx_hex = build_refund_tx(
            refund_privkey_hex=decrypt_refund_key(rec.refund_privkey).strip(),
            claim_public_key_hex=rec.claim_public_key,
            swap_tree=rec.swap_tree,
            lockup_address=rec.address,            # the funded address — guardrail checks this
            lockup_txid=rec.lockup_txid,
            lockup_vout=rec.lockup_vout,
            lockup_value=rec.lockup_value,
            destination_address=dest,
            timeout_block_height=rec.timeout_block_height,
            fee_sats=data.fee_sats,
            network=rec.network,
        )
    except RuntimeError as exc:
        # The address-match guardrail or a build error. Do NOT broadcast.
        logger.error(f"refund build failed for {swap_id}: {exc}")
        raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR, f"Could not build refund: {exc}")

    txid = await _broadcast(tx_hex, rec.network or DEFAULT_CONFIG_NETWORK)
    rec.status = "refunded"
    rec.refund_address = dest
    await update_boltz_swap(rec)
    logger.info(f"Refund broadcast for swap {swap_id}: {txid}")
    return {"success": True, "txid": txid, "swap_id": swap_id, "refunded_to": dest}

@silnt_refund_router.get("/api/v1/swap/list")
async def api_list_swaps(key_info: WalletTypeInfo = Depends(require_admin_key)):
    """All of the caller's swaps (history), newest first, with a deletable flag."""
    height = await _chain_height()
    rows = await list_boltz_swaps_for_wallet(key_info.wallet.id, key_info.wallet.id)
    out = []
    for rec in rows:
        # Reconcile: if a funded swap has actually settled at Boltz, advance it to
        # "completed" so it stops showing as active (nothing else updates this).
        if rec.status == "funded":
            done = await _invoice_paid(rec.payment_hash)
            if not done:
                boltz_state = await _boltz_status(rec.id, rec.network or DEFAULT_CONFIG_NETWORK)
                done = boltz_state in TERMINAL_STATES
            if done:
                rec.status = "completed"
                await update_boltz_swap(rec)
        # Derive a display status: mark past-timeout non-terminal swaps as "expired".
        status = rec.status
        if status not in ("completed", "refunded") and rec.timeout_block_height and height >= rec.timeout_block_height:
            status = "expired" if status != "funded" else status
        if status not in ("completed", "refunded", "failed", "expired"):
            invoice_failed = await _invoice_failed(rec.payment_hash)   # see helper
            lockup_confirmed = await _lockup_confirmed(rec)            # see helper
            if invoice_failed and not lockup_confirmed:
                rec.status = "failed"
                await update_boltz_swap(rec)
                status = "failed"
        deletable = (status in DELETABLE_STATES) or (not rec.lockup_txid)
        not_expired = not (rec.timeout_block_height and height >= rec.timeout_block_height)
        fundable = (
            status == "created"
            and not rec.lockup_txid
            and not_expired
            and bool(rec.address)
            and bool(rec.expected_amount)
        )
        out.append({
            "swap_id": rec.id,
            "status": status,
            "amount": rec.expected_amount or rec.lockup_value,
            "timeout_block_height": rec.timeout_block_height,
            "silnt_wallet_id": rec.silnt_wallet_id,
            "payment_hash": rec.payment_hash,
            "deletable": deletable,
            "fundable": fundable,
            # funding details (so the client can resume funding from history):
            "address": rec.address if fundable else None,
            "expected_amount": rec.expected_amount if fundable else None,
        })
    return {"swaps": out, "chain_height": height}


@silnt_refund_router.delete("/api/v1/swap/{swap_id}")
async def api_delete_swap(
    swap_id: str,
    key_info: WalletTypeInfo = Depends(require_admin_key),
):
    """Delete a finished swap (completed/refunded/expired) from history."""
    rec = await get_boltz_swap(swap_id)
    if not rec:
        raise HTTPException(HTTPStatus.NOT_FOUND, "Swap not found.")
    if rec.wallet_id != key_info.wallet.id and rec.silnt_wallet_id != key_info.wallet.id:
        raise HTTPException(HTTPStatus.FORBIDDEN, "Not your swap.")

    # Only allow deleting genuinely finished swaps — never an active/refundable one,
    # so a user can't accidentally discard a swap whose funds are still recoverable.
    height = await _chain_height(rec.network or DEFAULT_CONFIG_NETWORK)
    status = rec.status
    if status not in ("completed", "refunded"):
        # is it expired (past timeout and never refunded)? Block deletion if it's
        # still refundable — losing the record would lose the refund key.
        refundable, _ = await _is_refundable(rec, height)
        if refundable:
            raise HTTPException(
                HTTPStatus.BAD_REQUEST,
                "This swap is still refundable — refund it before deleting, or you'll lose the ability to recover the funds.",
            )
        # not refundable and not completed: only deletable if it never got funded
        # (no lockup) — i.e. nothing at stake.
        if rec.lockup_txid:
            raise HTTPException(
                HTTPStatus.BAD_REQUEST,
                "Swap has on-chain funds and isn't completed or refunded yet; can't delete.",
            )

    await delete_boltz_swap(swap_id)
    return {"success": True, "deleted": swap_id}

# ── optional: background auto-refund (call from a periodic task) ───────────────
async def refund_due_swaps(default_fee_sats: int = 300) -> list:
    """
    Auto-refund swaps that are refundable AND have a refund_address on record.
    Returns a list of {swap_id, txid|error}. Wire to a periodic task if you want
    the old extension's "retry every N minutes" behavior. Swaps without a stored
    refund_address are skipped (a destination is required).
    """
    results = []
    height = await _chain_height()
    for state in ("created", "funded", "failed"):
        for rec in await list_boltz_swaps_by_status(state):
            ok, _ = await _is_refundable(rec, height)
            if not ok or not rec.refund_address:
                continue
            if not rec.network:
                # Never guess network for a fund-critical refund; skip legacy rows.
                logger.warning(f"auto-refund skipped for {rec.id}: no network recorded")
                continue
            try:
                tx_hex = build_refund_tx(
                    refund_privkey_hex=decrypt_refund_key(rec.refund_privkey),
                    claim_public_key_hex=rec.claim_public_key,
                    swap_tree=rec.swap_tree,
                    lockup_address=rec.address,
                    lockup_txid=rec.lockup_txid,
                    lockup_vout=rec.lockup_vout,
                    lockup_value=rec.lockup_value,
                    destination_address=rec.refund_address,
                    timeout_block_height=rec.timeout_block_height,
                    fee_sats=default_fee_sats,
                    network=rec.network,
                )
                txid = await _broadcast(tx_hex, rec.network)
                rec.status = "refunded"
                await update_boltz_swap(rec)
                results.append({"swap_id": rec.id, "txid": txid})
            except Exception as exc:
                logger.warning(f"auto-refund failed for {rec.id}: {exc}")
                results.append({"swap_id": rec.id, "error": str(exc)})
    return results