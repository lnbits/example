"""
boltz_swap.py — add to the siLNt extension (Boltz v2 submarine swap, SP → Lightning).

This is the OPTION A happy-path swap-in: it replaces the dead v1 LNbits Boltz
extension (which can't talk to the v2-only regtest/mainnet Boltz backend).

Flow (chain → lightning / "submarine swap"):
  1. Mint a BOLT11 invoice on the user's LNbits wallet for the amount to receive.
  2. Generate a fresh refund keypair (secp256k1). Store the refund PRIVKEY so a
     future refund tx can be built (refund tx construction itself is NOT in this
     happy-path module — see the NOT-REFUND-SAFE note below).
  3. POST {boltz}/v2/swap/submarine { invoice, to:'BTC', from:'BTC',
     refundPublicKey } → Boltz returns the on-chain lockup `address` +
     `expectedAmount` + `swapTree`/`claimPublicKey`/`timeoutBlockHeight`.
  4. Return address + expectedAmount to the client; the user funds it from SP
     UTXOs via the normal Send flow.
  5. Boltz sees the on-chain payment and pays the invoice; sats land in the
     LNbits wallet. (Cooperative claim at `transaction.claim.pending` is OPTIONAL
     for swap-in — Boltz claims via script path on interval if we don't help, so
     the happy path does not need Musig2.)

⚠️ NOT REFUND-SAFE YET: if a swap-in FAILS after the user has sent on-chain, a
refund requires constructing a Taproot refund transaction with the stored refund
key (Musig2 cooperative or script-path). That shared Taproot/Musig2 layer is the
deferred next phase (it is also what Lightning→SP claim needs). For now we store
the refund key + swap tree so a refund CAN be built later, and we surface the
risk to the user in the UI. Test on regtest only until refunds are implemented.

Config: set SILNT boltz endpoint in the extension settings/env, e.g.
  BOLTZ_API_URL = http://127.0.0.1:9001   (regtest: boltz-backend-nginx)
  (mainnet: https://api.boltz.exchange)
"""

import json
import secrets
from http import HTTPStatus
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from loguru import logger
from pydantic import BaseModel

import coincurve

from lnbits.core.services import create_invoice
from lnbits.decorators import require_admin_key
from lnbits.core.models import WalletTypeInfo
from .crud import (
    get_backend_config,
    DEFAULT_CONFIG_NETWORK,
    get_boltz_swap,
    create_boltz_swap,
    update_boltz_swap
  )  # siLNt's existing config accessor
from .models import CreateSwapInRequest, SwapInResponse, BoltzSwapRecord, FundedRequest
from .swap_crypto import encrypt_refund_key

# ── Config ────────────────────────────────────────────────────────────────────
# boltz_url is stored in the per-network siLNt backend config (same store as
# blindbit_url / mempool_url), editable in the Thrilla Admin screen. Read it the
# same way the scanner reads blindbit_url, keyed by the swap's network.
#
#   regtest → http://127.0.0.1:9001   (boltz-backend-nginx)
#   mainnet → https://api.boltz.exchange
async def _boltz_url(network: str = DEFAULT_CONFIG_NETWORK) -> str:

    cfg = await get_backend_config(network)
    url = cfg.boltz_url
    if not url:
        raise HTTPException(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "Swaps are not configured. Set the Boltz API URL in Admin settings.",
        )
    return url


async def _boltz_get(path: str, network: str = DEFAULT_CONFIG_NETWORK) -> dict:
    base = await _boltz_url(network)
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(f"{base}{path}")
        r.raise_for_status()
        return r.json()


async def _boltz_post(path: str, body: dict, network: str = DEFAULT_CONFIG_NETWORK) -> dict:
    base = await _boltz_url(network)
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(f"{base}{path}", json=body)
        if r.status_code >= 400:
            # Surface Boltz's error message
            try:
                detail = r.json().get("error", r.text)
            except Exception:
                detail = r.text
            raise HTTPException(HTTPStatus.BAD_GATEWAY, f"Boltz: {detail}")
        return r.json()


silnt_boltz_router = APIRouter()


@silnt_boltz_router.get("/api/v1/swap/limits")
async def api_swap_limits(
    network: str = Query(DEFAULT_CONFIG_NETWORK),
    key_info: WalletTypeInfo = Depends(require_admin_key),
):
    """Boltz submarine pair limits/fees (min/max), for client-side validation."""
    try:
        pairs = await _boltz_get("/v2/swap/submarine", network)
        # shape: { "BTC": { "BTC": { "limits": {"minimal":..,"maximal":..}, "fees": {...} } } }
        btc = pairs.get("BTC", {}).get("BTC", {})
        limits = btc.get("limits", {})
        fees = btc.get("fees", {})
        return {
            "min": limits.get("minimal"),
            "max": limits.get("maximal"),
            "fees": fees,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(HTTPStatus.BAD_GATEWAY, f"Could not fetch Boltz limits: {exc}")


@silnt_boltz_router.post("/api/v1/swap/in", response_model=SwapInResponse)
async def api_create_swap_in(
    data: CreateSwapInRequest,
    key_info: WalletTypeInfo = Depends(require_admin_key),
) -> SwapInResponse:
    """
    Create a Boltz v2 submarine swap (chain → lightning). Mints the LN invoice,
    generates a refund key, calls Boltz, returns the lockup address + amount.
    """
    # 1. Mint the BOLT11 invoice on the user's LNbits wallet.
    try:
        payment = await create_invoice(
            wallet_id=data.wallet_id,
            amount=data.amount,
            memo=f"Thrilla swap-in {data.amount} sats",
            extra={"tag": "silnt_swap"},
            expiry=60 * 60,  # 1h to fund the on-chain side
        )
        invoice = payment.bolt11
    except Exception as exc:
        logger.error(f"swap-in invoice creation failed: {exc}")
        raise HTTPException(HTTPStatus.BAD_REQUEST, f"Could not create invoice: {exc}")

    # 2. Fresh refund keypair (kept so a refund tx CAN be built later).
    refund_secret = secrets.token_bytes(32)
    refund_pub = coincurve.PublicKey.from_secret(refund_secret).format(compressed=True).hex()

    # 3. Create the submarine swap on Boltz v2.
    try:
        swap = await _boltz_post(
            "/v2/swap/submarine",
            {
                "invoice": invoice,
                "to": "BTC",
                "from": "BTC",
                "refundPublicKey": refund_pub,
            },
            data.network,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"swap-in boltz create failed: {exc}")
        raise HTTPException(HTTPStatus.BAD_GATEWAY, f"Boltz create failed: {exc}")

    swap_id = swap.get("id")
    address = swap.get("address")
    expected = swap.get("expectedAmount")
    if not (swap_id and address and expected):
        raise HTTPException(HTTPStatus.BAD_GATEWAY, "Boltz response missing swap fields")

    # 4. PERSIST refund material (durable — a refund may be needed later/after restart).
    rec = BoltzSwapRecord(
        id=swap_id,
        wallet_id=data.wallet_id,
        silnt_wallet_id=data.silnt_wallet_id,
        network=data.network,
        status="created",
        refund_privkey=encrypt_refund_key(refund_secret.hex()),
        refund_public_key=refund_pub,
        claim_public_key=swap.get("claimPublicKey"),
        swap_tree=swap.get("swapTree"),
        timeout_block_height=swap.get("timeoutBlockHeight"),
        address=address,                      # lockup address (guardrail checks this)
        expected_amount=int(expected),
        invoice=invoice,
        payment_hash=payment.payment_hash,
        refund_address=data.refund_address,   # where a failed-swap refund goes
    )
    await create_boltz_swap(rec)
    return SwapInResponse(
        swap_id=swap_id,
        address=address,
        expected_amount=int(expected),
        timeout_block_height=swap.get("timeoutBlockHeight"),
        payment_hash=payment.payment_hash
    )


@silnt_boltz_router.get("/api/v1/swap/in/{swap_id}")
async def api_swap_in_status(
    swap_id: str,
    key_info: WalletTypeInfo = Depends(require_admin_key),
):
    """Poll a swap's status from Boltz (client can also use the WS directly)."""
    try:
        rec = await get_boltz_swap(swap_id)
        network = rec.network if rec and rec.network else DEFAULT_CONFIG_NETWORK
        status = await _boltz_get(f"/v2/swap/submarine/{swap_id}", network)
        return status
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(HTTPStatus.BAD_GATEWAY, f"Could not fetch status: {exc}")
    # If Boltz reports the swap is done (it claimed the lockup / invoice settled),
    # advance our record to "completed" so the UI stops showing it as active.
    boltz_state = status.get("status") if isinstance(status, dict) else None
    if boltz_state in ("transaction.claimed", "invoice.settled"):
        rec = await get_boltz_swap(swap_id)
        if rec and rec.status not in ("completed", "refunded"):
            rec.status = "completed"
            await update_boltz_swap(rec)
    return status

@silnt_boltz_router.post("/api/v1/swap/in/{swap_id}/funded")
async def api_swap_in_funded(
    swap_id: str,
    data: FundedRequest,
    key_info: WalletTypeInfo = Depends(require_admin_key),
):
    """
    Record the on-chain lockup outpoint after the SP send broadcasts. REQUIRED for
    a refund to be buildable later. The client passes only the funding txid; we
    resolve which vout pays the lockup address (and its value) by fetching the tx
    from the mempool/esplora endpoint — so the client doesn't have to guess the vout.
    """
    rec = await get_boltz_swap(swap_id)
    if not rec:
        raise HTTPException(HTTPStatus.NOT_FOUND, "Swap not found.")
    if rec.wallet_id != key_info.wallet.id and rec.silnt_wallet_id != key_info.wallet.id:
        raise HTTPException(HTTPStatus.FORBIDDEN, "Not your swap.")

    # Fetch the tx and find the output paying the lockup address.
    cfg = await get_backend_config(rec.network or DEFAULT_CONFIG_NETWORK)
    mempool = cfg.mempool_url
    if not mempool:
        raise HTTPException(HTTPStatus.SERVICE_UNAVAILABLE, "Mempool URL not configured.")
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.get(f"{mempool}/api/tx/{data.lockup_txid}")
        if r.status_code != 200:
            raise HTTPException(HTTPStatus.BAD_GATEWAY, f"Could not fetch funding tx: {r.status_code}")
        tx = r.json()

    vout = None
    value = None
    for i, o in enumerate(tx.get("vout", [])):
        if o.get("scriptpubkey_address") == rec.address:
            vout = i
            value = o.get("value")
            break
    if vout is None:
        raise HTTPException(HTTPStatus.BAD_REQUEST,
                            "Funding tx has no output paying the lockup address.")

    rec.lockup_txid = data.lockup_txid
    rec.lockup_vout = vout
    rec.lockup_value = int(value)
    rec.status = "funded"
    await update_boltz_swap(rec)
    return {"success": True, "swap_id": swap_id, "lockup_vout": vout, "lockup_value": int(value)}