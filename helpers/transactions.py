import time
import httpx
from loguru import logger
from ..crud import (
    get_backend_config,
    get_wallet_receives,
    get_wallet_sends,
    get_utxos_for_txid,
    get_utxos_spent_in_tx,
    get_owned_pubkeys,
)


# Per-process in-memory cache. Keyed by (mempool_base, txid).
# Acceptable to lose on restart — this is non-critical metadata.
_TX_CACHE: dict[tuple[str, str], tuple[float, dict]] = {}
_TX_CACHE_TTL = 3600  # 1 hour


async def _fetch_tx_from_mempool(txid: str, mempool_base: str) -> dict | None:
    """Fetch a tx's full mempool.space data, cached for 1hr."""
    key = (mempool_base, txid)
    now = time.time()
    cached = _TX_CACHE.get(key)
    if cached and now - cached[0] < _TX_CACHE_TTL:
        return cached[1]

    base = mempool_base.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(f"{base}/api/tx/{txid}")
            if r.status_code != 200:
                return None
            data = r.json()
            if bool(data.get("status", {}).get("confirmed")):
                _TX_CACHE[key] = (now, data)
            return data
    except Exception as e:
        logger.warning(f"Tx fetch failed for {txid}: {e}")
        return None


async def list_wallet_transactions(
    wallet_id: str,
    limit:     int = 50,
    offset:    int = 0,
) -> list[dict]:
    """
    Combined chronological transaction list from local DB (no mempool calls).

    Each row:
      { kind: 'send'|'receive',
        txid, timestamp, amount_sats,    # negative = net outflow, positive = inflow
        input_sum, output_sum,
        input_count, output_count,
        labels: [str] }
    """
    receives = {r["txid"]: r for r in await get_wallet_receives(wallet_id)}
    sends    = {s["txid"]: s for s in await get_wallet_sends(wallet_id)}

    txids = set(receives) | set(sends)
    rows = []
    for txid in txids:
        rcv = receives.get(txid)
        snd = sends.get(txid)

        if snd:
            # Spent inputs → a send. If the wallet also owns an output (change or
            # a consolidation back to self), subtract it so amount = net outflow.
            input_sum    = snd["input_sum"]
            output_sum   = rcv["output_sum"] if rcv else 0
            net_out      = input_sum - output_sum     # sent amount + fee
            kind         = "send"
            timestamp    = snd["spent_at"] or (rcv["timestamp"] if rcv else 0)
            amount_sats  = -net_out                   # negative = outflow
            labels       = rcv["labels"] if rcv else []
            input_count  = snd["input_count"]
            output_count = rcv["output_count"] if rcv else 0
            confirmed    = snd.get("pending_inputs", 0) == 0
        else:
            # No inputs spent → pure receive.
            input_sum    = 0
            output_sum   = rcv["output_sum"]
            kind         = "receive"
            timestamp    = rcv["timestamp"]
            amount_sats  = rcv["output_sum"]          # positive = inflow
            labels       = rcv["labels"]
            input_count  = 0
            output_count = rcv["output_count"]
            confirmed    = True

        rows.append({
            "kind":         kind,
            "txid":         txid,
            "timestamp":    timestamp,
            "amount_sats":  amount_sats,
            "input_sum":    input_sum,
            "output_sum":   output_sum,
            "input_count":  input_count,
            "output_count": output_count,
            "labels":       labels,
        })

    rows.sort(key=lambda r: r["timestamp"], reverse=True)
    return rows[offset:offset + limit]


async def get_wallet_transaction_detail(
    wallet_id: str,
    txid:      str,
    network:   str,
) -> dict:
    """
    Enriched view of one transaction. Pulls our own UTXOs from DB, then queries
    mempool.space for the full tx (fee, recipient, confirmation status).
    """
    backend        = await get_backend_config(network)
    mempool_base   = backend.mempool_url or "https://mempool.space"

    own_outputs    = await get_utxos_for_txid(wallet_id, txid)
    spent_inputs   = await get_utxos_spent_in_tx(wallet_id, txid)
    owned_pubkeys  = await get_owned_pubkeys(wallet_id)
    tx             = await _fetch_tx_from_mempool(txid, mempool_base)

    detail = {
        "txid":          txid,
        "own_outputs":   own_outputs,
        "spent_inputs":  spent_inputs,
        "fee_sats":      None,
        "recipients":    [],     # outputs NOT owned by us
        "confirmed":     None,
        "block_height":  None,
        "block_time":    None,
        "explorer_url":  f"{mempool_base.rstrip('/')}/tx/{txid}",
    }

    if tx is None:
        return detail

    # Fee
    detail["fee_sats"] = tx.get("fee")

    # Confirmation
    status = tx.get("status", {})
    detail["confirmed"]    = bool(status.get("confirmed"))
    detail["block_height"] = status.get("block_height")
    detail["block_time"]   = status.get("block_time")

    # Recipients = outputs whose x-only key is NOT one of ours
    for vout_data in tx.get("vout", []):
        spk_asm = vout_data.get("scriptpubkey_asm") or ""
        # Taproot: "OP_PUSHNUM_1 OP_PUSHBYTES_32 <x-only-key>"
        xonly = None
        parts = spk_asm.split()
        if len(parts) >= 3 and parts[0] == "OP_PUSHNUM_1":
            xonly = parts[-1]
        if xonly and xonly in owned_pubkeys:
            continue
        detail["recipients"].append({
            "address": vout_data.get("scriptpubkey_address"),
            "amount":  int(vout_data.get("value") or 0),
            "type":    vout_data.get("scriptpubkey_type"),
        })

    return detail