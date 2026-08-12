import httpx
from loguru import logger
from ..crud import (
    get_backend_config,
    get_wallet_unspent_utxos_for_dust_check,
    get_wallet_owned_outpoints,
    is_own_sent_tx,
    update_utxo_dust_flag,    
    set_utxo_freeze_auto,
    clear_utxo_freeze_auto,
    normalize_unfrozen_override,
    get_utxo_freeze_reason,
    get_effective_dust_threshold,
    get_silnt_wallet
)

# BIP-352 change label is m=0. m=1 is the legacy change index (wallets created
# before the fix); both are self-send change, never third-party dust.
BIP352_CHANGE_LABEL_INDEX = 0
BIP352_CHANGE_LABEL_INDICES = (0, 1)

async def _funding_tx_inputs_match_owned(
    txid: str,
    owned_outpoints: set[tuple[str, int]],
    mempool_base: str,
) -> bool:
    base = mempool_base.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(f"{base}/api/tx/{txid}")
            if r.status_code != 200:
                return False
            tx = r.json()

            input_outpoints: set[tuple[str, int]] = set()
            for vin in tx.get("vin", []):
                in_txid = vin.get("txid")
                in_vout = vin.get("vout")
                if in_txid is None or in_vout is None:
                    continue
                try:
                    input_outpoints.add((in_txid, int(in_vout)))
                except (TypeError, ValueError):
                    continue

            return bool(input_outpoints & owned_outpoints)
    except Exception as e:
        logger.warning(f"Dust check: could not fetch tx {txid}: {e}")
        return False


async def evaluate_dust_for_wallet(wallet_id: str) -> int:
    """
    Reconcile suspected_dust + auto-freeze state for every unspent UTXO.

    Idempotent: produces the correct (dust, frozen, freeze_reason) tuple for
    each UTXO regardless of prior state. Manual freezes are never touched.

    Returns the number of UTXOs that transitioned from non-dust to dust on
    this run (useful for the "flagged N new dust UTXO(s)" log line).
    """
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        return 0
    threshold = await get_effective_dust_threshold(wallet.user, wallet.network)
    backend   = await get_backend_config(wallet.network)
    mempool   = backend.mempool_url or "https://mempool.space"

    utxos             = await get_wallet_unspent_utxos_for_dust_check(wallet_id)
    owned_outpoints   = await get_wallet_owned_outpoints(wallet_id)

    logger.info(
        f"Dust eval: wallet={wallet_id} threshold={threshold} "
        f"unspent_count={len(utxos)} owned_outpoints={len(owned_outpoints)}"
    )

    newly_flagged = 0

    for u in utxos:
        amount       = int(u.get("amount") or 0)
        utxo_txid    = u.get("txid") or ""
        utxo_vout    = int(u.get("vout") or 0)
        current_dust = bool(u.get("suspected_dust") or False)

        if not utxo_txid:
            continue

        # Determine the correct classification for this UTXO
        if amount > threshold:
            should_be_dust = False
        else:
            if u.get("label_index") in BIP352_CHANGE_LABEL_INDICES:
                should_be_dust = False
            else:
                is_self_send = await is_own_sent_tx(wallet_id, utxo_txid)
                if not is_self_send:
                    is_self_send = await _funding_tx_inputs_match_owned(
                        utxo_txid, owned_outpoints, mempool
                    )
                should_be_dust = not is_self_send

        logger.info(
            f"  utxo {utxo_txid[:12]}:{utxo_vout} amount={amount} "
            f"current_dust={current_dust} should_be_dust={should_be_dust}"
        )

        # Reconcile state — always make the DB match the classification
        if should_be_dust:
            # Ensure suspected_dust=TRUE AND freeze_reason='auto'
            if not current_dust:
                await update_utxo_dust_flag(utxo_txid, utxo_vout, True)
                newly_flagged += 1
            # Always ensure auto-freeze is set when classified as dust.
            # set_utxo_freeze_auto only writes freeze_reason='auto'; it does
            # NOT clobber existing manual freezes (the WHERE in the UPDATE
            # filters by current state, or the helper should — see note).
            current_reason = await get_utxo_freeze_reason(utxo_txid, utxo_vout)
            if current_reason not in ("manual", "manual_unfrozen"):
                await set_utxo_freeze_auto(utxo_txid, utxo_vout)
        else:
            # Ensure suspected_dust=FALSE; release any auto-freeze (leave manual)
            if current_dust:
                await update_utxo_dust_flag(utxo_txid, utxo_vout, False)
            await clear_utxo_freeze_auto(utxo_txid, utxo_vout)
            await normalize_unfrozen_override(utxo_txid, utxo_vout)

    if newly_flagged:
        logger.info(f"Wallet {wallet_id}: flagged {newly_flagged} new dust UTXO(s)")

    return newly_flagged