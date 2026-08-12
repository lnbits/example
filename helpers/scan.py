"""
scan.py — Silent Payments blockchain scanner for the silnt LNbits extension.
"""

from __future__ import annotations
import asyncio, hashlib, struct
from dataclasses import dataclass
from typing import Optional
import coincurve, httpx
from coincurve import PublicKey
from loguru import logger
from ..crud import (
    db,
    DEFAULT_CONFIG_NETWORK,
    get_backend_config,
    get_silnt_wallet,
    get_silnt_wallets,
    get_wallet_addresses,
    insert_utxos_for_wallet,
    update_balance,
    ensure_labeled_address_row
)
from .dust_check import evaluate_dust_for_wallet
from .wallet import generate_labeled_sp_address, get_spend_pub_from_secret

_scan_progress: dict[str, dict] = {}
_scan_stop: dict[str, bool] = {}
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# BIP-352 reserves label m=0 for change. Wallets created before this fix put
# change at m=1, so we keep scanning m=1 too (legacy) — cheap, and it keeps
# existing wallets' historical change detectable — while producing new change
# at the standard m=0.
BIP352_CHANGE_LABEL_INDEX = 0
BIP352_LEGACY_CHANGE_LABEL_INDICES = [1]
# The labeled-address indices the receiver ALWAYS scans, whether or not a saved
# wallet_addresses row exists for them. This is what makes deleting a labeled
# address safe: its label stays in the scan set, so payments keep being detected
# (and ensure_labeled_address_row re-creates the row). COUPLED to
# MAX_ADDRESSES_PER_WALLET in views_api.py — this set must cover every index the
# assigner can hand out (2 .. cap+1). If you widen this, you may raise that cap;
# if you raise that cap, you MUST widen this (an assert there enforces it).
BIP352_LABELED_ADDRESS_INDICES=[2,3]
# BIP-352 v1.1.0 (March 2026): a recipient group holds at most K_max = 2323
# outputs — the most P2TR outputs that fit in a 100,000-vByte standard tx.
# Cap the receiver's per-transaction scan loop at this so a maliciously crafted
# transaction packing many outputs to one scan key can't force O(N^2) work
# (each match rescans the remaining outputs); the cap bounds it to O(N*K_max).
# Honest transactions never reach it, so conforming receivers are unaffected.
BIP352_MAX_OUTPUTS_PER_GROUP = 2323

@dataclass
class Label:
    pub_key: bytes
    tweak: bytes
    address: str = ""
    m: int = 0


@dataclass
class FoundOutput:
    output: bytes
    sec_key_tweak: bytes
    label: Optional[Label] = None


@dataclass
class OwnedUTXO:
    txid: bytes
    vout: int
    amount: int
    priv_key_tweak: bytes
    pub_key: bytes
    utxo_state: str
    timestamp: int = 0
    label: Optional[Label] = None
    label_text: Optional[str] = None

    def to_db_row(self, wallet_id: str) -> dict:
        return {
            "txid": self.txid.hex(),
            "vout": self.vout,
            "amount": self.amount,
            "priv_key_tweak": self.priv_key_tweak.hex(),
            "pub_key": self.pub_key.hex(),
            "utxo_state": self.utxo_state,
            "timestamp": self.timestamp,
            "wallet_id": wallet_id,
            "label": self.label_text,
            "label_index": self.label.m if self.label else None
        }


def request_scan_stop(wallet_id: str):
    _scan_stop[wallet_id] = True


def should_stop(wallet_id: str) -> bool:
    return _scan_stop.get(wallet_id, False)


def clear_scan_stop(wallet_id: str):
    _scan_stop.pop(wallet_id, None)


def _tagged_hash(tag: str, data: bytes) -> bytes:
    h = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(h + h + data).digest()


def _ser_u32(k: int) -> bytes:
    return struct.pack(">I", k)


def create_shared_secret(
    public_component: bytes, scan_key: bytes, input_hash: Optional[bytes] = None
) -> bytes:
    if input_hash is not None:
        scalar = (
            int.from_bytes(scan_key, "big") * int.from_bytes(input_hash, "big")
        ) % SECP256K1_N
        effective_key = scalar.to_bytes(32, "big")
    else:
        effective_key = scan_key
    return PublicKey(public_component).multiply(effective_key).format(compressed=True)


def create_output_pub_key_and_tweak(
    shared_secret: bytes, spend_pub_key: bytes, k: int
) -> tuple[bytes, bytes]:
    t_k = _tagged_hash("BIP0352/SharedSecret", shared_secret + _ser_u32(k))
    p_k = (
        PublicKey(spend_pub_key)
        .combine([PublicKey.from_secret(t_k)])
        .format(compressed=True)
    )
    return p_k[1:], t_k


def add_public_keys(pk1: bytes, pk2: bytes) -> bytes:
    if isinstance(pk1, PublicKey):
        pk1 = pk1.format(compressed=True)
    if isinstance(pk2, PublicKey):
        pk2 = pk2.format(compressed=True)
    return PublicKey(pk1).combine([PublicKey(pk2)]).format(compressed=True)


def negate_public_key(pk: bytes) -> bytes:
    return bytes([0x02 if pk[0] == 0x03 else 0x03]) + pk[1:]


def add_private_keys(sk1: bytes, sk2: bytes) -> bytes:
    return (
        (int.from_bytes(sk1, "big") + int.from_bytes(sk2, "big")) % SECP256K1_N
    ).to_bytes(32, "big")


def create_label(scan_key: bytes, m: int) -> Label:
    tweak = _tagged_hash("BIP0352/Label", scan_key + _ser_u32(m))
    return Label(
        pub_key=PublicKey.from_secret(tweak).format(compressed=True), tweak=tweak, m=m
    )


def create_labels(scan_key: bytes, indices: list[int]) -> list[Label]:
    all_indices = sorted(set(
        [BIP352_CHANGE_LABEL_INDEX]
        + BIP352_LEGACY_CHANGE_LABEL_INDICES
        + BIP352_LABELED_ADDRESS_INDICES
        + list(indices)
    ))
    return [create_label(scan_key, m) for m in all_indices]


def match_labels(
    tx_output_33: bytes, pk_33: bytes, labels: list  # list[Label]
):  # -> Optional[Label]
    try:
        diff = add_public_keys(tx_output_33, negate_public_key(pk_33))
    except Exception:
        return None
    for label in labels:
        # X-only comparison (includes parity byte) — avoids matching a label
        # that only shares an x-coordinate (its negation), which would produce a
        # wrong tweak and an unspendable detected output.
        if diff[1:] == label.pub_key[1:]:
            return label
    return None


def receiver_scan_transaction_with_shared_secret(
    scan_key: bytes,
    spend_pub_key: bytes,
    labels: list[Label],
    tx_outputs: list[bytes],
    shared_secret: bytes,
) -> list[FoundOutput]:
    found_outputs: list[FoundOutput] = []
    remaining = list(tx_outputs)
    k = 0
    # Stop at K_max even if outputs keep matching — bounds worst-case work on a
    # hostile transaction. A normal transaction exits earlier via `not found`.
    while k < BIP352_MAX_OUTPUTS_PER_GROUP:
        output_pub_key, tweak = create_output_pub_key_and_tweak(
            shared_secret, spend_pub_key, k
        )
        found = False
        for i, tx_output in enumerate(remaining):
            if output_pub_key == tx_output:
                found_outputs.append(FoundOutput(output=tx_output, sec_key_tweak=tweak))
                remaining.pop(i)
                found = True
                k += 1
                break
            if not labels:
                continue
            tx_out_33 = b"\x02" + tx_output
            out_pk_33 = b"\x02" + output_pub_key
            fl = match_labels(tx_out_33, out_pk_33, labels)
            if fl:
                found_outputs.append(
                    FoundOutput(
                        output=tx_output,
                        sec_key_tweak=add_private_keys(tweak, fl.tweak),
                        label=fl,
                    )
                )
                remaining.pop(i)
                found = True
                k += 1
                break
            tx_out_neg = negate_public_key(tx_out_33)
            fl = match_labels(tx_out_neg, out_pk_33, labels)
            if fl:
                found_outputs.append(
                    FoundOutput(
                        output=tx_out_neg[1:],
                        sec_key_tweak=add_private_keys(tweak, fl.tweak),
                        label=fl,
                    )
                )
                remaining.pop(i)
                found = True
                k += 1
                break
        if not found:
            break
    return found_outputs


def receiver_scan_transaction(
    scan_key, spend_pub_key, labels, tx_outputs, public_component, input_hash
):
    return receiver_scan_transaction_with_shared_secret(
        scan_key,
        spend_pub_key,
        labels,
        tx_outputs,
        create_shared_secret(public_component, scan_key, input_hash),
    )


def sync_block(tweaks, utxos, scan_key, spend_pub_key, labels):
    tweak_script_map: dict[bytes, tuple[bytes, bytes]] = {}
    raw = tweaks[0]
    tweak = bytes.fromhex(raw) if isinstance(raw, str) else raw
    ss = create_shared_secret(tweak, scan_key)
    opk, _ = create_output_pub_key_and_tweak(ss, spend_pub_key, 0)
    for raw in tweaks:
        tweak = bytes.fromhex(raw) if isinstance(raw, str) else raw
        ss = create_shared_secret(tweak, scan_key)
        opk, _ = create_output_pub_key_and_tweak(ss, spend_pub_key, 0)
        tweak_script_map[opk] = (tweak, opk)
        b33 = b"\x02" + opk
        for label in labels:
            try:
                lo = add_public_keys(b33, label.pub_key)
                tweak_script_map[lo[1:]] = (tweak, lo[1:])
            except Exception as e:
                logger.debug(f"label add m={label.m}: {e}")
            try:
                lon = add_public_keys(b33, negate_public_key(label.pub_key))
                tweak_script_map[lon[1:]] = (tweak, lon[1:])
            except Exception as e:
                logger.debug(f"label neg m={label.m}: {e}")
    if not tweak_script_map:
        return []
    txid_groups: dict[bytes, list[dict]] = {}
    helper_mapping: dict[bytes, bytes] = {}
    for u in utxos:
        tb = bytes.fromhex(u["txid"])
        xo = bytes.fromhex(u["pubkey"])
        txid_groups.setdefault(tb, []).append(u)
        helper_mapping[xo] = tb
    to_check: dict[bytes, list[dict]] = {}
    for xo, (tw, _) in tweak_script_map.items():
        if xo in helper_mapping:
            to_check[tw] = txid_groups[helper_mapping[xo]]
    owned: list[OwnedUTXO] = []
    for tw, rel_utxos in to_check.items():
        found = receiver_scan_transaction(
            scan_key,
            spend_pub_key,
            labels,
            [bytes.fromhex(u["pubkey"]) for u in rel_utxos],
            tw,
            None,
        )
        for fo in found:
            for u in rel_utxos:
                if fo.output == bytes.fromhex(u["pubkey"]):
                    owned.append(
                        OwnedUTXO(
                            txid=bytes.fromhex(u["txid"]),
                            vout=u["vout"],
                            amount=u["amount"],
                            priv_key_tweak=fo.sec_key_tweak,
                            pub_key=fo.output,
                            utxo_state="unspent",
                            timestamp=u.get("timestamp", 0),
                            label=fo.label,
                        )
                    )
                    break
    return owned


def sync_block_from_compute_index(index, scan_key, spend_pub_key, labels):
    owned: list[OwnedUTXO] = []
    for entry in index:
        tweak_hex = entry.get("tweak", "")
        txid = entry.get("txid", "")
        outputs_hex = entry.get("outputs", [])
        if not tweak_hex or not outputs_hex:
            continue
        try:
            ss = create_shared_secret(bytes.fromhex(tweak_hex), scan_key)
            shorts = set(outputs_hex)
            k = 0
            while True:
                opk, t_k = create_output_pub_key_and_tweak(ss, spend_pub_key, k)
                matched = False
                if opk.hex()[:16] in shorts:
                    owned.append(
                        OwnedUTXO(
                            txid=bytes.fromhex(txid),
                            vout=0,
                            amount=0,
                            priv_key_tweak=t_k,
                            pub_key=opk,
                            utxo_state="unspent",
                        )
                    )
                    matched = True
                if labels:
                    b33 = b"\x02" + opk
                    for label in labels:
                        try:
                            lo = add_public_keys(b33, label.pub_key)
                            if lo[1:].hex()[:16] in shorts:
                                owned.append(
                                    OwnedUTXO(
                                        txid=bytes.fromhex(txid),
                                        vout=0,
                                        amount=0,
                                        priv_key_tweak=add_private_keys(
                                            t_k, label.tweak
                                        ),
                                        pub_key=lo[1:],
                                        utxo_state="unspent",
                                        label=label,
                                    )
                                )
                                matched = True
                        except Exception:
                            pass
                if not matched:
                    break
                k += 1
        except Exception as e:
            logger.warning(f"compute_index txid={txid}: {e}")
    return owned

async def get_outspend_status(base_mempool_url: str, txid: str, vout: int) -> dict | None:
    """
    Exact-outpoint spent check via mempool.
    Returns {"spent": bool} when known, or None on unknown/error (caller leaves
    the UTXO in unconfirmed_spent and retries next scan).
    """
    base = (base_mempool_url or "https://mempool.space").rstrip("/")
    url = f"{base}/api/tx/{txid}/outspend/{vout}"
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as c:
            r = await c.get(url)
            if r.status_code == 404:
                # outpoint unknown to explorer — can't confirm; treat as unknown
                return None
            if r.status_code != 200:
                return None
            data = r.json()
            return {"spent": bool(data.get("spent", False))}
    except Exception as e:
        logger.warning(f"outspend check failed for {txid}:{vout}: {e}")
        return None

class BlindBitOracleClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def _client(self):
        return httpx.AsyncClient(timeout=30.0, verify=False)

    async def get_chain_tip(self) -> int:
        async with self._client() as c:
            return (await c.get(f"{self.base_url}/info")).json()["height"]

    async def get_tweaks(self, height: int) -> list[bytes]:
        async with self._client() as c:
            r = await c.get(f"{self.base_url}/tweaks/{height}")
            r.raise_for_status()
            d = r.json()
            return [
                bytes.fromhex(t) for t in (d["index"] if isinstance(d, dict) else d)
            ]

    async def get_utxos(self, height: int) -> list[dict]:
        async with self._client() as c:
            r = await c.get(f"{self.base_url}/utxos/{height}")
            r.raise_for_status()
            d = r.json()
            return d["index"] if isinstance(d, dict) else d

    async def get_spent_outputs(self, height: int) -> Optional[dict]:
        async with self._client() as c:
            r = await c.get(f"{self.base_url}/spent-outputs/{height}")
            return None if r.status_code == 404 else r.json()

    async def get_compute_index(self, height: int) -> Optional[dict]:
        async with self._client() as c:
            r = await c.get(f"{self.base_url}/compute-index/{height}")
            if r.status_code == 404:
                return None
            d = r.json()
            return d if isinstance(d, dict) and "index" in d else {"index": d}

    async def get_block_hash(self, height: int) -> Optional[dict]:
        async with self._client() as c:
            r = await c.get(f"{self.base_url}/blockhash/{height}")
            return None if r.status_code == 404 else r.json()


async def scan_block(
    height, client, scan_secret_bytes, spend_pub_bytes, labels,
    network: str,
):
    if labels:
        tweaks = await client.get_tweaks(height)
        if not tweaks:
            return []
        utxos = await client.get_utxos(height)
        if not utxos:
            return []
        # Offload the synchronous EC matching to a worker thread so it doesn't
        # block the event loop — keeps the API/UI responsive during a scan.
        loop = asyncio.get_event_loop()
        owned = await loop.run_in_executor(
            None, sync_block, tweaks, utxos, scan_secret_bytes, spend_pub_bytes, labels
        )
        for o in owned:
            if not o.timestamp:
                o.timestamp = await get_block_ts(o.txid.hex(), network)
        return owned
    compute_data = await client.get_compute_index(height)
    if compute_data:
        loop = asyncio.get_event_loop()
        matches = await loop.run_in_executor(
            None, sync_block_from_compute_index,
            compute_data["index"], scan_secret_bytes, spend_pub_bytes, labels
        )
        if matches:
            full_utxos = await client.get_utxos(height)
            lkp = {u["pubkey"]: u for u in full_utxos if "pubkey" in u}
            for owned in matches:
                ph = owned.pub_key.hex()
                full = lkp.get(ph) or next(
                    (u for u in full_utxos if u.get("pubkey", "")[:16] == ph[:16]), None
                )
                if full:
                    owned.vout = full.get("vout", owned.vout)
                    owned.amount = full.get("amount", owned.amount)
                    owned.timestamp = full.get("timestamp") or await get_block_ts(
                        full.get("txid", ""), network
                    )
                    owned.pub_key = bytes.fromhex(full["pubkey"])
        return matches
    tweaks = await client.get_tweaks(height)
    if not tweaks:
        return []
    utxos = await client.get_utxos(height)
    if not utxos:
        return []
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, sync_block, tweaks, utxos, scan_secret_bytes, spend_pub_bytes, labels
    )


async def mark_spent_utxos_batch(heights, client, wallet_id, owned_utxos_lookup, network):
    """
    Short-hash matches move UTXOs to 'unconfirmed_spent' (provisional), then each
    is verified against the exact outpoint via mempool outspend before finalizing.
    Replaces the previous version that finalized 'spent' directly on an 8-byte
    short-hash match.
    """
    if not owned_utxos_lookup:
        return

    # Resolve the mempool base once for verification.
    backend = await get_backend_config(network)
    mempool_base = backend.mempool_url or "https://mempool.space"

    async def check_height(height: int):
        try:
            spent_data = await client.get_spent_outputs(height)
            if not spent_data:
                return
            spent_set = set(spent_data.get("index", []))
            if not spent_set:
                return

            rows = await db.fetchall(
                """SELECT txid, vout, pub_key FROM silnt.utxos
                   WHERE wallet_id = :wallet_id
                   AND utxo_state IN ('unspent', 'unconfirmed_spent')""",
                {"wallet_id": wallet_id},
            )
            for row in rows:
                short_pub = row["pub_key"][:16]  # 8 bytes = 16 hex chars
                if short_pub not in spent_set:
                    continue
                # PROVISIONAL: short-hash match → mark unconfirmed_spent, do NOT
                # finalize. Only flip from 'unspent'; leave existing
                # 'unconfirmed_spent' as-is (verification below handles both).
                await db.execute(
                    """UPDATE silnt.utxos SET utxo_state = 'unconfirmed_spent'
                       WHERE txid = :txid AND vout = :vout
                         AND wallet_id = :wallet_id
                         AND utxo_state = 'unspent'""",
                    {"txid": row["txid"], "vout": row["vout"], "wallet_id": wallet_id},
                )
                # VERIFY the exact outpoint before finalizing.
                status = await get_outspend_status(mempool_base, row["txid"], row["vout"])
                if status is None:
                    # Unknown — leave as unconfirmed_spent, retry next scan.
                    logger.info(
                        f"{row['txid']}:{row['vout']} short-hash matched at block "
                        f"{height}; outspend unknown — left unconfirmed_spent"
                    )
                    continue
                if status["spent"]:
                    await db.execute(
                        """UPDATE silnt.utxos SET utxo_state = 'spent'
                           WHERE txid = :txid AND vout = :vout
                             AND wallet_id = :wallet_id
                             AND utxo_state = 'unconfirmed_spent'""",
                        {"txid": row["txid"], "vout": row["vout"], "wallet_id": wallet_id},
                    )
                    logger.info(
                        f"Confirmed {row['txid']}:{row['vout']} spent (outspend) "
                        f"at block {height}"
                    )
                else:
                    # FALSE POSITIVE: 8-byte short-hash collision. Restore unspent.
                    await db.execute(
                        """UPDATE silnt.utxos SET utxo_state = 'unspent'
                           WHERE txid = :txid AND vout = :vout
                             AND wallet_id = :wallet_id
                             AND utxo_state = 'unconfirmed_spent'""",
                        {"txid": row["txid"], "vout": row["vout"], "wallet_id": wallet_id},
                    )
                    logger.warning(
                        f"Short-hash FALSE POSITIVE: {row['txid']}:{row['vout']} "
                        f"matched spent-index at block {height} but outspend says "
                        f"unspent — restored to unspent."
                    )
        except Exception as e:
            logger.warning(f"mark_spent_utxos error at block {height}: {e}")

    # Verification adds an explorer call per matched UTXO. Matches are rare
    # (only your own spends), so this stays cheap. Kept within the same
    # asyncio.gather over heights as before.    
    await asyncio.gather(*[check_height(h) for h in heights])


async def set_last_scan_height(wallet_id: str, height: int) -> None:
    await db.execute(
        "UPDATE silnt.wallets SET last_scan_height = :height WHERE id = :id",
        {"height": height, "id": wallet_id},
    )


def get_scan_progress(wallet_id: str) -> dict:
    return _scan_progress.get(
        wallet_id, {"active": False, "current": 0, "total": 0, "found": 0, "amount": 0}
    )


def set_scan_progress(wallet_id, current, total, found, active=True, amount=0):
    _scan_progress[wallet_id] = {
        "active": active,
        "current": current,
        "total": total,
        "found": found,
        "amount": amount,
    }


async def scan_wallet(
    wallet_id: str,
    scan_secret_hex: str,  # scan private key — detection only
    spend_secret_hex: Optional[str] = None,
    from_height: Optional[int] = None,
    to_height: Optional[int] = None,
    spend_pub_hex: Optional[str] = None,
) -> dict:
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise ValueError(f"Wallet {wallet_id} not found")
    blindbit = await get_backend_config(wallet.network)
    if not blindbit.blindbit_url:
        raise ValueError("BlindBit Oracle URL not configured")

    scan_secret_bytes = bytes.fromhex(scan_secret_hex)
    # Scanning is detection-only: it needs the spend PUBLIC key, never the spend
    # private key. Accept the pubkey directly (the background scanner derives it
    # from the wallet's sp_address, so the spend key never reaches the server) or
    # derive it from a supplied spend secret (interactive client scans).
    if spend_pub_hex:
        spend_pub_bytes = bytes.fromhex(spend_pub_hex)
    elif spend_secret_hex:
        spend_pub_bytes = coincurve.PublicKey.from_secret(
            bytes.fromhex(spend_secret_hex)
        ).format(compressed=True)
    else:
        raise ValueError("scan_wallet needs spend_pub_hex or spend_secret_hex")
    spend_pub_hex_resolved = spend_pub_bytes.hex()

    oracle = BlindBitOracleClient(base_url=blindbit.blindbit_url)
    start = max(from_height if from_height is not None else wallet.last_height, 1)
    end = to_height if to_height is not None else await oracle.get_chain_tip()
    logger.info(f"Scanning wallet {wallet_id} blocks {start}–{end}")

    saved_addresses = await get_wallet_addresses(wallet_id)
    labels = create_labels(
        scan_secret_bytes, indices=[a.label_index for a in saved_addresses]
    )
    addr_label_map: dict[int, str] = {
        a.label_index: a.label
        for a in saved_addresses
        if getattr(a, "label", None)
    }
    total_found = 0
    total_found_amount = 0
    blocks_scanned = 0
    last_scanned_height = start
    total_blocks = end - start + 1
    stopped = False
    clear_scan_stop(wallet_id)
    set_scan_progress(wallet_id, 0, total_blocks, 0)
    # Smaller batches keep the span of work between event-loop yields short, so
    # navigation/API calls stay responsive during a scan.
    BATCH_SIZE = 5

    for batch_start in range(0, total_blocks, BATCH_SIZE):
        if should_stop(wallet_id):
            logger.info(f"Scan stopped at {last_scanned_height}")
            stopped = True
            await set_last_scan_height(wallet_id, last_scanned_height)
            set_scan_progress(
                wallet_id, blocks_scanned, total_blocks, total_found,
                active=False, amount=total_found_amount,
            )
            clear_scan_stop(wallet_id)
            break

        batch = list(
            range(start + batch_start, min(start + batch_start + BATCH_SIZE, end + 1))
        )

        owned_rows = await db.fetchall(
            "SELECT txid, vout FROM silnt.utxos WHERE wallet_id = :wallet_id AND utxo_state IN ('unspent', 'unconfirmed_spent')",
            {"wallet_id": wallet_id},
        )
        owned_utxos_lookup = {f"{r['txid']}:{r['vout']}": r for r in owned_rows}

        batch_results = await asyncio.gather(
            *[
                scan_block(
                    h,
                    oracle,
                    scan_secret_bytes,
                    spend_pub_bytes,
                    labels,
                    wallet.network,
                )
                for h in batch
            ],
            return_exceptions=True,
        )

        await mark_spent_utxos_batch(batch, oracle, wallet_id, owned_utxos_lookup, wallet.network)

        for h, result in zip(batch, batch_results):
            if isinstance(result, Exception):
                logger.error(f"Block {h} error: {result}")
                continue
            if result:
                # Inherit address labels onto matching UTXOs (added earlier)
                for owned in result:
                    if owned.label and owned.label.m in addr_label_map:
                        owned.label_text = addr_label_map[owned.label.m]
                    elif owned.label and owned.label.m >= 2:
                        try:
                            hrp = "sp" if (wallet.network == "mainnet") else "tsp"
                            spend_pub_hex = spend_pub_hex_resolved
                            labeled_addr = generate_labeled_sp_address(
                                scan_secret_hex=scan_secret_hex,
                                spend_pub_hex=spend_pub_hex,
                                m=owned.label.m,
                                hrp=hrp,
                            )
                            await ensure_labeled_address_row(
                                wallet_id, labeled_addr, owned.label.m
                            )
                        except Exception as e:
                            logger.warning(f"Could not restore labeled address m={owned.label.m}: {e}")    
                try:
                    # Count only genuinely NEW utxos — re-detecting an existing
                    # one on a rescan is an upsert, not a discovery, and must not
                    # inflate the "found" count the UI shows.
                    new_count, new_amount = await insert_utxos_for_wallet(wallet_id, result)
                    total_found += new_count
                    total_found_amount += new_amount
                    logger.info(
                        f"Block {h}: {len(result)} detected, {new_count} new"
                    )
                except Exception as ins_err:
                    # Log full DB error server-side for the admin to investigate,
                    # but don't crash the whole scan — just skip this block's results
                    logger.error(
                        f"Block {h}: found {len(result)} UTXO(s) but DB insert failed: {ins_err}"
                    )
                    continue
            blocks_scanned += 1
            last_scanned_height = h

        set_scan_progress(
            wallet_id, blocks_scanned, total_blocks, total_found,
            amount=total_found_amount,
        )
        await set_last_scan_height(wallet_id, last_scanned_height)

        # Yield to the event loop between batches so other requests (wallet
        # loads, navigation) get serviced promptly during a long scan.
        await asyncio.sleep(0)

    await set_last_scan_height(wallet_id, last_scanned_height)
    set_scan_progress(
        wallet_id, blocks_scanned, total_blocks, total_found,
        active=False, amount=total_found_amount,
    )

    try:
        rec = await reconcile_unconfirmed_spent(wallet_id, wallet.network)
        if rec["restored"] or rec["confirmed"]:
            logger.info(
                f"Wallet {wallet_id} reconcile: "
                f"{rec['confirmed']} confirmed, {rec['restored']} restored, "
                f"{rec['pending']} still pending"
            )
    except Exception as e:
        logger.warning(f"Reconcile failed for {wallet_id}: {e}")
        
    unspent = await db.fetchall(
        "SELECT amount FROM silnt.utxos WHERE wallet_id = :wallet_id AND utxo_state = 'unspent'",
        {"wallet_id": wallet_id},
    )
    balance = sum(r["amount"] for r in unspent)
    await update_balance(wallet_id, balance)
    try:        
        newly_flagged = await evaluate_dust_for_wallet(wallet_id)
        if newly_flagged > 0:
            logger.info(f"Wallet {wallet_id}: flagged {newly_flagged} new dust UTXO(s)")
    except Exception as e:
        logger.warning(f"Dust evaluation failed for {wallet_id}: {e}")
    logger.info(
        f"Scan done: {blocks_scanned} blocks, {total_found} UTXOs, balance={balance}"
    )
    set_scan_progress(
        wallet_id, blocks_scanned, total_blocks, total_found,
        active=False, amount=total_found_amount,
    )
    return {
        "utxos_found": total_found,
        "amount_found": total_found_amount,
        "blocks_scanned": blocks_scanned,
        "final_height": last_scanned_height,
        "balance": balance,
        "stopped": stopped
    }


async def scan_all_wallets(user: str, network: str = "mainnet") -> list[dict]:
    results = []
    for wallet in await get_silnt_wallets(user, network):
        try:
            r = await scan_wallet(wallet.id)
            r["wallet_id"] = wallet.id
            results.append(r)
        except Exception as e:
            logger.error(f"Wallet {wallet.id} failed: {e}")
            results.append({"wallet_id": wallet.id, "error": str(e)})
    return results


async def get_block_ts(txid: str, network: str = DEFAULT_CONFIG_NETWORK) -> int:
    backend = await get_backend_config(network)
    base = (backend.mempool_url or "https://mempool.space").rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(f"{base}/api/tx/{txid}")
            if r.status_code == 200:
                return int(r.json().get("status", {}).get("block_time") or 0)
    except Exception:
        pass
    return 0

async def get_tx_status(base_mempool_url: str, txid: str) -> dict | None:
    """
    Returns {"confirmed": bool} if the tx is known to the explorer,
    or None if the tx is unknown (404 — dropped / never propagated).
    """
    base = (base_mempool_url or "https://mempool.space").rstrip("/")
    url = f"{base}/api/tx/{txid}"
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as c:
            r = await c.get(url)
            if r.status_code == 404:
                return None                      # unknown → dropped
            if r.status_code != 200:
                # transient error — treat as "unknown status", do nothing this round
                return {"unknown": True}
            data = r.json()
            return {"confirmed": bool(data.get("status", {}).get("confirmed", False))}
    except Exception as e:
        logger.warning(f"tx-status check failed for {txid}: {e}")
        return {"unknown": True}                  # network hiccup — don't change state


async def reconcile_unconfirmed_spent(wallet_id: str, network: str = DEFAULT_CONFIG_NETWORK) -> dict:
    """
    Walk the wallet's unconfirmed_spent UTXOs and reconcile each against the
    explorer. Returns counts of {confirmed, restored, pending}.
    """
    backend = await get_backend_config(network)
    base = backend.mempool_url or "https://mempool.space"

    rows = await db.fetchall(
        """SELECT txid, vout, spent_in_txid FROM silnt.utxos
           WHERE wallet_id = :wid AND utxo_state = 'unconfirmed_spent'""",
        {"wid": wallet_id},
    )
    if not rows:
        return {"confirmed": 0, "restored": 0, "pending": 0}

    # Group outpoints by the spending txid so we query each tx once
    by_txid: dict[str, list[tuple[str, int]]] = {}
    for r in rows:
        stx = r["spent_in_txid"]
        if not stx:
            # No spending txid recorded but state is unconfirmed_spent — anomalous.
            # Safest is to leave it; a manual restore can handle it.
            continue
        by_txid.setdefault(stx, []).append((r["txid"], r["vout"]))

    confirmed = restored = pending = 0

    for spending_txid, outpoints in by_txid.items():
        status = await get_tx_status(base, spending_txid)

        if status is None:
            # Dropped / unknown to the explorer → the spend never happened.
            # Restore these inputs to unspent so they're spendable again.
            for (in_txid, in_vout) in outpoints:
                await db.execute(
                    """UPDATE silnt.utxos
                          SET utxo_state    = 'unspent',
                              spent_in_txid = NULL,
                              spent_at      = NULL
                        WHERE wallet_id = :wid AND txid = :txid AND vout = :vout
                          AND utxo_state = 'unconfirmed_spent'""",
                    {"wid": wallet_id, "txid": in_txid, "vout": in_vout},
                )
                restored += 1
            logger.info(
                f"Restored {len(outpoints)} UTXO(s) to unspent — spending tx "
                f"{spending_txid} was dropped/unknown"
            )

        elif status.get("confirmed"):
            # The spend confirmed → finalize as spent.
            for (in_txid, in_vout) in outpoints:
                await db.execute(
                    """UPDATE silnt.utxos SET utxo_state = 'spent'
                        WHERE wallet_id = :wid AND txid = :txid AND vout = :vout
                          AND utxo_state = 'unconfirmed_spent'""",
                    {"wid": wallet_id, "txid": in_txid, "vout": in_vout},
                )
                confirmed += 1
            logger.info(f"Finalized {len(outpoints)} UTXO(s) spent by confirmed tx {spending_txid}")

        else:
            # Still pending in mempool, or transient error → leave unchanged.
            pending += len(outpoints)

    return {"confirmed": confirmed, "restored": restored, "pending": pending}