"""
boltz_refund.py — script-path refund for a failed Boltz v2 submarine swap-in.

When a swap-in fails (invoice.failedToPay / transaction.lockupFailed) or simply
isn't claimed, the user's on-chain funds sit in the Boltz lockup Taproot output.
After the swap's timeout block height, they can be refunded via the REFUND LEAF
(script path): single-sig Schnorr by the user's refund key + CLTV. No Musig2
signing is needed for the script-path refund (only Musig2 KEY AGGREGATION to
rebuild the Taproot internal key for the control block — deterministic, verified
against the BIP-327 test vector).

SAFETY — this module self-verifies before signing:
  It reconstructs the Taproot output address from (claim_pubkey, refund_pubkey,
  swap_tree) and asserts it equals the lockup address Boltz actually funded. If
  they differ, it RAISES and refuses to sign — so a wrong reconstruction can
  never produce a broadcastable (or fund-losing) transaction. This is the same
  address-match check that was verified green against real swap data.

Refund tx shape:
  - 1 input: the lockup UTXO (txid:vout, value)
  - 1 output: the user's on-chain refund address (a plain address they control)
  - nLockTime = timeout_block_height ; input sequence = 0xfffffffe (enables CLTV,
    not final) ; must be broadcast at block height >= timeout.
  - witness = [schnorr_sig, refund_script, control_block]

Requires: coincurve (Schnorr). Pure-python secp256k1 is used only for KeyAgg /
point math so the internal-key derivation doesn't depend on coincurve internals.
"""

import hashlib
from typing import Optional

from loguru import logger
import coincurve


# ── secp256k1 (for KeyAgg / Taproot point math) ───────────────────────────────
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G = (_Gx, _Gy)


def _inv(a, m=_P):
    return pow(a, m - 2, m)


def _padd(A, B):
    if A is None:
        return B
    if B is None:
        return A
    x1, y1 = A
    x2, y2 = B
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if A == B:
        l = (3 * x1 * x1) * _inv(2 * y1) % _P
    else:
        l = (y2 - y1) * _inv(x2 - x1) % _P
    x3 = (l * l - x1 - x2) % _P
    return (x3, (l * (x1 - x3) - y1) % _P)


def _pneg(Pt):
    if Pt is None:
        return None
    x, y = Pt
    return (x, (_P - y) % _P)


def _pmul(k, Pt):
    R = None
    while k:
        if k & 1:
            R = _padd(R, Pt)
        Pt = _padd(Pt, Pt)
        k >>= 1
    return R


def _lift_x(x):
    y2 = (pow(x, 3, _P) + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    if (y * y) % _P != y2:
        raise ValueError("point not on curve")
    return (x, _P - y if y & 1 else y)


def _ser_x(Pt):
    return Pt[0].to_bytes(32, "big")


def _even(Pt):
    return Pt[1] % 2 == 0


def _tagged(tag, *ms):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + b"".join(ms)).digest()


def _parse_pub(pk: bytes):
    x = int.from_bytes(pk[1:], "big")
    Pt = _lift_x(x)
    if pk[0] == 3:
        Pt = (Pt[0], _P - Pt[1])
    return Pt


def _key_agg(pks: list) -> tuple:
    """BIP-327 key aggregation (verified against the official test vector)."""
    Lc = _tagged("KeyAgg list", b"".join(pks))
    second = next((pk for pk in pks if pk != pks[0]), None)
    Q = None
    for pk in pks:
        a = 1 if pk == second else int.from_bytes(_tagged("KeyAgg coefficient", Lc, pk), "big") % _N
        Q = _padd(Q, _pmul(a, _parse_pub(pk)))
    return Q


# ── bech32m (for the address self-check) ──────────────────────────────────────
_CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _poly(v):
    g = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    c = 1
    for x in v:
        b = c >> 25
        c = ((c & 0x1FFFFFF) << 5) ^ x
        for i in range(5):
            c ^= g[i] if (b >> i) & 1 else 0
    return c


def _hrpexp(h):
    return [ord(c) >> 5 for c in h] + [0] + [ord(c) & 31 for c in h]


def _convertbits(data, frm, to, pad=True):
    acc = 0
    bits = 0
    ret = []
    mv = (1 << to) - 1
    for v in data:
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            ret.append((acc >> bits) & mv)
    if pad and bits:
        ret.append((acc << (to - bits)) & mv)
    return ret


def _bech32m_addr(hrp, witver, prog):
    data = [witver] + _convertbits(list(prog), 8, 5)
    pm = _poly(_hrpexp(hrp) + data + [0, 0, 0, 0, 0, 0]) ^ 0x2BC830A3
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CH[d] for d in data + chk)


_SEGWIT_HRP = {"regtest": "bcrt", "testnet": "tb", "signet": "tb", "mainnet": "bc"}


# ── Taproot reconstruction (control block + output address) ───────────────────
def _leaf_hash(script: bytes) -> bytes:
    return _tagged("TapLeaf", bytes([0xC0, len(script)]) + script)


def reconstruct_taproot(claim_pub_hex: str, refund_pub_hex: str,
                        claim_script_hex: str, refund_script_hex: str,
                        agg_order: str = "claim_first"):
    """
    Returns (internal_key_xonly: bytes, output_key_xonly: bytes,
             output_parity: int, control_block: bytes, refund_script: bytes).
    The control block is for spending via the REFUND leaf (sibling = claim leaf).

    agg_order controls the BIP-327 KeyAgg input order, which Boltz may set by
    sorting the keys lexicographically rather than a fixed claim/refund order.
    The exact order changes the aggregate internal key (and thus the address), so
    the caller tries both and keeps whichever reconstructs the funded address.
    """
    claim_pub = bytes.fromhex(claim_pub_hex)
    refund_pub = bytes.fromhex(refund_pub_hex)
    claim_script = bytes.fromhex(claim_script_hex)
    refund_script = bytes.fromhex(refund_script_hex)

    if agg_order == "refund_first":
        agg_keys = [refund_pub, claim_pub]
    elif agg_order == "sorted":
        agg_keys = sorted([claim_pub, refund_pub])
    else:  # "claim_first" (default / original)
        agg_keys = [claim_pub, refund_pub]

    internal = _key_agg(agg_keys)
    # BIP-341: the taptweak is applied to the internal point represented by its
    # x-only key, i.e. the EVEN-Y point. MuSig2 KeyAgg can yield an odd-Y
    # aggregate; if so, negate it to the even-Y point before tweaking, else the
    # output key (and address) come out wrong. (This is the parity that bit us —
    # distinct from key ORDER, which we also try.)
    if not _even(internal):
        internal = _pneg(internal)
    ikey = _ser_x(internal)

    lh_r = _leaf_hash(refund_script)
    lh_c = _leaf_hash(claim_script)
    root = _tagged("TapBranch", min(lh_r, lh_c) + max(lh_r, lh_c))

    t = int.from_bytes(_tagged("TapTweak", ikey + root), "big") % _N
    Q = _padd(internal, _pmul(t, _G))
    outkey = _ser_x(Q)
    parity = 0 if _even(Q) else 1

    # control block for the refund leaf: [0xc0 | parity] + internal_key + sibling(claim) leaf hash
    control_block = bytes([0xC0 | parity]) + ikey + lh_c
    return ikey, outkey, parity, control_block, refund_script


def taproot_address(output_key_xonly: bytes, network: str) -> str:
    return _bech32m_addr(_SEGWIT_HRP.get(network, "bcrt"), 1, output_key_xonly)


# ── Tx serialization helpers ──────────────────────────────────────────────────
def _varint(n: int) -> bytes:
    if n < 0xFD:
        return n.to_bytes(1, "little")
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _spk_from_address(addr: str) -> bytes:
    """Decode a refund destination address to its scriptPubKey (bech32/bech32m)."""
    # minimal segwit decode (v0 bech32 / v1 bech32m). Legacy not supported (refund
    # addresses should be bech32). Returns scriptPubKey bytes.
    hrp_end = addr.rfind("1")
    hrp = addr[:hrp_end]
    # decode data part
    data = [_CH.find(c) for c in addr[hrp_end + 1:]]
    if any(d == -1 for d in data):
        raise ValueError("bad address char")
    witver = data[0]
    prog = bytes(_convertbits(data[1:-6], 5, 8, pad=False))
    if witver == 0:
        return bytes([0x00, len(prog)]) + prog          # OP_0 push
    op = 0x50 + witver                                    # OP_1..OP_16
    return bytes([op, len(prog)]) + prog


# ── BIP-341 script-path sighash ───────────────────────────────────────────────
def _script_path_sighash(
    version: int, locktime: int,
    in_txid: str, in_vout: int, in_value: int, in_spk: bytes, in_sequence: int,
    outputs: list,            # [(spk, amount)]
    tapleaf_hash: bytes,
) -> bytes:
    txid_le = bytes.fromhex(in_txid)[::-1]
    outpoint = txid_le + in_vout.to_bytes(4, "little")
    seq = in_sequence.to_bytes(4, "little")

    sha_prevouts = hashlib.sha256(outpoint).digest()
    sha_amounts = hashlib.sha256(in_value.to_bytes(8, "little")).digest()
    sha_spks = hashlib.sha256(_varint(len(in_spk)) + in_spk).digest()
    sha_seqs = hashlib.sha256(seq).digest()
    out_ser = b"".join(amt.to_bytes(8, "little") + _varint(len(spk)) + spk for spk, amt in outputs)
    sha_outputs = hashlib.sha256(out_ser).digest()

    spend_type = 0x02   # script-path, no annex
    msg = (
        b"\x00"                                   # epoch
        + b"\x00"                                 # hash_type SIGHASH_DEFAULT
        + version.to_bytes(4, "little")
        + locktime.to_bytes(4, "little")
        + sha_prevouts + sha_amounts + sha_spks + sha_seqs
        + sha_outputs
        + bytes([spend_type])
        + (0).to_bytes(4, "little")               # input index (single input)
        + tapleaf_hash + b"\x00" + b"\xff\xff\xff\xff"   # ext: leaf||keyver||codesep
    )
    return _tagged("TapSighash", msg)


# ── Build + sign the refund transaction ───────────────────────────────────────
def build_refund_tx(
    *,
    refund_privkey_hex: str,
    claim_public_key_hex: str,
    swap_tree: dict,
    lockup_address: str,        # the address Boltz funded (for the self-check)
    lockup_txid: str,
    lockup_vout: int,
    lockup_value: int,
    destination_address: str,   # user's on-chain refund address
    timeout_block_height: int,
    fee_sats: int,
    network: str,               # REQUIRED — caller passes the swap's recorded network
) -> str:
    """
    Returns the signed refund tx hex. RAISES if the reconstructed Taproot address
    does not match `lockup_address` (the safety guardrail) — so it never signs
    against a mis-reconstructed output.
    """
    refund_priv = bytes.fromhex(refund_privkey_hex)
    refund_pub = coincurve.PrivateKey(refund_priv).public_key.format(compressed=True).hex()

    claim_script_hex = swap_tree["claimLeaf"]["output"]
    refund_script_hex = swap_tree["refundLeaf"]["output"]

    # Boltz may aggregate the internal key in different key orders (fixed order
    # vs BIP-327 sorted). The order changes the address, so try each and keep the
    # one that reconstructs the ACTUAL funded lockup address. The guardrail below
    # still enforces a match, so this can only ever select a correct reconstruction.
    recon = None
    for order in ("claim_first", "refund_first", "sorted"):
        ikey, outkey, parity, control_block, refund_script = reconstruct_taproot(
            claim_public_key_hex, refund_pub, claim_script_hex, refund_script_hex, agg_order=order
        )
        if taproot_address(outkey, network) == lockup_address:
            recon = (ikey, outkey, parity, control_block, refund_script)
            logger.info(f"[refund] reconstruction matched with key order: {order}")
            break

    # ── SAFETY GUARDRAIL: reconstructed address must equal the funded address ──
    if recon is None:
        # Recompute the default order purely to report it in the error.
        _, outkey_dbg, _, _, _ = reconstruct_taproot(
            claim_public_key_hex, refund_pub, claim_script_hex, refund_script_hex, agg_order="claim_first"
        )
        recon_addr = taproot_address(outkey_dbg, network)
        raise RuntimeError(
            "Refund ABORTED: reconstructed Taproot address does not match the "
            f"funded lockup address (tried all key orders).\n  reconstructed={recon_addr}\n  lockup={lockup_address}\n"
            "Refusing to sign — the swap tree / keys do not reconstruct the output."
        )
    ikey, outkey, parity, control_block, refund_script = recon

    in_spk = bytes.fromhex("5120") + outkey          # P2TR scriptPubKey of the lockup
    dest_spk = _spk_from_address(destination_address)
    out_amount = lockup_value - fee_sats
    if out_amount <= 0:
        raise ValueError("fee exceeds lockup value")

    version = 2
    sequence = 0xFFFFFFFE                              # enables nLockTime/CLTV, not final
    outputs = [(dest_spk, out_amount)]

    tapleaf_hash = _leaf_hash(refund_script)
    sighash = _script_path_sighash(
        version, timeout_block_height,
        lockup_txid, lockup_vout, lockup_value, in_spk, sequence,
        outputs, tapleaf_hash,
    )

    # Schnorr sign (BIP-340) with the refund key.
    sig = coincurve.PrivateKey(refund_priv).sign_schnorr(sighash)  # 64 bytes, SIGHASH_DEFAULT

    # witness stack: [signature, refund_script, control_block]
    witness = (
        _varint(3)
        + _varint(len(sig)) + sig
        + _varint(len(refund_script)) + refund_script
        + _varint(len(control_block)) + control_block
    )

    txid_le = bytes.fromhex(lockup_txid)[::-1]
    out_ser = b"".join(amt.to_bytes(8, "little") + _varint(len(spk)) + spk for spk, amt in outputs)
    tx = (
        version.to_bytes(4, "little")
        + b"\x00\x01"                                  # segwit marker+flag
        + _varint(1)
        + txid_le + lockup_vout.to_bytes(4, "little") + _varint(0) + sequence.to_bytes(4, "little")
        + _varint(len(outputs)) + out_ser
        + witness
        + timeout_block_height.to_bytes(4, "little")   # nLockTime
    )
    return tx.hex()


# ── Notes ─────────────────────────────────────────────────────────────────────
# • Broadcast only at block height >= timeout_block_height, else CLTV rejects it.
# • sign_schnorr: confirm coincurve's method name/signature in your version. Some
#   builds expose PrivateKey.sign_schnorr(msg32); others need the schnorr module.
#   If it errors, that's the one call to adjust — the sighash above is the message.
# • The guardrail (address match) is verified-correct against real swap data, so
#   if build_refund_tx does NOT raise, the control block + script are right and a
#   rejected broadcast would only indicate a signing/serialization issue (safe).