import base64
import coincurve
import hashlib
import httpx
import io
import math
import struct
from typing import Optional
from base64 import b64encode
from embit import bip32, bip39, ec, finalizer, script
from embit.networks import NETWORKS
from binascii import hexlify
from .curve import bech32_encode, Encoding
from .curve import int_from_bytes, Point
from loguru import logger
from lnbits.utils.crypto import AESCipher
from cryptography.fernet import Fernet
from embit.transaction import (
    Transaction,
    TransactionInput,
    TransactionOutput,
    SIGHASH,
    Witness,
)
from embit.psbt import PSBT, InputScope
from embit.script import Script
from embit.networks import NETWORKS
from .curve import (
    decode,
    convertbits,
    int_from_bytes,
    serP,
    ser256,
    has_even_y,
    G,
    p as CURVE_P,
)
# EC scalar ops via libsecp256k1 (constant-time, ~100x faster) — validated
# byte-for-byte against curve.py's pure-Python versions
# (helpers/_curve_equivalence_check.py).
from .curve_native import pubkey_point_gen_from_int, point_add, point_mul
from embit.ec import SchnorrSig
from mnemonic import Mnemonic
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ── Phase 1: per-input tweaked signing keys + scripts (orig steps 1–2) ────────
def _prepare_inputs(spend_key, utxos: list[dict]):
    """
    For each UTXO, derive the full signing key (priv_key_tweak + spend_key, with
    BIP-340 odd-Y negation) and its taproot script. Returns parallel lists.
    """
    n = SECP256K1_N
    input_keys = []
    input_scripts = []
    for utxo in utxos:
        priv_key_tweak_hex = utxo.get("priv_key_tweak") or ""
        if not priv_key_tweak_hex:
            raise ValueError(f"Missing priv_key_tweak for utxo {utxo['txid']}")

        pub_key_hex = utxo.get("pub_key") or ""
        if not pub_key_hex:
            raise ValueError(f"Missing pub_key for utxo {utxo['txid']}")

        priv_tweak_int  = int_from_bytes(bytes.fromhex(priv_key_tweak_hex))
        spend_key_int   = int_from_bytes(spend_key.secret)
        full_secret_int = (priv_tweak_int + spend_key_int) % n

        full_pub_point = pubkey_point_gen_from_int(full_secret_int)
        if not has_even_y(full_pub_point):
            full_secret_int = n - full_secret_int
            full_pub_point  = pubkey_point_gen_from_int(full_secret_int)

        signing_key   = ec.PrivateKey(full_secret_int.to_bytes(32, "big"))
        actual_x_only = bytes.fromhex(pub_key_hex)
        actual_script = Script(bytes([0x51, 0x20]) + actual_x_only)

        input_keys.append(signing_key)
        input_scripts.append((actual_script, actual_x_only))

    return input_keys, input_scripts


# ── Phase 2: recipient scriptPubKey (orig step 3) ─────────────────────────────
def _derive_recipient_script(recipient: str, spend_key, utxos: list[dict]) -> Script:
    if recipient.startswith("sp1") or recipient.startswith("tsp1"):
        return Script(derive_sp_scriptpubkey(recipient, spend_key.secret, utxos))
    try:
        return script.address_to_scriptpubkey(recipient)
    except Exception as e:
        raise ValueError(f"Invalid recipient address: {str(e)}")


# ── Phase 3: amounts, fee, change (orig step 4) ───────────────────────────────
def _compute_amounts(utxos: list[dict], amount: int, fee_rate: float):
    """
    Returns (total_input, fee, change_amount, estimated_vsize).
    Dust change (<546) is absorbed into the fee, leaving change_amount = 0.
    """
    total_input = sum(u["amount"] for u in utxos)
    estimated_vsize = int(10 + (57.5 * len(utxos)) + (31 * 2))
    fee = max(1, math.ceil(estimated_vsize * fee_rate))
    change_amount = total_input - amount - fee

    if change_amount < 0:
        raise ValueError(
            f"Insufficient funds. Need {amount + fee} sats "
            f"(including {fee} sats fee), have {total_input} sats."
        )

    if 0 < change_amount < 546:
        logger.debug(f"Change {change_amount} sats below dust — adding to fee")
        fee += change_amount
        change_amount = 0

    return total_input, fee, change_amount, estimated_vsize


# ── Phase 4: BIP-352 m=0 change scriptPubKey (orig step 5) ────────────────────
def _derive_change_script(change_amount, scan_secret_hex, spend_key, utxos, network):
    """Returns the change Script, or None when change is dust/zero."""
    if change_amount < 546:
        return None
    spend_pub_hex = coincurve.PublicKey.from_secret(
        spend_key.secret
    ).format(compressed=True).hex()
    hrp = "sp" if network.lower() == "mainnet" else "tsp"
    change_sp_address = generate_labeled_sp_address(
        scan_secret_hex=scan_secret_hex,
        spend_pub_hex=spend_pub_hex,
        m=0,                                   # BIP-352 change label (m=0)
        hrp=hrp,
    )
    return Script(derive_sp_scriptpubkey(change_sp_address, spend_key.secret, utxos))


# ── Phase 5: assemble + verify outputs (orig steps 7 + 7b) ────────────────────
def _assemble_outputs(amount, recipient_script, change_amount, change_script, recipient):
    tx_outputs = [TransactionOutput(amount, recipient_script)]
    if change_script is not None:
        tx_outputs.append(TransactionOutput(change_amount, change_script))

    tx_outputs.sort(
        key=lambda x: (
            x.value,
            x.script_pubkey.data.hex()
            if hasattr(x.script_pubkey, "data")
            else bytes(x.script_pubkey).hex(),
        )
    )

    if recipient.startswith("sp1") or recipient.startswith("tsp1"):
        if not verify_sp_output(recipient_script, tx_outputs):
            raise ValueError(
                "Derived SP recipient output not found in transaction outputs. "
                "Funds would be unrecoverable. Aborting."
            )
    if change_script is not None:
        if not verify_sp_output(change_script, tx_outputs):
            raise ValueError(
                "Derived SP change output not found in transaction outputs. "
                "Change would be unrecoverable. Aborting."
            )

    return tx_outputs


# ── Phase 6: build PSBT, sign, finalize, serialize (orig steps 6 + 8 + 9 + 10) ─
def _build_sign_finalize(utxos, input_keys, input_scripts, tx_outputs):
    """
    BIP69-sort inputs, construct + sign (SIGHASH_DEFAULT) + finalize the PSBT,
    return the serialized tx hex.
    """
    # step 6 — inputs (BIP69 sorted), keep keys/scripts/amounts aligned
    tx_inputs_with_keys = [
        (
            TransactionInput(bytes.fromhex(u["txid"]), int(u.get("vout", 0))),
            input_keys[i],
            input_scripts[i],
            u["amount"],
        )
        for i, u in enumerate(utxos)
    ]
    tx_inputs_with_keys.sort(key=lambda x: (x[0].txid.hex(), x[0].vout))

    tx_inputs            = [t[0] for t in tx_inputs_with_keys]
    input_keys_sorted    = [t[1] for t in tx_inputs_with_keys]
    input_scripts_sorted = [t[2] for t in tx_inputs_with_keys]
    input_amounts_sorted = [t[3] for t in tx_inputs_with_keys]

    # step 8 — construct PSBT + witness_utxos
    tx   = Transaction(vin=tx_inputs, vout=tx_outputs)
    psbt = PSBT(tx)
    for i in range(len(tx_inputs)):
        psbt.inputs[i].witness_utxo = TransactionOutput(
            input_amounts_sorted[i], input_scripts_sorted[i][0]
        )

    # step 9 — sign each input (SIGHASH_DEFAULT = 0, commits to whole tx)
    utxo_amounts = [inp.witness_utxo.value         for inp in psbt.inputs]
    utxo_scripts = [inp.witness_utxo.script_pubkey for inp in psbt.inputs]
    for i in range(len(psbt.inputs)):
        h          = taproot_sighash(tx, i, utxo_scripts, utxo_amounts, sighash_type=0)
        priv_bytes = input_keys_sorted[i].secret
        cc_key     = coincurve.PrivateKey(priv_bytes)
        sig_bytes  = cc_key.sign_schnorr(h).rjust(64, b"\x00")
        psbt.inputs[i].taproot_key_sig = SchnorrSig.parse(sig_bytes)

    # step 10 — finalize + extract
    for inp in psbt.inputs:
        if inp.taproot_key_sig is not None:
            inp.final_scriptwitness = Witness([inp.taproot_key_sig.serialize()])
            inp.final_scriptsig     = Script(b"")
    for i, inp in enumerate(psbt.inputs):
        if inp.final_scriptwitness:
            tx.vin[i].witness = inp.final_scriptwitness

    return tx.serialize().hex()

def _validate_or_generate_mnemonic(
    plain_mnemonic: Optional[str],
) -> tuple[str, bool]:
    """
    Returns (mnemonic_plain, was_generated).
    - If plain_mnemonic is provided: validate 12 words + BIP-39 checksum.
    - If absent: generate a fresh 12-word seed.
    """    
    mn = Mnemonic("english")

    if plain_mnemonic:
        words = plain_mnemonic.strip().lower().split()
        if len(words) != 12:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail=f"Mnemonic must be exactly 12 words (got {len(words)}).",
            )
        normalized = " ".join(words)
        if not mn.check(normalized):
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="Invalid mnemonic — the checksum (last word) is incorrect. "
                       "Double-check your recovery phrase.",
            )
        return normalized, False

    # Generate a new 12-word mnemonic (128 bits entropy)
    return mn.generate(strength=128), True

def get_seed(mnemonic, passphrase: str = "") -> bytes:
    """
    Re‑creates the BIP‑39 seed from the hard‑coded mnemonic.
    Returns the 64‑byte seed (as `bytes`).
    """
    seed = bip39.mnemonic_to_seed(mnemonic, password=passphrase)
    return seed


def generate_hardened_keys(seed, network: str = "mainnet") -> dict:
    # BIP352: coin_type 0 = mainnet, 1 = testnet/signet
    coin_type = 0 if network == "mainnet" else 1
    xprv_version = (
        NETWORKS["main"]["xprv"] if network == "mainnet" else NETWORKS["test"]["xprv"]
    )

    root = bip32.HDKey.from_seed(seed, version=xprv_version)

    scan_path = f"m/352h/{coin_type}h/0h/1h/0"
    spend_path = f"m/352h/{coin_type}h/0h/0h/0"

    scan_private_key = root.derive(scan_path).key.secret
    spend_private_key = root.derive(spend_path).key.secret
    scank = root.derive(scan_path).key.secret
    spendk = root.derive(spend_path)

    return {
        "scan_priv_key": scan_private_key,
        "spend_priv_key": spend_private_key,
        "scank": hexlify(scank).decode(),
        "spendk": spendk.get_public_key(),
    }


def encode_silent_payment_address(
    B_scan: Point, B_m: Point, hrp: str = "tsp", version: int = 0
) -> str:
    if B_scan is None or B_m is None:
        raise ValueError("ERROR: Invalid data.")
    ret = bech32_encode(
        hrp, [version] + convertbits(serP(B_scan) + serP(B_m), 8, 5), Encoding.BECH32M
    )
    if decode(hrp, ret) == (None, None):
        raise ValueError("ERROR: Invalid data.")
    return ret


async def generate_silent_wallet_address(mnemonic, passphrase="", network: str = "mainnet") -> tuple:
    seed = get_seed(mnemonic, passphrase=passphrase)
    key_material = generate_hardened_keys(seed, network)

    B_scan = pubkey_point_gen_from_int(int_from_bytes(key_material["scan_priv_key"]))
    B_spend = pubkey_point_gen_from_int(int_from_bytes(key_material["spend_priv_key"]))

    # mainnet → 'sp', signet/testnet → 'tsp'
    hrp = "sp" if network == "mainnet" else "tsp"
    sp = encode_silent_payment_address(B_scan, B_spend, hrp, 0)

    spend_priv_hex = hexlify(key_material["spend_priv_key"]).decode()
    scan_key_hex = key_material["scank"]

    return (str(sp), scan_key_hex, spend_priv_hex)


def parse_sp_address(sp_address: str) -> tuple:
    """Extract B_scan and B_spend as compressed pubkey bytes from a Silent Payment address."""
    hrp = "tsp" if sp_address.startswith("tsp") else "sp"
    version, decoded = decode(hrp, sp_address)
    if decoded is None:
        raise ValueError(f"Invalid Silent Payment address: {sp_address}")
    b_scan_bytes = bytes(decoded[:33])
    b_spend_bytes = bytes(decoded[33:66])
    return b_scan_bytes, b_spend_bytes


def compressed_pubkey_to_point(compressed: bytes) -> tuple:
    """Parse a compressed SEC1 pubkey bytes into a curve Point."""
    prefix = compressed[0]
    x = int_from_bytes(compressed[1:33])
    y_sq = (pow(x, 3, CURVE_P) + 7) % CURVE_P
    y = pow(y_sq, (CURVE_P + 1) // 4, CURVE_P)
    if (y % 2 == 0) != (prefix == 0x02):
        y = CURVE_P - y
    return (x, y)


def derive_sp_scriptpubkey(
    sp_address: str,
    spend_secret: bytes,
    utxos: list[dict],
) -> bytes:
    b_scan_bytes, b_spend_bytes = parse_sp_address(sp_address)
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    # Step 1: sum input private keys, negating taproot keys with odd Y
    a_sum = 0
    A_points = []
    for u in utxos:
        priv = (
            int.from_bytes(bytes.fromhex(u["priv_key_tweak"]), "big")
            + int.from_bytes(spend_secret, "big")
        ) % n
        pub_point = pubkey_point_gen_from_int(priv)
        if pub_point[1] % 2 == 1:  # odd Y — negate (taproot requirement)
            priv = n - priv
            pub_point = pubkey_point_gen_from_int(priv)
        a_sum = (a_sum + priv) % n
        A_points.append(pub_point)

    # Step 2: A_sum = sum of all input pubkeys
    A_sum_point = A_points[0]
    for pt in A_points[1:]:
        A_sum_point = point_add(A_sum_point, pt)
    A_sum_bytes = bytes([0x02 + (A_sum_point[1] % 2)]) + ser256(A_sum_point[0])

    # Step 3: smallest outpoint = min(reversed_txid || vout_LE)
    outpoints = [
        bytes.fromhex(u["txid"])[::-1] + int(u.get("vout", 0)).to_bytes(4, "little")
        for u in utxos
    ]
    outpointL = min(outpoints)

    # Step 4: input_hash = TaggedHash("BIP0352/Inputs", outpointL || A_sum)
    input_hash_bytes = tagged_hash("BIP0352/Inputs", outpointL + A_sum_bytes)
    input_hash = int.from_bytes(input_hash_bytes, "big")

    # Step 5: shared_secret = (a_sum * input_hash) * B_scan
    a_tweaked = (a_sum * input_hash) % n
    B_scan = compressed_pubkey_to_point(b_scan_bytes)
    ecdh_point = point_mul(B_scan, a_tweaked)

    # Step 6: t_k = TaggedHash("BIP0352/SharedSecret", serP(ecdh) || ser32(0))
    ecdh_compressed = bytes([0x02 + (ecdh_point[1] % 2)]) + ser256(ecdh_point[0])
    t_k_bytes = tagged_hash(
        "BIP0352/SharedSecret", ecdh_compressed + (0).to_bytes(4, "big")
    )
    t_k = int.from_bytes(t_k_bytes, "big")

    # Step 7: P = B_spend + t_k*G
    B_spend = compressed_pubkey_to_point(b_spend_bytes)
    tG = pubkey_point_gen_from_int(t_k)
    P = point_add(B_spend, tG)

    return bytes([0x51, 0x20]) + ser256(P[0])


def verify_sp_output(
    recipient_script: Script,
    tx_outputs: list[TransactionOutput],
) -> bool:
    """
    Verify the derived SP scriptpubkey appears in the transaction outputs.
    Call this after building tx_outputs but before signing.
    """
    expected = bytes(recipient_script.data)
    for out in tx_outputs:
        out_script = (
            out.script_pubkey.data
            if hasattr(out.script_pubkey, "data")
            else bytes(out.script_pubkey)
        )
        if out_script == expected:
            return True
    return False

# ── Public entry point — same signature + return as before ────────────────────
def build_transaction(
    spend_key_hex:   str,
    scan_secret_hex: str,
    recipient:       str,
    amount:          int,
    fee_rate:        float,
    utxos:           list[dict],
    network:         str = "Mainnet",
) -> dict:
    """
    Build and sign a Bitcoin transaction.
    Supports Silent Payment addresses (sp1/tsp1) and standard on-chain addresses.
    Change goes to the wallet's own m=0 labeled SP address (BIP-352 reserved
    change label). Returns dict with tx_hex, fee, amount, change.
    """
    spend_key = ec.PrivateKey(bytes.fromhex(spend_key_hex))

    input_keys, input_scripts = _prepare_inputs(spend_key, utxos)
    recipient_script = _derive_recipient_script(recipient, spend_key, utxos)
    total_input, fee, change_amount, estimated_vsize = _compute_amounts(
        utxos, amount, fee_rate
    )
    change_script = _derive_change_script(
        change_amount, scan_secret_hex, spend_key, utxos, network
    )
    tx_outputs = _assemble_outputs(
        amount, recipient_script, change_amount, change_script, recipient
    )
    tx_hex = _build_sign_finalize(utxos, input_keys, input_scripts, tx_outputs)

    return {
        "tx_hex":        tx_hex,
        "fee":           fee,
        "amount":        amount,
        "change":        change_amount,
        "total_input":   total_input,
        "recipient":     recipient,
        "fee_rate_used": fee_rate,
        "vsize":         estimated_vsize,
    }


def decrypt_mnemonic(
    m: str | None = None, k: str | None = None, urlsafe: bool = False
) -> str | None:
    """
    Decrypt message with the secret key

    Args:
        m: Message to decrypt
        k: Key used to decrypt
        urlsafe: Whether the message uses URL-safe base64 encoding
    """
    if not m:
        return None
    return AESCipher(key=k).decrypt(m, urlsafe=urlsafe)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def tagged_hash(tag: str, data: bytes) -> bytes:
    tag_bytes = tag.encode()
    tag_hash = sha256(tag_bytes)
    return sha256(tag_hash + tag_hash + data)


def taproot_sighash(
    tx: Transaction,
    input_index: int,
    utxo_scripts: list,
    utxo_amounts: list,
    sighash_type: int = 0,
) -> bytes:
    """
    Compute BIP341 taproot key-path sighash manually.
    """

    # sha_prevouts
    prevouts = b""
    for vin in tx.vin:
        prevouts += vin.txid[::-1] + vin.vout.to_bytes(4, "little")
    sha_prevouts = sha256(prevouts)
    # sha_amounts
    amounts = b""
    for amt in utxo_amounts:
        amounts += amt.to_bytes(8, "little")
    sha_amounts = sha256(amounts)
    # sha_scriptpubkeys
    scripts = b""
    for s in utxo_scripts:
        script_bytes = s.data if hasattr(s, "data") else bytes(s)
        scripts += len(script_bytes).to_bytes(1, "little") + script_bytes
    sha_scriptpubkeys = sha256(scripts)
    # sha_sequences
    sequences = b""
    for vin in tx.vin:
        sequences += vin.sequence.to_bytes(4, "little")
    sha_sequences = sha256(sequences)
    # sha_outputs
    outputs = b""
    for vout in tx.vout:
        script_bytes = (
            vout.script_pubkey.data
            if hasattr(vout.script_pubkey, "data")
            else bytes(vout.script_pubkey)
        )
        outputs += vout.value.to_bytes(8, "little")
        outputs += len(script_bytes).to_bytes(1, "little") + script_bytes
    sha_outputs = sha256(outputs)
    # spend_type = 0 (key path, no annex)
    spend_type = (0).to_bytes(1, "little")

    # input data
    vin = tx.vin[input_index]
    input_data = (
        vin.txid
        + vin.vout.to_bytes(4, "little")
        + utxo_amounts[input_index].to_bytes(8, "little")
        + len(utxo_scripts[input_index].data).to_bytes(1, "little")
        + utxo_scripts[input_index].data
        + vin.sequence.to_bytes(4, "little")
    )

    # Full sighash preimage
    preimage = (
        bytes([0x00])  # epoch
        + sighash_type.to_bytes(1, "little")  # hash_type
        + tx.version.to_bytes(4, "little")  # nVersion
        + tx.locktime.to_bytes(4, "little")  # nLockTime
        + sha_prevouts
        + sha_amounts
        + sha_scriptpubkeys
        + sha_sequences
        + sha_outputs
        + spend_type
        + input_index.to_bytes(4, "little")  # input_index
    )
    return tagged_hash("TapSighash", preimage)


def generate_labeled_sp_address(
    scan_secret_hex: str, spend_pub_hex: str, m: int, hrp: str = "sp"
) -> str:
    """
    Derive a BIP-352 LABELED Silent Payment address.

        B_m = B_spend + TaggedHash("BIP0352/Label", b_scan || ser32(m)) * G

    Reserved indices (per BIP-352 spec):
      - m=0  → change label (reserved, per BIP-352, for self-send change
                outputs; a real tweak IS applied. Never hand this address out.)
      - m≥1  → user-defined labels
      The default/base address is the UNLABELED address (B_spend directly, no
      tweak) — it is computed elsewhere, not via this function.

    Args:
        scan_secret_hex: receiver's scan private key (hex)
        spend_pub_hex:   receiver's spend public key (33-byte compressed, hex)
        m:               label index (must be ≥ 1)
        hrp:             "sp" for mainnet, "tsp" for testnet/signet
    """
    if not isinstance(m, int):
        raise TypeError(f"label_index (m) must be an integer, got {type(m).__name__}")
    if m < 0:
        raise ValueError(
            f"label_index must be ≥ 0 (m=0 is the change label; the base "
            f"address is unlabeled and derived separately; got m={m})"
        )
    scan_secret_bytes = bytes.fromhex(scan_secret_hex)
    spend_pub_bytes = bytes.fromhex(spend_pub_hex)

    # BIP352: TaggedHash("BIP0352/Label", scan_secret || ser32(m)) — big-endian
    tag_hash = hashlib.sha256("BIP0352/Label".encode()).digest()
    label_hash = hashlib.sha256(
        tag_hash + tag_hash + scan_secret_bytes + struct.pack(">I", m)
    ).digest()

    # B_m = B_spend + label_hash * G
    B_m = coincurve.PublicKey.combine_keys(
        [
            coincurve.PublicKey(spend_pub_bytes),
            coincurve.PublicKey.from_secret(label_hash),
        ]
    ).format(compressed=True)

    # B_scan pubkey
    B_scan = coincurve.PublicKey.from_secret(scan_secret_bytes).format(compressed=True)

    return bech32_encode(hrp, [0] + convertbits(B_scan + B_m, 8, 5), Encoding.BECH32M)


def get_spend_pub_from_secret(spend_secret_hex: str) -> str:
    """Derive compressed spend public key from spend private key hex."""
    pub = coincurve.PublicKey.from_secret(bytes.fromhex(spend_secret_hex))
    return pub.format(compressed=True).hex()
