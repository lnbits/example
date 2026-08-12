"""
PayJoin merge builder (helper) — builds the final UNSIGNED two-party PayJoin
PSBT from descriptors. Descriptor-based (not zpub+fp): derives addresses/keys and
key-origins straight from the output descriptors, so PSBT BIP32_DERIVATION matches
exactly what each wallet declared (the thing that made Sparrow recognize inputs).

Model (sender-pays-fee, receiver is payee):
  payment output = amount + R  (to receiver's payment address)
  sender change  = S - amount - fee
  unsigned; both parties sign their own input independently; siLNt combines.
"""

from __future__ import annotations

from embit import script
from embit.descriptor import Descriptor
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput

DUST = 546
P2WPKH_IN_VB = 68


def _net(network: str):
    n = network.lower()
    if n == "mainnet":
        return NETWORKS["main"]
    if n == "regtest":
        return NETWORKS["regtest"]
    return NETWORKS["test"]


def _spk_bytes(spk):
    return spk.data if hasattr(spk, "data") else bytes(spk)


def _strip_checksum_merge(descriptor: str) -> str:
    """Remove BIP-380 '#checksum' and repair mangled/single-chain multipath so a
    verbatim Sparrow export (or a client-mangled '//*') parses + derives both
    chains."""
    s = (descriptor or "").strip()
    if "#" in s:
        s = s[: s.rindex("#")].strip()
    if "//*" in s:
        s = s.replace("//*", "/<0;1>/*")
    elif "/<0;1>/*" not in s and "/0/*" in s:
        s = s.replace("/0/*", "/<0;1>/*")
    return s


def _key_and_origin(descriptor: str, chain: int, index: int):
    """Derive (pubkey, scriptPubKey, DerivationPath) for one input/output from a
    descriptor at chain/index. Uses the descriptor's own key-origin so the PSBT
    derivation matches the signer's wallet."""
    d = Descriptor.from_string(_strip_checksum_merge(descriptor))
    # derive the concrete key at branch=chain, index
    dd = d.derive(index, branch_index=chain)
    # dd.keys[0].key is an HDKey (extended key, serializes to 78 bytes). The PSBT
    # BIP32_DERIVATION map MUST be keyed by the bare 33-byte compressed pubkey, so
    # take HDKey.key -> embit.ec.PublicKey. (Using the HDKey directly produces a
    # malformed PSBT key: Sparrow rejects "key type must be one byte plus pub key".)
    hd = dd.keys[0].key             # HDKey
    key = hd.key                    # embit.ec.PublicKey (33-byte compressed)
    spk = dd.script_pubkey()        # Script (p2wpkh)
    # origin: master fingerprint + full path (account_path + chain + index)
    ko = d.keys[0].origin
    full_path = list(ko.derivation) + [chain, index]
    return key, spk, DerivationPath(ko.fingerprint, full_path)


def build_merged_payjoin(
    sender_descriptor: str, sender_inputs: list[dict],
    receiver_descriptor: str, receiver_input: dict,
    network: str, destination: str, amount: int, fee_rate: float,
    sender_change_index: int = 0,
) -> dict:
    metas = []   # (TransactionInput, pubkey, spk, value, DerivationPath)
    S = 0
    for u in sender_inputs:
        key, spk, dp = _key_and_origin(sender_descriptor, int(u["chain"]), int(u["index"]))
        vin = TransactionInput(bytes.fromhex(u["txid"]), int(u["vout"]))
        vin.sequence = 0xFFFFFFFD
        metas.append((vin, key, spk, int(u["value"]), dp))
        S += int(u["value"])

    rk, rspk, rdp = _key_and_origin(receiver_descriptor,
                                    int(receiver_input["chain"]), int(receiver_input["index"]))
    rvin = TransactionInput(bytes.fromhex(receiver_input["txid"]), int(receiver_input["vout"]))
    rvin.sequence = 0xFFFFFFFD
    R = int(receiver_input["value"])
    metas.append((rvin, rk, rspk, R, rdp))

    n_in = len(sender_inputs) + 1
    vsize = int(10 + P2WPKH_IN_VB * n_in + 31 * 2)
    fee = max(1, round(vsize * fee_rate))
    sender_change = S - amount - fee
    if sender_change < 0:
        raise ValueError(f"Sender can't cover amount+fee: have {S}, need {amount + fee}")

    pay_spk = script.address_to_scriptpubkey(destination)
    payment_value = amount + R
    tx_outputs = [TransactionOutput(payment_value, pay_spk)]
    out_meta = [None]

    if sender_change >= DUST:
        ckey, cspk, cdp = _key_and_origin(sender_descriptor, 1, sender_change_index)
        tx_outputs.append(TransactionOutput(sender_change, cspk))
        out_meta.append((ckey, cdp))
    else:
        fee += max(0, sender_change)
        sender_change = 0

    # BIP-69 ordering
    in_idx = sorted(range(len(metas)), key=lambda i: (metas[i][0].txid.hex(), metas[i][0].vout))
    metas = [metas[i] for i in in_idx]
    out_idx = sorted(range(len(tx_outputs)),
                     key=lambda i: (tx_outputs[i].value, _spk_bytes(tx_outputs[i].script_pubkey).hex()))
    tx_outputs = [tx_outputs[i] for i in out_idx]
    out_meta = [out_meta[i] for i in out_idx]

    tx = Transaction(version=2, vin=[m[0] for m in metas], vout=tx_outputs)
    psbt = PSBT(tx)
    for i, (vin, key, spk, val, dp) in enumerate(metas):
        psbt.inputs[i].witness_utxo = TransactionOutput(val, spk)
        psbt.inputs[i].bip32_derivations[key] = dp
    for i, m in enumerate(out_meta):
        if m is not None:
            key, dp = m
            psbt.outputs[i].bip32_derivations[key] = dp

    return {
        "psbt_base64": psbt.to_string(),
        "sender_in": S, "receiver_in": R,
        "payment_value": payment_value, "amount": amount,
        "fee": fee, "sender_change": sender_change, "vsize": vsize, "n_inputs": n_in,
    }