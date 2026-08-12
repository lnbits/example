"""
PSBT combine + finalize for P2WPKH (the step siLNt's coordinator owns).

Two parties each sign the SAME unsigned merged PSBT in their own Sparrow, each
exporting a PSBT whose inputs carry partial_sigs only for THEIR input(s). This:
  1. combines all partial_sigs into one PSBT (manual merge, no embit .update),
  2. finalizes each P2WPKH input -> final_scriptwitness = [sig, pubkey],
  3. serializes the network transaction hex.

Avoids embit's Script.__eq__ trap: never use `x in (None, {}, ...)` on embit
objects (that calls Script.__eq__ which does self.data == other.data and throws
on None). Use `is None` / len() checks only.

Usage:
  python psbt_combine.py <signed_psbt_a_b64> <signed_psbt_b_b64> [...]

All PSBTs must be signed copies of the SAME unsigned tx.
"""

from __future__ import annotations

import sys

from embit.psbt import PSBT
from embit.transaction import Witness


def combine_and_finalize(psbt_b64_list: list[str]) -> dict:
    if not psbt_b64_list:
        raise ValueError("need at least one PSBT")

    base = PSBT.from_string(psbt_b64_list[0])
    n = len(base.inputs)

    # combine: merge partial_sigs from every PSBT
    for extra_b64 in psbt_b64_list[1:]:
        other = PSBT.from_string(extra_b64)
        if len(other.inputs) != n:
            raise ValueError("PSBTs have different input counts - not the same tx")
        for i in range(n):
            src = getattr(other.inputs[i], "partial_sigs", None)
            if src:
                if getattr(base.inputs[i], "partial_sigs", None) is None:
                    base.inputs[i].partial_sigs = type(src)()
                for pub, sig in src.items():
                    base.inputs[i].partial_sigs[pub] = sig
            if base.inputs[i].witness_utxo is None and other.inputs[i].witness_utxo is not None:
                base.inputs[i].witness_utxo = other.inputs[i].witness_utxo

    sig_report = []
    for i in range(n):
        ps = getattr(base.inputs[i], "partial_sigs", None)
        sig_report.append((i, bool(ps)))

    missing = [i for i, ok in sig_report if not ok]
    if missing:
        return {
            "n_inputs": n,
            "sig_report": sig_report,
            "finalized": False,
            "finalize_error": f"inputs missing partial_sigs: {missing}",
            "combined_psbt": base.to_string(),
        }

    # finalize each P2WPKH input: witness = [sig, pubkey]
    tx = base.tx
    for i in range(n):
        ps = base.inputs[i].partial_sigs
        pub, sig = next(iter(ps.items()))
        wit = Witness([sig, pub.serialize()])
        base.inputs[i].final_scriptwitness = wit
        tx.vin[i].witness = wit

    tx_hex = tx.serialize().hex()
    return {
        "n_inputs": n,
        "sig_report": sig_report,
        "finalized": True,
        "tx_hex": tx_hex,
    }
