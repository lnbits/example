# coincurve / libsecp256k1-backed replacements for the pure-Python elliptic
# curve operations in curve.py.
#
# Same Point = (x, y) interface and byte-for-byte identical outputs, but the
# scalar multiplications run in libsecp256k1 (C, constant-time) instead of
# hand-rolled Python double-and-add with a Fermat modular inverse. That removes
# the secret-dependent timing on the scan/spend keys (a side-channel, relevant
# now the server holds the scan key for background scanning) and is ~100x faster.
#
# NOT yet wired into wallet.py. Validate first:
#     cd helpers && python _curve_equivalence_check.py     # needs coincurve
# Once it reports all-match, flip wallet.py's EC imports from `.curve` to
# `.curve_native` (or inline these bodies into curve.py).
from typing import Optional

from coincurve import PublicKey

try:  # normal package import
    from .curve import Point, serP, has_even_y, x, y  # noqa: F401  (re-exported)
except ImportError:  # allow the standalone check script to import it directly
    from curve import Point, serP, has_even_y, x, y  # type: ignore  # noqa: F401

# secp256k1 group order.
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _pub(P: Point) -> PublicKey:
    """A libsecp256k1 public key from an (x, y) point."""
    return PublicKey.from_point(P[0], P[1])


def pubkey_point_gen_from_int(seckey: int) -> Point:
    """seckey * G as an (x, y) point (matches curve.pubkey_point_gen_from_int).

    seckey*G and (seckey mod n)*G are the same group element, so reducing mod n
    keeps the output identical for every practical scalar (all < 2^256)."""
    d = seckey % N
    if d == 0:
        raise ValueError("scalar is 0 mod n — no valid public point")
    return PublicKey.from_secret(d.to_bytes(32, "big")).point()


def point_add(P1: Optional[Point], P2: Optional[Point]) -> Optional[Point]:
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    # P + (-P) = point at infinity (same x, different y). Handle before combine,
    # which would otherwise raise on an infinity result.
    if P1[0] == P2[0] and P1[1] != P2[1]:
        return None
    # combine_keys sums the points; equal inputs double correctly.
    return PublicKey.combine_keys([_pub(P1), _pub(P2)]).point()


def point_mul(P: Optional[Point], d: int) -> Optional[Point]:
    if P is None:
        return None
    k = d % N
    if k == 0:
        return None
    return _pub(P).multiply(k.to_bytes(32, "big")).point()
