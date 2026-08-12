"""Validate curve_native (coincurve) against curve (pure Python) before swapping.

Run on a machine with coincurve + libsecp256k1 installed:

    cd helpers && python _curve_equivalence_check.py

Asserts curve_native produces byte-for-byte identical output to the pure-Python
curve across random vectors, then benchmarks the speedup. "OK" = safe drop-in;
any MISMATCH = DO NOT SWAP (it would change derived addresses/keys).

Note: the pure-Python point_mul is very slow (~tens of ms each), so the slow
reference is only exercised a small number of times. Random points are
generated with the fast coincurve path; their correctness is covered separately
by the pubkey_gen check.
"""
import secrets
import sys
import time

try:
    import curve as ref
    import curve_native as nat
except ImportError:  # python -m helpers._curve_equivalence_check
    from . import curve as ref
    from . import curve_native as nat

N = nat.N
SLOW = 60    # rounds that invoke the slow pure-Python point_mul
FAST = 400   # rounds that only use fast ops (point_add / serP)


def rand_scalar() -> int:
    return secrets.randbelow(N - 1) + 1


def rand_point():
    # Fast point generation (coincurve). Correctness of this path is asserted by
    # the pubkey_gen check below, so it's safe to use it to build test inputs.
    return nat.pubkey_point_gen_from_int(rand_scalar())


def neg(P):
    return (P[0], (ref.p - P[1]) % ref.p)


def check(name, a, b):
    if a != b:
        raise AssertionError(f"MISMATCH in {name}:\n  ref   = {a}\n  native= {b}")


def phase(msg):
    print(msg, end=" ", flush=True)


def main() -> None:
    print(f"Running equivalence check (SLOW={SLOW}, FAST={FAST})...\n")

    phase("pubkey_gen...")
    for _ in range(SLOW):
        s = rand_scalar()
        check("pubkey_gen",
              ref.pubkey_point_gen_from_int(s),
              nat.pubkey_point_gen_from_int(s))
    print("ok")

    phase("point_add (add/double/inverse)...")
    for _ in range(FAST):
        P, Q = rand_point(), rand_point()
        check("add", ref.point_add(P, Q), nat.point_add(P, Q))
        check("double", ref.point_add(P, P), nat.point_add(P, P))
        check("inverse", ref.point_add(P, neg(P)), nat.point_add(P, neg(P)))
    print("ok")

    phase("point_mul...")
    for _ in range(SLOW):
        P, d = rand_point(), rand_scalar()
        check("mul", ref.point_mul(P, d), nat.point_mul(P, d))
    print("ok")

    phase("serP...")
    for _ in range(FAST):
        P = rand_point()
        check("serP", ref.serP(P), nat.serP(P))
    print("ok")

    print("\nOK: all vectors match — curve_native is a byte-for-byte drop-in.\n")

    # Benchmark the scan hot-path op (scalar * point).
    pts = [rand_point() for _ in range(SLOW)]
    scs = [rand_scalar() for _ in range(SLOW)]
    t0 = time.perf_counter()
    for P, d in zip(pts, scs):
        ref.point_mul(P, d)
    t1 = time.perf_counter()
    for P, d in zip(pts, scs):
        nat.point_mul(P, d)
    t2 = time.perf_counter()
    pure, native = t1 - t0, t2 - t1
    speedup = pure / native if native else float("inf")
    print(f"point_mul x{SLOW}: pure-Python {pure:.3f}s | coincurve {native:.4f}s "
          f"| {speedup:.0f}x faster")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print("\nFAILED — do NOT swap:\n" + str(e))
        sys.exit(1)
