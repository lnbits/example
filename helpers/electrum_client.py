"""
Stage 0 spike: prove siLNt's backend can talk to a Fulcrum/Electrum server and
fetch correct UTXO/balance data for a known address.

Self-contained. No siLNt/LNbits imports, no DB, no xpub chains. Just connectivity
+ the Electrum line protocol + correct scripthash computation.

Run:
    python electrum_client.py <host> <port> <bech32_address> [--tls]

Examples:
    python electrum_client.py 192.0.2.10 50001 tb1q...           # plain TCP
    python electrum_client.py fulcrum.example.net 50002 tb1q... --tls

What it does:
    1. Opens a TCP (or TLS) socket to host:port.
    2. server.version handshake (newline-delimited JSON-RPC).
    3. Computes the Electrum "scripthash" for the given P2WPKH (bech32 bc1q/tb1q)
       address: scriptPubKey -> sha256 -> REVERSE bytes -> hex.
    4. Calls blockchain.scripthash.get_balance and .listunspent.
    5. Prints balance + UTXOs so you can eyeball against an explorer.

If this prints the right balance/UTXOs for a known signet address, the entire
PayJoin feature is de-risked — everything downstream is conventional.

NOTE (production, not this spike): plain TCP over the internet leaks which
scripthashes you query to any on-path observer. Use TLS (:50002) or a tunnel
(WireGuard/Tailscale/SSH) in production. This client supports TLS via --tls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import ssl
import sys


# ── bech32 / segwit decode (BIP-173) — minimal, vendored to stay standalone ───
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_verify_checksum(hrp: str, data: list[int]) -> str | None:
    """Return 'bech32' or 'bech32m' depending on which checksum validates."""
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if const == 1:
        return "bech32"
    if const == 0x2BC830A3:
        return "bech32m"
    return None


def _bech32_decode(addr: str) -> tuple[str | None, list[int] | None, str | None]:
    if any(ord(c) < 33 or ord(c) > 126 for c in addr):
        return None, None, None
    if addr.lower() != addr and addr.upper() != addr:
        return None, None, None
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        return None, None, None
    hrp = addr[:pos]
    if any(c not in CHARSET for c in addr[pos + 1:]):
        return None, None, None
    data = [CHARSET.find(c) for c in addr[pos + 1:]]
    spec = _bech32_verify_checksum(hrp, data)
    if spec is None:
        return None, None, None
    return hrp, data[:-6], spec


def _convertbits(data: list[int], frombits: int, tobits: int, pad: bool = True) -> list[int] | None:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def address_to_scriptpubkey(addr: str) -> bytes:
    """
    Convert a segwit bech32/bech32m address to its scriptPubKey bytes.
    Supports v0 P2WPKH (20-byte) / P2WSH (32-byte) and v1 P2TR (32-byte).
    For this spike we mainly care about P2WPKH (BIP-84, bc1q/tb1q).
    """
    hrp, data, spec = _bech32_decode(addr)
    if hrp is None or data is None:
        raise ValueError(f"Not a valid bech32 address: {addr}")
    if hrp not in ("bc", "tb", "bcrt"):
        raise ValueError(f"Unexpected HRP {hrp!r} (expected bc/tb/bcrt)")
    witver = data[0]
    prog = _convertbits(data[1:], 5, 8, False)
    if prog is None:
        raise ValueError("Invalid witness program padding")
    prog = bytes(prog)
    # checksum spec must match version: v0 -> bech32, v1+ -> bech32m
    if witver == 0 and spec != "bech32":
        raise ValueError("v0 address must use bech32 checksum")
    if witver >= 1 and spec != "bech32m":
        raise ValueError("v1+ address must use bech32m checksum")
    if witver == 0:
        if len(prog) == 20:
            return bytes([0x00, 0x14]) + prog          # P2WPKH
        if len(prog) == 32:
            return bytes([0x00, 0x20]) + prog          # P2WSH
        raise ValueError(f"Invalid v0 program length {len(prog)}")
    if witver == 1 and len(prog) == 32:
        return bytes([0x51, 0x20]) + prog              # P2TR
    raise ValueError(f"Unsupported witver/len: v{witver}/{len(prog)}")


def electrum_scripthash(addr: str) -> str:
    """
    Electrum scripthash = sha256(scriptPubKey), BYTE-REVERSED, hex.
    The reversal is the classic gotcha — Electrum uses little-endian here.
    """
    spk = address_to_scriptpubkey(addr)
    h = hashlib.sha256(spk).digest()
    return h[::-1].hex()


# ── minimal Electrum JSON-RPC line client ─────────────────────────────────────
class ElectrumClient:
    def __init__(self, host: str, port: int, use_tls: bool = False, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._buf = b""
        self._id = 0

    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_tls:
            # Fulcrum's self-signed cert is common; for a spike we don't verify.
            # In production, pin/verify the cert or tunnel instead.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=self.host)
        raw.settimeout(self.timeout)
        self._sock = raw

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def _call(self, method: str, params: list) -> dict:
        assert self._sock is not None, "not connected"
        self._id += 1
        req = {"id": self._id, "method": method, "params": params}
        self._sock.sendall((json.dumps(req) + "\n").encode())
        # read until we get a full line containing our id
        while True:
            if b"\n" in self._buf:
                line, self._buf = self._buf.split(b"\n", 1)
                if not line.strip():
                    continue
                msg = json.loads(line.decode())
                if msg.get("id") == self._id:
                    return msg
                # ignore notifications / other ids in this simple spike
                continue
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("server closed connection")
            self._buf += chunk

    def server_version(self) -> list:
        r = self._call("server.version", ["siLNt-spike", "1.4"])
        if "error" in r and r["error"]:
            raise RuntimeError(f"server.version error: {r['error']}")
        return r.get("result")

    def get_balance(self, scripthash: str) -> dict:
        r = self._call("blockchain.scripthash.get_balance", [scripthash])
        if "error" in r and r["error"]:
            raise RuntimeError(f"get_balance error: {r['error']}")
        return r.get("result", {})

    def list_unspent(self, scripthash: str) -> list:
        r = self._call("blockchain.scripthash.listunspent", [scripthash])
        if "error" in r and r["error"]:
            raise RuntimeError(f"listunspent error: {r['error']}")
        return r.get("result", [])

    def broadcast(self, tx_hex: str) -> str:
        """blockchain.transaction.broadcast -> returns txid (or raises with the
        node's reject reason, e.g. 'witness program hash mismatch')."""
        r = self._call("blockchain.transaction.broadcast", [tx_hex])
        if "error" in r and r["error"]:
            raise RuntimeError(f"broadcast rejected: {r['error']}")
        return r.get("result", "")

    def get_transaction(self, txid: str, verbose: bool = True) -> dict:
        r = self._call("blockchain.transaction.get", [txid, verbose])
        if "error" in r and r["error"]:
            raise RuntimeError(f"get tx error: {r['error']}")
        return r.get("result", {})

    def server_height(self) -> int:
        """Current chain tip height as Fulcrum sees it (blockchain.headers.subscribe
        returns the tip header with its height). Used for health/sync checks."""
        r = self._call("blockchain.headers.subscribe", [])
        if "error" in r and r["error"]:
            raise RuntimeError(f"headers.subscribe error: {r['error']}")
        res = r.get("result", {})
        # result is {height, hex} for the current tip
        return int(res.get("height", 0))
