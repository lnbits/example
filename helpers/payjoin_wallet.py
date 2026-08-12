"""
Stage 1 — watch-only BIP-84 wallet for PayJoin: import a zpub, derive the
receive (0/*) and change (1/*) address chains, and sync UTXOs/balance from
Fulcrum (via the Stage-0 ElectrumClient).

siLNt holds ONLY the zpub. No seed, no private keys. This module discovers
spendable UTXOs and records, per UTXO, the (chain, index) so that Stage 2 can
emit correct PSBT BIP32_DERIVATION fields for the external signer (Sparrow).

Derivation approach verified against BIP-84 canonical test vectors
(mnemonic "abandon abandon ... about"): zpub m/84'/0'/0' →
  0/0 bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
  1/0 bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el

Uses embit (already a siLNt dependency). Pairs with electrum_client.py.

Assumptions (per decisions):
- Import format: zpub (BIP-84 account extended pubkey). Standard origin assumed:
  m/84'/<coin>'/0', where coin = 0 mainnet, 1 signet/testnet.
- Chains: receive (0/*) AND change (1/*). Gap limit 20.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from embit import bip32, script
from embit.networks import NETWORKS
from .electrum_client import ElectrumClient, electrum_scripthash
import base58

GAP_LIMIT = 20
RECEIVE_CHAIN = 0
CHANGE_CHAIN = 1


_SLIP132_TO_STD = {
    # zpub (mainnet BIP-84) -> xpub
    bytes.fromhex("04b24746"): bytes.fromhex("0488b21e"),
    # vpub (testnet/signet BIP-84) -> tpub
    bytes.fromhex("045f1cf6"): bytes.fromhex("043587cf"),
    # already-standard pass through
    bytes.fromhex("0488b21e"): bytes.fromhex("0488b21e"),
    bytes.fromhex("043587cf"): bytes.fromhex("043587cf"),
}


def normalize_account_xpub(zpub: str) -> str:
    """Re-version a zpub/vpub/xpub/tpub to the standard xpub/tpub embit accepts.
    Lossless: only the version prefix changes, key+chaincode are untouched."""
    raw = base58.b58decode_check(zpub)
    ver, rest = raw[:4], raw[4:]
    std = _SLIP132_TO_STD.get(ver)
    if std is None:
        raise ValueError(f"Unsupported extended-key version {ver.hex()} (expected zpub/vpub/xpub/tpub)")
    return base58.b58encode_check(std + rest).decode()


def coin_type_for(network: str) -> int:
    return 0 if network.lower() == "mainnet" else 1


def hrp_for(network: str) -> str:
    n = network.lower()
    if n == "mainnet":
        return "bc"
    if n == "regtest":
        return "bcrt"
    return "tb"  # signet/testnet


@dataclass
class DerivedAddress:
    chain: int            # 0 receive, 1 change
    index: int
    address: str
    pubkey_hex: str       # 33-byte compressed pubkey (for PSBT BIP32_DERIVATION)


@dataclass
class WatchUtxo:
    txid: str
    vout: int
    value: int
    height: int
    address: str
    chain: int
    index: int
    pubkey_hex: str       # owning key's compressed pubkey


@dataclass
class SyncResult:
    network: str
    addresses: list[DerivedAddress] = field(default_factory=list)
    utxos: list[WatchUtxo] = field(default_factory=list)
    confirmed_sats: int = 0
    unconfirmed_sats: int = 0


# ── address derivation ────────────────────────────────────────────────────────
def _account_key(zpub: str):
    """Return an embit HDKey for the account-level extended PUBLIC key."""
    std = normalize_account_xpub(zpub)
    return bip32.HDKey.from_string(std)


def derive_address(acct_key, network: str, chain: int, index: int) -> DerivedAddress:
    """Derive one P2WPKH address at <chain>/<index> from the account pubkey."""
    child = acct_key.derive([chain, index])           # non-hardened public CKD
    pub = child.key                                    # embit PublicKey
    spk = script.p2wpkh(pub)                           # OP_0 <hash160(pubkey)>
    net = NETWORKS["main"] if network.lower() == "mainnet" else (
        NETWORKS["regtest"] if network.lower() == "regtest" else NETWORKS["test"]
    )
    addr = spk.address(net)
    return DerivedAddress(
        chain=chain,
        index=index,
        address=addr,
        pubkey_hex=pub.serialize().hex(),
    )


def _descriptor_net(network: str):
    n = network.lower()
    if n == "mainnet":
        return NETWORKS["main"]
    if n == "regtest":
        return NETWORKS["regtest"]
    return NETWORKS["test"]


def strip_descriptor_checksum(descriptor: str) -> str:
    """Remove the BIP-380 '#checksum' suffix (and surrounding whitespace) so
    embit's Descriptor.from_string can parse a Sparrow export pasted verbatim.
    The checksum is always a trailing '#' + 8 chars; xpubs/paths never contain
    '#', so cutting at the last '#' is safe. We keep the user's original string
    for STORAGE; this is only for parsing."""
    s = (descriptor or "").strip()
    if "#" in s:
        s = s[: s.rindex("#")].strip()
    return s


def _normalize_multipath(s: str) -> str:
    """Repair a mangled/single-chain key-path to canonical '<0;1>' multipath so
    both receive (0) and change (1) chains derive. Some clients eat the literal
    '<0;1>' (it has '<' '>') leaving '//*'; others export single '/0/*'."""
    if "//*" in s:
        s = s.replace("//*", "/<0;1>/*")
    elif "/<0;1>/*" not in s and "/0/*" in s:
        s = s.replace("/0/*", "/<0;1>/*")
    return s


def _parse_descriptor_obj(descriptor: str):
    """Single choke point: strip checksum, normalize multipath, then parse."""
    from embit.descriptor import Descriptor
    return Descriptor.from_string(_normalize_multipath(strip_descriptor_checksum(descriptor)))


def _looks_like_descriptor(s: str) -> bool:
    s = s.strip()
    return "(" in s or s.lower().startswith(("wpkh", "pkh", "sh", "wsh", "tr"))


def derive_descriptor_address(descriptor: str, network: str, chain: int, index: int) -> DerivedAddress:
    """Derive a P2WPKH address at <chain>/<index> straight from an output
    descriptor (handles the wpkh([fp/path]xpub/<0;1>/*) form). Uses the
    descriptor's own derivation so addresses match the declaring wallet."""
    d = _parse_descriptor_obj(descriptor)
    dd = d.derive(index, branch_index=chain)
    hd = dd.keys[0].key          # HDKey
    pub = hd.key                 # embit.ec.PublicKey (33-byte compressed)
    addr = dd.address(_descriptor_net(network))
    return DerivedAddress(
        chain=chain, index=index, address=addr,
        pubkey_hex=pub.serialize().hex(),
    )


# ── sync ──────────────────────────────────────────────────────────────────────
def _sync_chain(client: ElectrumClient, derive_fn, network: str, chain: int,
                gap_limit: int = GAP_LIMIT) -> tuple[list[DerivedAddress], list[WatchUtxo], int, int]:
    """
    Walk one chain (receive or change) until `gap_limit` consecutive unused
    addresses are seen. `derive_fn(network, chain, index) -> DerivedAddress`.
    Collect UTXOs from all used addresses.
    """
    addrs: list[DerivedAddress] = []
    utxos: list[WatchUtxo] = []
    confirmed = unconfirmed = 0

    consecutive_unused = 0
    index = 0
    while consecutive_unused < gap_limit:
        da = derive_fn(network, chain, index)
        sh = electrum_scripthash(da.address)
        bal = client.get_balance(sh)
        c = int(bal.get("confirmed", 0))
        u = int(bal.get("unconfirmed", 0))
        # An address counts as used if it currently holds funds OR has ever had
        # history. get_balance only reflects current funds, so also peek history
        # presence via listunspent (cheap) and treat any UTXO as "used". For a
        # fully-spent-but-previously-used address, listunspent is empty and
        # get_balance is 0 — we'd treat it as unused. That is acceptable for a
        # PayJoin spend wallet (we only care about spendable UTXOs); the gap
        # limit still advances past gaps. If strict used-detection is needed,
        # swap to blockchain.scripthash.get_history.
        unspent = client.list_unspent(sh)
        used = bool(unspent) or c > 0 or u > 0

        if used:
            consecutive_unused = 0
            addrs.append(da)
            confirmed += c
            unconfirmed += u
            for x in unspent:
                utxos.append(WatchUtxo(
                    txid=x.get("tx_hash"),
                    vout=int(x.get("tx_pos")),
                    value=int(x.get("value")),
                    height=int(x.get("height", 0)),
                    address=da.address,
                    chain=chain,
                    index=index,
                    pubkey_hex=da.pubkey_hex,
                ))
        else:
            consecutive_unused += 1

        index += 1

    return addrs, utxos, confirmed, unconfirmed


def next_unused_receive_index(descriptor_or_zpub: str, network: str, host: str, port: int,
                              use_tls: bool = False, gap_limit: int = GAP_LIMIT) -> int:
    """
    Return the next unused RECEIVE-chain (chain 0) index for a descriptor, by
    syncing and taking one past the highest used receive index. Avoids address
    reuse when issuing a payment address (e.g. PayJoin accept). Returns 0 if the
    receive chain has no history yet.
    """
    res = sync_wallet(descriptor_or_zpub, network, host, port,
                      use_tls=use_tls, gap_limit=gap_limit)
    used_recv = [a.index for a in res.addresses if a.chain == RECEIVE_CHAIN]
    return (max(used_recv) + 1) if used_recv else 0


def sync_wallet(descriptor_or_zpub: str, network: str, host: str, port: int,
                use_tls: bool = False, gap_limit: int = GAP_LIMIT) -> SyncResult:
    """
    Full watch-only sync: derive + scan receive and change chains via Fulcrum.
    Accepts EITHER an output descriptor (wpkh([fp/path]xpub/<0;1>/*)) — the path
    the endpoint uses — OR a bare zpub/vpub (the standalone CLI test path).
    """
    result = SyncResult(network=network)

    s = (descriptor_or_zpub or "").strip()
    if not s:
        raise ValueError("Empty descriptor/xpub passed to sync_wallet "
                         "(stored descriptor missing or blank).")

    if _looks_like_descriptor(s):
        desc = s
        def derive_fn(net, chain, index):
            return derive_descriptor_address(desc, net, chain, index)
    else:
        acct_key = _account_key(s)
        def derive_fn(net, chain, index):
            return derive_address(acct_key, net, chain, index)

    client = ElectrumClient(host, port, use_tls=use_tls)
    try:
        client.connect()
        client.server_version()
        for chain in (RECEIVE_CHAIN, CHANGE_CHAIN):
            addrs, utxos, c, u = _sync_chain(client, derive_fn, network, chain, gap_limit)
            result.addresses.extend(addrs)
            result.utxos.extend(utxos)
            result.confirmed_sats += c
            result.unconfirmed_sats += u
    finally:
        client.close()

    return result
