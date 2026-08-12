from typing import Optional, List
from fastapi import Query
from pydantic import BaseModel, Field
from datetime import datetime
import re

USERNAME_PATTERN = re.compile(r"^[a-z0-9_\-]{3,20}$")
RESERVED_USERNAMES = {
    "admin", "administrator", "root", "support", "help", "info", "abuse",
    "postmaster", "webmaster", "system", "anthropic", "claude", "bot",
    "moderator", "mod", "service", "noreply", "no-reply", "test", "demo",
}
REQUEST_COOLDOWN_SECONDS = 24 * 3600
RECENT_REJECT_COOLDOWN   = 24 * 3600

class CreateWallet(BaseModel):
    title:       str
    network:     str = "mainnet"
    hr_address:  Optional[str] = None    
    mnemonic:    Optional[str] = None    
    passphrase:  Optional[str] = None    
    last_height: Optional[int] = None

class BackendConfig(BaseModel):
    blindbit_url: str = ""
    mempool_url: str = "https://mempool.space"
    min_scan_height:  int = 0   # 0 = no minimum; e.g. 840000 = no scans before block 840000
    max_wallets_per_user: int = 1   # 0 = unlimited
    dust_threshold_sats:    int = 5000
    boltz_url: str = ""
    fulcrum_host: str = ""
    fulcrum_port: int = 50001
    fulcrum_tls: bool = False
    login_scan_enabled: bool = True            # auto catch-up scan on wallet open
    login_scan_auto_threshold: int = 432       # gap < this => scan silently; >= => prompt

class CreateWallet(BaseModel):
    mnemonic: str = None
    title: str = None
    network: str = "mainnet"
    passphrase: Optional[str] = ""
    hr_address: Optional[str] = None
    last_height: str = None
    balance: Optional[int] = None
    # Client-derived Silent Payments address. When present, the client generated
    # the seed and derived keys on-device (server never sees the mnemonic), so the
    # server stores this address as-is and skips server-side generation/derivation.
    sp_address: Optional[str] = None


class WalletAccount(BaseModel):
    id: str
    user: str
    title: str
    balance: int
    network: str = "mainnet"
    sp_address: str
    hr_address: str
    last_height: int
    # 0 = never scanned (matches the DB column default in migrations.py). Was 1,
    # which made a freshly-created wallet report "scanned to block 1".
    last_scan_height: int = 0


class UTXORecord(BaseModel):
    txid: str
    vout: int
    amount: int
    priv_key_tweak: str
    pub_key: str
    utxo_state: str
    timestamp: int
    wallet_id: str
    label: Optional[str] = None # individual utxo user created label
    label_index: Optional[int] = None  # None = main wallet, int = subaccount
    frozen: bool = False
    freeze_reason: Optional[str]
    suspected_dust: bool = False


class ScanWalletRequest(BaseModel):
    from_height: Optional[int] = None
    to_height: Optional[int] = None
    scan_secret: str
    spend_key: str


class UtxoForTx(BaseModel):
    txid: str
    vout: int = 0
    amount: int
    priv_key_tweak: str
    pub_key: str
    label: Optional[str] = None

class BuildTxRequest(BaseModel):
    wallet_id: str
    recipient: str
    amount: int
    fee_rate: float = 1
    memo: str = ""
    utxos: list[dict]
    spend_key: str
    scan_secret:  str 


class RecoverKeysRequest(BaseModel):
    mnemonic:    str          # encrypted (AES-encrypted with last_height as key)
    last_height: int          # encryption key + birth height
    passphrase:  Optional[str] = None   # NEW: BIP-39 passphrase (plaintext)
    
class Config(BaseModel):
    sats_denominated: bool = True
    network: str = "mainnet"


class WalletAddress(BaseModel):
    id: str
    wallet_id: str
    sp_address: str
    label_index: int
    hr_address: Optional[str] = None
    created_at: int = 0


class PreviewAddressRequest(BaseModel):    
    scan_secret: str
    spend_key: str
    label_index: Optional[int] = None   # auto-picked if None


class SaveAddressRequest(BaseModel):
    sp_address: str
    label: Optional[str] = None
    label_index: Optional[int] = None


class CloudflareConfig(BaseModel):
    api_token: str = ""
    zone_id: str = ""
    domain: str = ""


class NtfyConfig(BaseModel):
    enabled: bool = False
    server_url: str = "https://ntfy.bitaurus.net"   # base URL of the ntfy server
    topics: List[str] = []                # one or more topics to publish to
    access_token: str = ""                # optional bearer token for protected topics
    username: str = ""                    # HTTP Basic auth username (self-hosted servers)
    password: str = ""                    # HTTP Basic auth password
    priority: str = "default"             # ntfy priority: min|low|default|high|urgent


class SetupBip353Request(BaseModel):
    username: str  # e.g. "alice" → alice@yourdomain.com
    ttl: int = 300  # DNS TTL in seconds

class ForgotPasswordRequest(BaseModel):
    email: str

class InviteRequest(BaseModel):
    email: str

class UpdateUtxoLabel(BaseModel):
    label: str = ''
    wallet_id: str
    vout: Optional[int] = None

class UpdateUtxoFrozenRequest(BaseModel):
    frozen: bool

class UpdateAddressLabelRequest(BaseModel):
    label: Optional[str] = None

class TrustedDevice(BaseModel):
    id:            str
    user_id:       str
    device_id:     str
    user_agent:    Optional[str] = None
    ip:            Optional[str] = None
    label:         Optional[str] = None
    confirmed_at:  int
    last_seen_at:  int

class DeviceVerifyCodeRequest(BaseModel):
    code: str

class DeviceCheckResponse(BaseModel):
    status:        str             # 'trusted' | 'pending'
    device_count:  int
    cap:           int


class DeviceConfirmResponse(BaseModel):
    confirmed:    bool
    device_count: int
    cap:          int
    device_id:    str | None = None

class DeviceListResponse(BaseModel):
    devices:        List[TrustedDevice]
    current_device: Optional[str] = None
    cap:            int

class WhoamiResponse(BaseModel):
    user_id:   str
    username:  Optional[str] = None
    email:     Optional[str] = None
    is_admin:  bool

class UserPrefs(BaseModel):
    user_id:             str
    dust_threshold_sats: Optional[int] = None
    updated_at:          int

class UpdateUserPrefsRequest(BaseModel):
    dust_threshold_sats: Optional[int] = None    # None = revert to admin default

class Bip353Request(BaseModel):
    id:                 str
    user_id:            str
    wallet_id:          str
    sp_address:         str
    requested_username: str
    address_id:     Optional[str] = None
    final_username:     Optional[str] = None
    message:            Optional[str] = None
    status:             str   # 'pending' | 'approved' | 'rejected' | 'cancelled'
    reject_reason:      Optional[str] = None
    created_at:         int
    processed_at:       Optional[int] = None
    processed_by:       Optional[str] = None


class CreateBip353Request(BaseModel):
    wallet_id:          str
    requested_username: str
    address_id:         Optional[str] = None   # NULL = wallet base SP address
    message:            Optional[str] = Field(default=None, max_length=500)

class ApproveBip353Request(BaseModel):
    final_username: Optional[str] = None    # admin may tweak the requested name

class RejectBip353Request(BaseModel):
    reason: str = Field(..., max_length=500)

class BroadcastOutpoint(BaseModel):
    txid: str
    vout: int

class BroadcastTxRequest(BaseModel):
    tx_hex:          str
    wallet_id:       str
    # full outpoints of the inputs this tx spends
    spent_outpoints: List[BroadcastOutpoint] = []
    # optional metadata for richer Activity display before rescan
    recipient:       Optional[str] = None
    amount:          Optional[int] = None
    fee:             Optional[int] = None
    # backward-compat: older clients may still send spent_txids
    spent_txids:     Optional[List[str]] = None

class RestoreUtxoRequest(BaseModel):
    wallet_id: str
    txid: str
    vout: int
    
# ── Models ────────────────────────────────────────────────────────────────────
class CreateSwapInRequest(BaseModel):
    wallet_id: str          # LNbits wallet to receive the Lightning payment
    amount: int             # sats to receive on Lightning
    refund_address: str                  # on-chain (non-SP) address to refund to on failure
    silnt_wallet_id: Optional[str] = None  # SP wallet funding the swap (for ownership/listing)
    network: str


class SwapInResponse(BaseModel):
    swap_id: str
    address: str            # on-chain lockup address to pay
    expected_amount: int    # exact sats to send on-chain (incl. Boltz fees)
    timeout_block_height: Optional[int] = None

class BoltzSwapRecord(BaseModel):
    id: str
    wallet_id: str                       # LNbits wallet (receives LN)
    silnt_wallet_id: Optional[str] = None
    network: Optional[str] = None
    status: str = "created"              # created|funded|failed|refunded|completed
    # refund material:
    refund_privkey: str                  # hex — SENSITIVE
    refund_public_key: str               # hex (what we sent to Boltz)
    claim_public_key: str                # hex (Boltz's key from create response)
    swap_tree: dict                      # the swapTree Boltz returned (JSON)
    timeout_block_height: Optional[int] = None
    # lockup output to refund (filled once the on-chain lockup is observed):
    lockup_txid: Optional[str] = None
    lockup_vout: Optional[int] = None
    lockup_value: Optional[int] = None
    # bookkeeping:
    address: Optional[str] = None        # Boltz lockup address
    expected_amount: Optional[int] = None
    invoice: Optional[str] = None
    payment_hash: Optional[str] = None
    refund_address: Optional[str] = None # where the refund should go (user's on-chain addr)

class RefundRequest(BaseModel):
    address: Optional[str] = None   # if omitted, use the address stored at create
    fee_sats: int = 300

class FundedRequest(BaseModel):
    lockup_txid: str         # the SP-send tx that paid the Boltz lockup address

class PayjoinDescriptor(BaseModel):
    id: str
    user_id: str
    label: Optional[str] = None
    descriptor: str            # raw output descriptor (encrypted at rest)
    xpub: str                  # parsed account xpub (encrypted at rest)
    xpub_sha256: Optional[str] = None   # non-reversible dedup tag
    master_fp: str             # 8 hex chars
    account_path: str          # e.g. "84h/1h/0h"
    script_type: str = "wpkh"
    network: str
    last_sync_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


class PayjoinRequest(BaseModel):
    id: str
    status: str = "PROPOSED"
    sender_user_id: str
    sender_username: str
    receiver_user_id: Optional[str] = None
    receiver_username: str
    sender_descriptor_id: str
    receiver_descriptor_id: Optional[str] = None
    amount_sats: int
    fee_rate: float
    payment_address: str
    receiver_input_sats: Optional[int] = None
    fee_sats: Optional[int] = None
    psbt: Optional[str] = None
    unsigned_psbt: Optional[str] = None
    receiver_signed_psbt: Optional[str] = None
    sender_signed_psbt: Optional[str] = None
    memo: Optional[str] = None
    tx_hex: Optional[str] = None
    txid: Optional[str] = None
    sender_inputs: Optional[str] = None     # JSON string
    receiver_input: Optional[str] = None    # JSON string
    reject_reason: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    expires_at: Optional[int] = None


# ── request bodies (FastAPI) ──────────────────────────────────────────────────
class ImportDescriptorData(BaseModel):
    descriptor: str
    label: Optional[str] = None
    network: str = "signet"


class ProposePayjoinData(BaseModel):
    sender_descriptor_id: str
    receiver_username: str
    amount_sats: int
    fee_rate: float
    # sender's selected input outpoints to spend (from their synced UTXOs):
    sender_inputs: list[dict]   # [{txid, vout, value, chain, index}, ...]

class AcceptPayjoinData(BaseModel):
    receiver_descriptor_id: str
    # the receiver's chosen contributed input:
    receiver_input: dict 

class ContributePayjoinData(BaseModel):
    receiver_descriptor_id: str
    # the receiver's chosen contributed input:
    receiver_input: dict        # {txid, vout, value, chain, index}
    # receiver's signed copy of the final unsigned PSBT (base64):
    signed_psbt: str


class FinalizePayjoinData(BaseModel):
    # sender's signed copy of the final unsigned PSBT (base64):
    signed_psbt: str

# ── invoice model (payee-initiated, directed PayJoin) ─────────────────────────
class CreateInvoiceData(BaseModel):
    # A (payee) creates a directed invoice for a specific payer B.
    receiver_descriptor_id: str       # A's wallet that receives the payment
    receiver_input: dict              # A's ONE contributed input {txid,vout,value,chain,index}
    payer_username: str               # B, chosen from the dropdown
    amount_sats: int                  # what B owes A
    fee_rate: float
    memo: Optional[str] = None


class PayInvoiceData(BaseModel):
    # B (payer) pays an invoice: commits their wallet + inputs. siLNt then builds
    # the merged PSBT. No signature yet — both sign the returned unsigned PSBT.
    sender_descriptor_id: str         # B's wallet to spend from
    sender_inputs: list[dict]         # B's selected inputs


class SignPayjoinData(BaseModel):
    # either party submits their signed copy of the pristine unsigned PSBT;
    # siLNt combines + broadcasts once BOTH are present (order-independent).
    signed_psbt: str


# ── connections (consent-based curated payer/payee list) ──────────────────────
class PayjoinContact(BaseModel):
    id: str
    status: str
    requester_user_id: str
    target_user_id: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class CreateContactData(BaseModel):
    username: str


class ContactLabelData(BaseModel):
    label: str = ""   # private label for a connection (blank clears it)


class SpContact(BaseModel):
    id: str
    user_id: str
    network: str = "mainnet"       # address book is per-network
    label: str
    kind: str                      # 'bitmail' | 'sp'
    value: str                     # recipient (bitmail name or sp address); decrypted on read
    value_sha256: Optional[str] = None
    created_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None


class CreateSpContactData(BaseModel):
    label: str
    value: str                     # 'name@domain' or 'sp1...'/'tsp1...'


class UpdateSpContactData(BaseModel):
    label: str


class BackgroundScanData(BaseModel):
    # The wallet's scan PRIVATE key (hex). Uploaded to opt a wallet into
    # server-side background scanning. Detection-only — never the spend key.
    scan_secret: str


class FcmTokenData(BaseModel):
    token: str  # Firebase Cloud Messaging device token


class AdminDeleteAccountData(BaseModel):
    identifier: str            # username or email of the account to delete
    confirm_username: str      # must match the resolved username (typed confirmation)
    delete_bitmail: bool = True

class AdminAlert(BaseModel):
    id:           str
    kind:         str
    severity:     str = "warning"
    title:        str
    detail:       str = ""
    meta:         Optional[str] = None
    acknowledged: bool = False
    created_at:   int