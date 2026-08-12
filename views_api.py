import asyncio
import json
from http import HTTPStatus
from base64 import b64encode
import httpx
import hashlib
import re
import secrets
import time
import time as _time
from .helpers.wallet import (
    generate_silent_wallet_address,
    decrypt_mnemonic,
    build_transaction,
    generate_labeled_sp_address,
    get_spend_pub_from_secret,
)
from .helpers.scan import (
    scan_wallet, get_scan_progress, request_scan_stop, get_tx_status,
    BIP352_LABELED_ADDRESS_INDICES,
)
from .helpers.address_resolver import bip353_resolve
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, Cookie
from lnbits.core.models import WalletTypeInfo
from lnbits.decorators import require_admin_key, require_invoice_key
from lnbits.helpers import urlsafe_short_hash
from lnbits.settings import settings as lnbits_settings
from loguru import logger
from typing import Optional
from .helpers.bip353_cloudflare import (
    create_bip353_record,
    get_zone_domain,
    delete_bip353_record,
    CloudflareError    
)
from .helpers.email_verification import (
    RegistrationRequest, VerifyRegistrationRequest,
    start_registration, complete_registration,
)
from mnemonic import Mnemonic
from .helpers.dust_check import evaluate_dust_for_wallet
from .helpers.scan_rate_limiter import check_scan_allowed, mark_scan_finished
from .helpers.invite_rate_limiter import check_invite_allowed, record_invite
from .helpers.forgot_password import request_password_reset
from .helpers.transactions import get_wallet_transaction_detail, list_wallet_transactions
from lnbits.core.crud import get_account, get_account_by_username, get_account_by_email
from lnbits.core.crud.users import delete_account
from lnbits.core.services.notifications import send_email_notification
from .helpers.device_auth import (
    require_trusted_device,
    require_trusted_device_admin,    
    set_device_cookie,
    clear_device_cookie,
    read_device_id,
    get_client_ip,
    cookie_name_for_user,    
    MAX_TRUSTED_DEVICES_PER_USER
)
from .helpers.user import is_lnbits_admin, require_admin, validate_born_height
from .helpers.scan import BlindBitOracleClient
from .helpers.fee_rates_backend import  get_recommended_fees, get_btc_usd_rate
from .helpers.payjoin_wallet import sync_wallet, next_unused_receive_index
from .helpers.payjoin_merge import build_merged_payjoin
from .helpers.psbt_combine import combine_and_finalize
from .helpers.electrum_client import ElectrumClient
from .crud import (
    get_silnt_wallets,
    create_silnt_wallet,
    delete_silnt_wallet,
    delete_utxos_for_wallet,
    get_sp_address,
    get_hr_address,
    update_hr_address,
    update_last_height,
    update_title,
    update_balance,
    get_silnt_wallet,
    get_backend_config,
    update_backend_config,
    get_utxos_for_wallet,
    insert_utxos_for_wallet,
    update_unconfirmed_utxo,
    save_wallet_address,
    get_wallet_addresses,
    count_wallet_addresses,
    insert_wallet_address,
    delete_wallet_label_address,
    delete_wallet_label_addresses,
    get_cloudflare_config,
    update_cloudflare_config,
    count_silnt_wallets,
    address_exists,
    update_utxo_label_by_txid,
    get_utxos_by_txid,
    get_next_label_index,
    label_index_taken,
    owner_check_dust,
    update_utxo_frozen,
    get_eligible_utxos,
    update_address_label,
    get_wallet_address,
    mark_utxos_spent_by_tx,
    set_utxo_freeze_manual,
    clear_utxo_freeze_manual,
    count_trusted_devices,
    list_trusted_devices,
    add_trusted_device,
    get_trusted_device,
    touch_trusted_device,
    revoke_trusted_device,
    revoke_all_other_devices,
    get_user_prefs,
    upsert_user_prefs,
    get_effective_dust_threshold,
    get_wallet_active_request,
    get_wallet_last_rejected_request,
    create_bip353_request,
    get_bip353_request,
    list_user_bip353_requests,
    list_pending_bip353_requests,
    is_username_taken,
    is_username_approved_elsewhere,
    sp_address_has_approved_bitmail,
    update_bip353_request_status,
    cancel_user_request,
    restore_utxo_to_unspent,
    get_wallet_unspent_balance,
    get_utxo,
    delete_all_silnt_data_for_user,
    get_user_hr_addresses,
    clear_wallet_hr_address,
    count_approved_bip353_for_wallet,
    address_has_approved_bitmail,
    update_label_hr_address,
    clear_label_hr_address,
    mark_utxos_confirmed_spent_by_tx,    
    cancel_pending_request_for_address,
    cancel_all_pending_requests_for_wallet,
    list_all_bip353_requests,
    delete_bip353_request_if_terminal,
    delete_terminal_bip353_requests,
    delete_bip353_requests_for_wallet,
    create_payjoin_descriptor,
    get_payjoin_descriptor,
    list_payjoin_descriptors,
    delete_payjoin_descriptor, 
    derive_descriptor_address,
    get_payjoin_request, 
    update_payjoin_request,
    list_silnt_user_ids_for_network,
    list_payjoin_requests_for_receiver, 
    list_payjoin_requests_for_sender,
    get_reserved_outpoints,
    create_payjoin_invoice, list_payjoin_invoices_for_payer,
    get_account_id_by_email,
    create_payjoin_contact,
    get_payjoin_contact,
    set_payjoin_contact_status,
    delete_payjoin_contact,
    list_payjoin_contacts,
    list_accepted_contact_user_ids,
    list_accepted_contacts_with_ids,
    set_payjoin_contact_label,
    get_payjoin_contact_labels,
    create_sp_contact,
    list_sp_contacts,
    update_sp_contact_label,
    delete_sp_contact,
    touch_sp_contact,
    list_silnt_user_ids,
    get_ntfy_config,
    update_ntfy_config,
    send_ntfy_notification,
    notify_service_health_change,
    create_admin_alert,
    list_admin_alerts,
    count_open_admin_alerts,
    acknowledge_admin_alert,
    delete_admin_alerts_for_wallet,
    get_issued_bitmail_sp_address,
    list_approved_bitmails,
    open_alert_exists_for,
    open_tamper_notified,
    mark_tamper_notified,
    resolve_open_alerts_for,
    tamper_signature_alerted,
    should_send_login_alert,
    create_device_code,
    verify_device_code,
    mark_self_revoke,
    in_self_revoke_grace,
    DEFAULT_CONFIG_NETWORK
)

from .models import (
    BackendConfig,
    CreateWallet,
    WalletAccount,
    BuildTxRequest,
    BroadcastTxRequest,
    Config,
    ScanWalletRequest,
    SaveAddressRequest,
    PreviewAddressRequest,
    CloudflareConfig,
    SetupBip353Request,
    RecoverKeysRequest,
    ForgotPasswordRequest,
    DeviceVerifyCodeRequest,
    UpdateUtxoLabel,
    UpdateUtxoFrozenRequest,
    UpdateAddressLabelRequest,
    TrustedDevice,
    DeviceCheckResponse,
    DeviceConfirmResponse,
    DeviceListResponse,
    WhoamiResponse,
    UserPrefs,
    UpdateUserPrefsRequest,
    CreateBip353Request,
    ApproveBip353Request,
    RejectBip353Request,
    RestoreUtxoRequest,
    InviteRequest,
    ImportDescriptorData,
    CreateInvoiceData,
    PayInvoiceData,
    SignPayjoinData,
    CreateContactData,
    ContactLabelData,
    CreateSpContactData,
    UpdateSpContactData,
    BackgroundScanData,
    FcmTokenData,
    AdminDeleteAccountData,
    NtfyConfig,
    USERNAME_PATTERN,
    RESERVED_USERNAMES,
    RECENT_REJECT_COOLDOWN,
)

# COUPLED to the always-scanned labeled indices in helpers/scan.py
# (BIP352_LABELED_ADDRESS_INDICES). get_next_label_index() hands out the lowest
# free index >= 2, and this cap stops new saves once that many labeled rows
# exist, so the highest index the server ever assigns is MAX_ADDRESSES_PER_WALLET
# + 1. Every index in 2..(cap+1) MUST be in BIP352_LABELED_ADDRESS_INDICES,
# because that set is scanned regardless of whether a saved-address row exists —
# which is exactly what keeps a *deleted* labeled address still detectable (its
# label stays in the scan set, so payments to it are still found and the row is
# re-created). Raise this cap and you MUST widen BIP352_LABELED_ADDRESS_INDICES
# to match (or switch scanning to a high-water mark); otherwise a deleted
# high-index labeled address would silently stop being detected. The assert below
# fails fast at import if the two ever drift apart.
MAX_ADDRESSES_PER_WALLET = 2
assert set(range(2, MAX_ADDRESSES_PER_WALLET + 2)) <= set(BIP352_LABELED_ADDRESS_INDICES), (
    "MAX_ADDRESSES_PER_WALLET outgrew the always-scanned labeled indices "
    "(BIP352_LABELED_ADDRESS_INDICES); a deleted labeled address at an unscanned "
    "index would stop being detected. Widen the scanned set or use a high-water mark."
)
BIP352_CHANGE_LABEL_INDEX = 0
BITMAIL_MAX_ACQUISITIONS = 3
BLINDBIT_SYNC_TOLERANCE = 2
FULCRUM_SYNC_TOLERANCE = 2

silnt_api_router = APIRouter()

_BITMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# ── Wallets ──────────────────────────────────────────────────────────────────


@silnt_api_router.get("/api/v1/wallet", status_code=HTTPStatus.OK)
async def api_wallets_retrieve(
    network: Optional[str] = Query(None),
    key_info: WalletTypeInfo = Depends(require_trusted_device),
) -> list[WalletAccount]:
    return await get_silnt_wallets(key_info.wallet.user, network)


@silnt_api_router.get(
    "/api/v1/wallet/{wallet_id}", dependencies=[Depends(require_trusted_device)]
)
async def api_wallet_retrieve(wallet_id: str) -> WalletAccount:
    silnt_wallet = await get_silnt_wallet(wallet_id)
    if not silnt_wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    return silnt_wallet


@silnt_api_router.post("/api/v1/wallet", status_code=HTTPStatus.OK)
async def api_wallet_create(
    data: CreateWallet, key_info: WalletTypeInfo = Depends(require_trusted_device)
) -> dict:
    try:
        wallet_id = urlsafe_short_hash()

        blindbit_cfg = await get_backend_config(data.network)
        min_height   = blindbit_cfg.min_scan_height or 0

        # ★ 1. Default last_height to oracle tip if not supplied
        last_height = data.last_height
        if last_height is None:
            try:
                oracle = BlindBitOracleClient(base_url=blindbit_cfg.blindbit_url)
                tip = await oracle.get_chain_tip()   # ← your existing tip helper
                last_height = int(tip) if tip else 0
            except Exception as e:
                logger.warning(f"Could not fetch oracle tip; defaulting to 0: {e}")
                last_height = 0
        else:
            last_height = int(data.last_height)

        # Clamp to configured minimum
        if min_height > 0 and last_height < min_height:
            # If the user explicitly entered a too-low height, error.
            # If we auto-defaulted to tip, tip is always >= min so no error.
            if data.last_height is not None:
                raise HTTPException(
                    status_code=HTTPStatus.BAD_REQUEST,
                    detail=(
                        f"Wallet birth height must be at least {min_height} on this server. "
                        f"You entered {data.last_height}."
                    ),
                )
            last_height = min_height

        # ★ 2. Generate or import + ★ 3. checksum validation
        #    data.mnemonic is encrypted (as before) when importing. Decrypt first,
        #    then validate/generate. If no mnemonic supplied → generate fresh.
        passphrase = (data.passphrase or "").strip()

        new_wallet = WalletAccount(
            id=wallet_id,
            user=key_info.wallet.user,
            title=data.title,
            balance=0,
            hr_address=data.hr_address or "",
            network=data.network,
            last_height=last_height,
            sp_address="",
            spend_key="",
            scan_secret="",
        )

        if data.sp_address:
            # Client-side derivation: the app generated the seed and derived the
            # keys on-device, so the server never sees the mnemonic or the private
            # keys. Trust the supplied address (self-custody) and skip derivation.
            sp_address = data.sp_address.strip()
            expected_prefix = "sp1" if data.network == "mainnet" else "tsp1"
            if not sp_address.startswith(expected_prefix):
                raise HTTPException(
                    status_code=HTTPStatus.BAD_REQUEST,
                    detail=f"sp_address must start with '{expected_prefix}' for {data.network}.",
                )
            # Never known to the server; the client stores its own keys/mnemonic.
            scan_secret_hex = ""
            spend_key_hex = ""
            mnemonic_plain = None
            was_generated = False
        else:
            # Legacy path: server generates (or imports) the seed and derives keys.
            # Kept for older clients and the web app until they move on-device too.
            mn = Mnemonic("english")
            if data.mnemonic:                      # ← only decrypt when present
                mnemonic_plain = decrypt_mnemonic(data.mnemonic, str(last_height))
                words = mnemonic_plain.strip().lower().split()
                if len(words) != 12:
                    raise HTTPException(status_code=HTTPStatus.BAD_REQUEST,
                        detail=f"Mnemonic must be exactly 12 words (got {len(words)}).")
                mnemonic_plain = " ".join(words)
                if not mn.check(mnemonic_plain):
                    raise HTTPException(status_code=HTTPStatus.BAD_REQUEST,
                        detail="Invalid mnemonic — the checksum (last word) is incorrect.")
                was_generated = False
            else:
                mnemonic_plain = mn.generate(strength=128)   # fresh 12 words
                was_generated = True

            (
                sp_address,
                scan_secret_hex,
                spend_key_hex,
            ) = await generate_silent_wallet_address(
                mnemonic_plain,
                passphrase=passphrase,
                network=data.network,
            )
            if not all([sp_address, scan_secret_hex, spend_key_hex]):
                raise ValueError(
                    f"Wallet '{data.title}' cannot be created with given mnemonic!"
                )

        _stable_seed = f"{data.network}:{sp_address}".encode()
        wallet_id = "sp" + hashlib.sha256(_stable_seed).hexdigest()[:20]
        new_wallet.id = wallet_id

        wallets = await get_silnt_wallets(key_info.wallet.user, data.network)
        if any(w.sp_address == sp_address for w in wallets):
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="Silent Payment Wallet already exists!",
            )

        # The limit is per-network: max_wallets_per_user comes from THIS network's
        # backend config, so count only the user's wallets on this network. A user
        # at the cap on signet can still create a wallet on mainnet.
        max_wallets = blindbit_cfg.max_wallets_per_user or 1
        if max_wallets > 0:
            current_count = await count_silnt_wallets(key_info.wallet.user, data.network)
            if current_count >= max_wallets:
                raise HTTPException(
                    status_code=HTTPStatus.BAD_REQUEST,
                    detail=(
                        f"Wallet limit reached. You can have at most {max_wallets} wallet"
                        f"{'s' if max_wallets != 1 else ''} on {data.network}. "
                        f"You currently have {current_count}."
                    ),
                )

        if data.hr_address:
            try:
                resolved = bip353_resolve(data.hr_address)
                result = resolved.get("result", "")
                result = result.replace("bitcoin:?sp=", "").replace("sp=", "").strip()
                if result.lower() != sp_address.lower():
                    raise HTTPException(
                        status_code=HTTPStatus.BAD_REQUEST,
                        detail="BIP353 address resolves to a different SP address than the wallet's.",
                    )
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(
                    status_code=HTTPStatus.BAD_REQUEST,
                    detail=f"BIP353 resolution failed for {data.hr_address}: {str(e)}",
                )

        new_wallet.sp_address = sp_address
        await create_silnt_wallet(new_wallet)

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)
        ) from exc

    return {
        "wallet_id":   wallet_id,
        "sp_address":  sp_address,
        "scan_secret": scan_secret_hex,   # client must store securely
        "spend_key":   spend_key_hex,     # client must store securely
        # ★ Return the mnemonic so the client can show it once (esp. on generate)
        "mnemonic":    mnemonic_plain,
        "passphrase":  passphrase if passphrase else None,
        "last_height": last_height,
        "network":     data.network,
        "generated":   was_generated,
    }


@silnt_api_router.put("/api/v1/wallet/{wallet_id}", status_code=HTTPStatus.OK)
async def api_wallet_update(
    wallet_id: str,
    data: CreateWallet,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
) -> dict:
    try:
        wallet = await get_silnt_wallet(wallet_id)
        if not wallet:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
            )
        if data.hr_address is not None and data.hr_address != wallet.hr_address:
            # Validate BIP353 resolves to this wallet's SP address
            try:
                resolved = bip353_resolve(data.hr_address)
                result = resolved.get("result", "")
                result = result.replace("bitcoin:?sp=", "").replace("sp=", "").strip()
                if result.lower() != wallet.sp_address.lower():
                    raise HTTPException(
                        status_code=HTTPStatus.BAD_REQUEST,
                        detail=f"BIP353 address resolves to a different SP address than this wallet's.",
                    )
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(
                    status_code=HTTPStatus.BAD_REQUEST,
                    detail=f"BIP353 resolution failed for {data.hr_address}: {str(e)}",
                )
            await update_hr_address(wallet.id, data.hr_address)
        if data.last_height is not None and int(data.last_height) != wallet.last_height:
            validated_height = await validate_born_height(data.last_height, wallet.network)
            if validated_height is not None:
                await update_last_height(wallet.id, int(data.last_height))
        if data.title is not None and data.title != wallet.title:
            await update_title(wallet.id, data.title)
        if data.balance is not None and data.balance != wallet.balance:
            await update_balance(wallet.id, data.balance)
    except Exception as exc:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)
        ) from exc
    return {}


@silnt_api_router.delete(
    "/api/v1/wallet/{wallet_id}", dependencies=[Depends(require_trusted_device)]
)
async def api_wallet_delete(wallet_id: str):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
     # Clean up BitMail state before wiping the wallet:
    # 1. Cancel all pending requests so none linger in the admin queue.
    try:
        await cancel_all_pending_requests_for_wallet(wallet_id)
    except Exception as e:
        logger.warning(f"Could not cancel pending requests for deleted wallet {wallet_id}: {e}")

    # 2. Remove DNS records for any live BitMails (base + labeled) on this wallet.
    cf = await get_cloudflare_config()
    if cf and getattr(cf, "api_token", "") and getattr(cf, "zone_id", ""):
        hrs = []
        if (wallet.hr_address or "").strip():
            hrs.append(wallet.hr_address.strip())
        try:
            for a in await get_wallet_addresses(wallet_id):
                ahr = (a.get("hr_address") if isinstance(a, dict) else getattr(a, "hr_address", None)) or ""
                if ahr.strip():
                    hrs.append(ahr.strip())
        except Exception as e:
            logger.warning(f"Could not enumerate labeled BitMails for {wallet_id}: {e}")
        for hr in hrs:
            if "@" in hr:
                try:
                    await delete_bip353_record(cf.api_token, cf.zone_id, cf.domain, hr.split("@", 1)[0])
                    logger.info(f"Removed BitMail DNS {hr} for deleted wallet {wallet_id}")
                except Exception as e:
                    logger.warning(f"Could not remove BitMail DNS {hr} for deleted wallet {wallet_id}: {e}")
    await delete_silnt_wallet(wallet_id)
    await delete_utxos_for_wallet(wallet_id)
    await delete_wallet_label_addresses(wallet_id)
    # Purge records that reference this wallet by id so nothing is left orphaned:
    # its BitMail requests (else the tamper sweep keeps checking a dead wallet and
    # list_approved_bitmails returns it forever) and any admin alerts raised for it.
    try:
        await delete_bip353_requests_for_wallet(wallet_id)
        await delete_admin_alerts_for_wallet(wallet_id)
    except Exception as e:
        logger.warning(f"post-delete cleanup (bip353/alerts) failed for {wallet_id}: {e}")
    return "", HTTPStatus.NO_CONTENT


@silnt_api_router.get("/api/v1/wallet/{wallet_id}/addresses")
async def api_get_wallet_addresses(
    wallet_id: str, key_info: WalletTypeInfo = Depends(require_trusted_device)
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")
    addresses = await get_wallet_addresses(wallet_id)
    return {"addresses": addresses, "max": MAX_ADDRESSES_PER_WALLET}


@silnt_api_router.post("/api/v1/wallet/{wallet_id}/addresses/preview")
async def api_preview_wallet_address(
    wallet_id: str,
    data: PreviewAddressRequest,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    label_index = data.label_index
    # Only honor an explicit index if it's a real, free labeled slot. Anything
    # else — None, a reserved index (0 change / 1 legacy change), one outside the
    # always-scanned range, or an already-taken slot — falls back to the next
    # free slot, so a previewed address can never land outside the scan set (see
    # the MAX_ADDRESSES_PER_WALLET / BIP352_LABELED_ADDRESS_INDICES coupling).
    if (
        label_index is None
        or label_index not in BIP352_LABELED_ADDRESS_INDICES
        or await label_index_taken(wallet_id, label_index)
    ):
        label_index = await get_next_label_index(wallet_id)
    spend_pub_hex = get_spend_pub_from_secret(data.spend_key)
    hrp = "sp" if wallet.network == "mainnet" else "tsp"

    try:
        sp_address = generate_labeled_sp_address(
            scan_secret_hex=data.scan_secret,
            spend_pub_hex=spend_pub_hex,
            m=label_index,
            hrp=hrp,
        )
    except Exception as e:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate address: {str(e)}",
        )
    return {
        "sp_address":  sp_address,
        "label_index": label_index,
    }


@silnt_api_router.delete("/api/v1/wallet/{wallet_id}/addresses/{address_id}")
async def api_delete_wallet_address(
    wallet_id: str,
    address_id: str,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")
    # Clean up this address's BitMail state before deleting the row, so we don't
    # (a) orphan a pending request in the admin queue, or (b) leave a live DNS
    # record bound to an address that no longer exists.
    addr = await get_wallet_address(address_id)

    # 1. Cancel any pending BitMail request for this address.
    try:
        await cancel_pending_request_for_address(wallet_id, address_id, sp_address=(getattr(addr, "sp_address", None) if addr else None))
    except Exception as e:
        logger.warning(f"Could not cancel pending request for deleted address {address_id}: {e}")

    # 2. If the address had an approved BitMail, remove its DNS record. The
    #    approved bip353_requests row is intentionally LEFT intact: it preserves
    #    the wallet's lifetime BitMail cap and keeps the username reserved.
    hr = (addr.hr_address or "").strip() if addr else ""
    if hr and "@" in hr:
        cf = await get_cloudflare_config()
        if cf and getattr(cf, "api_token", "") and getattr(cf, "zone_id", ""):
            try:
                await delete_bip353_record(cf.api_token, cf.zone_id, cf.domain, hr.split("@", 1)[0])
                logger.info(f"Removed BitMail DNS {hr} for deleted labeled address {address_id}")
            except Exception as e:
                logger.warning(f"Could not remove BitMail DNS for deleted address {address_id}: {e}")
    await delete_wallet_label_address(address_id, wallet_id)
    return "", HTTPStatus.NO_CONTENT


@silnt_api_router.post("/api/v1/wallet/{wallet_id}/addresses")
async def api_save_generated_wallet_address(
    wallet_id: str,
    data: SaveAddressRequest,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    count = await count_wallet_addresses(wallet_id)
    if count >= MAX_ADDRESSES_PER_WALLET:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Maximum of {MAX_ADDRESSES_PER_WALLET} addresses per wallet reached.",
        )
    if await address_exists(wallet_id, data.sp_address):
        raise HTTPException(
            status_code=HTTPStatus.CONFLICT,
            detail="This address is already saved on this wallet. Generate a new one.",
        )
    # Determine the label_index — trust server, not stale client state.
    label_index = data.label_index
    # A saved labeled address MUST land on an always-scanned index, or it would
    # silently stop being detected if later deleted (see the
    # MAX_ADDRESSES_PER_WALLET / BIP352_LABELED_ADDRESS_INDICES coupling). Unlike
    # preview, save can't regenerate the address (it has no keys) — the client's
    # sp_address is bound to its index — so an out-of-range/reserved explicit
    # index can't be safely remapped: reject it rather than persist a mismatched,
    # unscannable row.
    if label_index is not None and label_index not in BIP352_LABELED_ADDRESS_INDICES:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Invalid label index; regenerate the address and try again.",
        )
    # Auto-pick (None) or a race on an already-taken slot → next free in-range
    # slot. The cap check above guarantees a free scanned slot exists here.
    if label_index is None or await label_index_taken(wallet_id, label_index):
        label_index = await get_next_label_index(wallet_id)

    try:
        return await save_wallet_address(
            wallet_id   = wallet_id,
            sp_address  = data.sp_address,
            label       = data.label,
            label_index = label_index,
        )
    except Exception as e:
        logger.error(f"save_wallet_address failed: {e}")
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Could not save labeled address. Please contact your administrator.",
        )    


@silnt_api_router.get(
    "/api/v1/oracle/tip",
    dependencies=[Depends(require_trusted_device)],
)
async def api_get_chain_tip(network: Optional[str] = Query(None)):
    # No silent signet fallback: a client that omits `network` (e.g. a mainnet
    # build) would otherwise get signet's tip. Require it explicitly.
    if not network:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="A `network` query parameter is required (e.g. ?network=mainnet).",
        )
    blindbit = await get_backend_config(network)
    if not blindbit.blindbit_url:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="BlindBit Oracle URL not configured.",
        )
    headers = {}
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.get(
                f"{blindbit.blindbit_url.rstrip('/')}/info", headers=headers
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        raise HTTPException(
            status_code=HTTPStatus.BAD_GATEWAY,
            detail=f"Could not reach BlindBit Oracle: {str(e)}",
        )


# ── Backend config ───────────────────────────────────────────────────────────


@silnt_api_router.get("/api/v1/backend/config")
async def api_get_backend_config(
    network: Optional[str] = Query(None),
    key_info: WalletTypeInfo = Depends(require_trusted_device),
) -> BackendConfig:
    """Any authenticated user can read the blindbit endpoint (needed to trigger scan).
    Credentials (user/pass) are included so the scan proxy can use them server-side."""
    return await get_backend_config(network or DEFAULT_CONFIG_NETWORK)


@silnt_api_router.put("/api/v1/backend/config")
async def api_update_backend_config(
    data: BackendConfig,  network: Optional[str] = Query(None),
    key_info: WalletTypeInfo = Depends(require_trusted_device_admin)
) -> BackendConfig:
    require_admin(key_info)
    """Only admin can write blindbit connection settings."""
    return await update_backend_config(data, network or DEFAULT_CONFIG_NETWORK)


# ── Scanning ──────────────────────────────────────────────────────────────────


@silnt_api_router.get(
    "/api/v1/utxos",
    description="Fetch UTXOs from blindbit",
    dependencies=[Depends(require_trusted_device)],
)
async def api_get_utxos(
    wallet_id: str = Query(...), key_info: WalletTypeInfo = Depends(require_trusted_device)
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    utxos = await get_utxos_for_wallet(wallet_id)
    return {
        "utxos": [u.dict() for u in utxos],
    }


@silnt_api_router.post("/api/v1/wallet/{wallet_id}/scan")
async def api_scan_wallet(
    wallet_id: str,
    data: ScanWalletRequest,
    request: Request,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist.")
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    # Enforce min scan height
    blindbit = await get_backend_config(wallet.network)
    min_height = blindbit.min_scan_height or 0

    requested_from = data.from_height if data.from_height is not None else wallet.last_height
    if min_height > 0 and requested_from < min_height:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=(
                f"Scanning below block {min_height} is disabled on this server. "
                f"Requested start height was {requested_from}."
            ),
        )

    # Estimate block count for budget check
    # Use chain tip as fallback if to_height not given
    to_height_est = data.to_height
    if to_height_est is None:        
        oracle = BlindBitOracleClient(base_url=blindbit.blindbit_url)
        to_height_est = await oracle.get_chain_tip()
    estimated_blocks = max(1, to_height_est - requested_from)

    client_ip = request.client.host if request.client else "unknown"

    # Rate limit check (raises 429 if any limit exceeded)
    check_scan_allowed(
        user_id=key_info.wallet.user,
        wallet_id=wallet_id,
        ip=client_ip,
        estimated_blocks=estimated_blocks,
    )
    user_id = key_info.wallet.user

    async def _run_scan():
        result = None
        try:
            result = await scan_wallet(
                wallet_id=wallet_id,
                scan_secret_hex=data.scan_secret,
                spend_secret_hex=data.spend_key,
                from_height=data.from_height,
                to_height=data.to_height,
            )
            # Notify on any newly-found coins, not just when the background sweep
            # is the finder. Opening the app triggers this interactive scan, which
            # usually beats the 30-min sweep — so without this, an app-open find
            # would never notify. The client shows it as an in-app banner (app in
            # foreground) via the FCM onMessage handler.
            new_found = (result or {}).get("utxos_found", 0) if isinstance(result, dict) else 0
            if new_found > 0:
                await _notify_payment_found(wallet, new_found, (result or {}).get("amount_found"))
        except ValueError as e:
            logger.error(f"Scan value error for {wallet_id}: {e}"); _mark_scan_failed(wallet_id)
        except RuntimeError as e:
            logger.error(f"Scan runtime error for {wallet_id}: {e}"); _mark_scan_failed(wallet_id)
        except Exception as e:
            logger.error(f"Scan unexpected error for {wallet_id}: {e}", exc_info=True); _mark_scan_failed(wallet_id)
        finally:
            actual = (result or {}).get("blocks_scanned") if isinstance(result, dict) else None
            mark_scan_finished(
                user_id, wallet_id,
                actual_blocks=actual,
                estimated_blocks=estimated_blocks,
            )

    asyncio.create_task(_run_scan())
    return {"started": True}    

@silnt_api_router.post("/api/v1/wallet/{wallet_id}/scan/stop")
async def api_stop_scan(
    wallet_id: str, key_info: WalletTypeInfo = Depends(require_trusted_device)
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist.")
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")
    request_scan_stop(wallet_id)
    # Charge only for blocks actually scanned so far, and clear the per-wallet
    # cooldown so the user can immediately retry (e.g. fix the range and rescan).
    actual = get_scan_progress(wallet_id).get("current", 0)
    mark_scan_finished(
        key_info.wallet.user, wallet_id,
        actual_blocks=actual,
        estimated_blocks=None,         # not reconciling here; just reset cooldown
        reset_wallet_cooldown=True,
    )
    return {"status": "stop requested"}


# ── Background scanning (opt-in "Remote Scanner") ─────────────────────────────
# Opting in uploads ONLY the wallet's scan key (detection capability) so the
# server can keep the wallet caught up on a timer while the user is away. The
# spend key is never uploaded; the background scanner derives the spend PUBLIC
# key from the wallet's sp_address. Disabling deletes the key from the server.

async def _get_owned_wallet(wallet_id: str, key_info: WalletTypeInfo):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist.")
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")
    return wallet


@silnt_api_router.get("/api/v1/wallet/{wallet_id}/background-scan")
async def api_background_scan_status(
    wallet_id: str, key_info: WalletTypeInfo = Depends(require_trusted_device)
):
    from .crud import is_background_scan_enabled
    await _get_owned_wallet(wallet_id, key_info)
    return {"enabled": await is_background_scan_enabled(wallet_id)}


@silnt_api_router.put("/api/v1/wallet/{wallet_id}/background-scan")
async def api_background_scan_enable(
    wallet_id: str,
    data: BackgroundScanData,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    import coincurve
    from .crud import enable_background_scan
    from .helpers.wallet import parse_sp_address

    wallet = await _get_owned_wallet(wallet_id, key_info)
    sk = (data.scan_secret or "").strip().lower()
    try:
        sk_bytes = bytes.fromhex(sk)
        assert len(sk_bytes) == 32
    except Exception:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="scan_secret must be a 32-byte hex string.",
        )
    # Safety: the uploaded key must actually be THIS wallet's scan key (its public
    # key must match the B_scan in the wallet's sp_address). Rejects a wrong/typo'd
    # key that would silently scan nothing.
    try:
        b_scan_from_key = coincurve.PublicKey.from_secret(sk_bytes).format(compressed=True)
        b_scan_from_addr, _ = parse_sp_address(wallet.sp_address)
    except Exception:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Invalid scan key.")
    if b_scan_from_key != b_scan_from_addr:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="scan key does not match this wallet.",
        )
    await enable_background_scan(wallet_id, sk)
    return {"enabled": True}


@silnt_api_router.delete("/api/v1/wallet/{wallet_id}/background-scan")
async def api_background_scan_disable(
    wallet_id: str, key_info: WalletTypeInfo = Depends(require_trusted_device)
):
    from .crud import disable_background_scan
    await _get_owned_wallet(wallet_id, key_info)
    await disable_background_scan(wallet_id)
    return {"enabled": False}


@silnt_api_router.delete("/api/v1/background-scan/all")
async def api_background_scan_disable_all(
    key_info: WalletTypeInfo = Depends(require_trusted_device)
):
    """Revoke server-side background scanning for ALL of the user's wallets in one
    call. Used by the mobile duress action so a coerced unlock also removes the
    uploaded scan key from the server."""
    from .crud import disable_all_background_scans_for_user
    await disable_all_background_scans_for_user(key_info.wallet.user)
    return {"ok": True}


# ── Push notification device tokens (FCM) ─────────────────────────────────────
@silnt_api_router.post("/api/v1/fcm/token")
async def api_register_fcm_token(
    data: FcmTokenData, key_info: WalletTypeInfo = Depends(require_trusted_device)
):
    from .crud import register_fcm_token
    tok = (data.token or "").strip()
    if not tok:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="token is required.")
    await register_fcm_token(key_info.wallet.user, tok)
    return {"ok": True}


@silnt_api_router.delete("/api/v1/fcm/token")
async def api_unregister_fcm_token(
    data: FcmTokenData, key_info: WalletTypeInfo = Depends(require_trusted_device)
):
    from .crud import remove_fcm_token
    tok = (data.token or "").strip()
    if tok:
        await remove_fcm_token(tok)
    return {"ok": True}


@silnt_api_router.post("/api/v1/fcm/test")
async def api_test_fcm(
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    """Send a diagnostic push to this user's registered devices and report the
    outcome. Lets the user verify the whole FCM pipeline (credentials on the
    server + a registered device token) without waiting for a real payment and
    the 30-min background sweep. The returned report says exactly why nothing
    arrived if it didn't."""
    from .crud import list_fcm_tokens_for_user
    from .helpers.fcm import send_fcm_report

    tokens = await list_fcm_tokens_for_user(key_info.wallet.user)
    report = await send_fcm_report(
        tokens,
        "Thrilla test notification",
        "If you can see this, push notifications are working.",
        {"type": "test"},
    )
    return report


async def _notify_payment_found(wallet, new_found: int, amount_sats) -> None:
    """Best-effort push when a scan finds new funds.

    Deliberately GENERIC for privacy: an FCM 'notification' message has its
    title, body and data pass through Google in plaintext (that's how Android
    displays it while the app is closed). So we intentionally omit the amount,
    wallet name and count — the sensitive financial metadata — and leave only
    "a payment arrived". The exact amount is shown ONLY inside the app: the
    in-app banner is composed locally from scan data and never traverses FCM.
    (`new_found`/`amount_sats` are kept in the signature for callers but are
    intentionally NOT put into the message.)

    No-op if push isn't configured or the user has no registered device."""
    try:
        from .crud import list_fcm_tokens_for_user
        from .helpers.fcm import send_fcm

        tokens = await list_fcm_tokens_for_user(wallet.user)
        if not tokens:
            return
        await send_fcm(
            tokens,
            "Payment received",
            "You've received a new payment. Open Thrilla to view.",
            {"type": "payment"},
        )
    except Exception as e:
        logger.warning(f"payment-found push failed for {getattr(wallet, 'id', '?')}: {e}")


# How often to poll each active network's chain tip for a new block. A sweep is
# triggered as soon as the tip advances, so a received payment is detected within
# ~a block instead of waiting out the full interval.
BACKGROUND_SCAN_POLL_SECONDS = 60
# Safety-net: sweep at least this often even if no new block was observed (covers
# newly opted-in wallets, missed tip updates, and server restarts).
BACKGROUND_SCAN_INTERVAL_SECONDS = 1800  # 30 min


async def background_tip_advanced(last_tip_by_network: dict) -> bool:
    """Poll each active network's chain tip once and report whether a new block
    has appeared since the previous check. Updates ``last_tip_by_network`` in
    place. Cheap enough to call every minute — one tip request per network with
    opted-in wallets, not one per wallet. Never raises."""
    advanced = False
    try:
        from .crud import list_background_scan_networks

        networks = await list_background_scan_networks()
    except Exception as e:
        logger.warning(f"background tip check: could not list networks: {e}")
        return False

    for net in networks:
        try:
            blindbit = await get_backend_config(net)
            if not blindbit.blindbit_url:
                continue
            oracle = BlindBitOracleClient(base_url=blindbit.blindbit_url)
            tip = await oracle.get_chain_tip()
            if not tip:
                continue
            if int(tip) > int(last_tip_by_network.get(net, 0)):
                last_tip_by_network[net] = int(tip)
                advanced = True
        except Exception as e:
            logger.warning(f"background tip check failed for {net}: {e}")
    return advanced


async def run_background_scans() -> None:
    """One sweep: catch up every opted-in wallet to the chain tip. Stores no
    spend key — derives the spend PUBLIC key from each wallet's sp_address."""
    from .crud import (
        list_background_scan_wallet_ids,
        get_background_scan_secret,
    )
    from .helpers.wallet import parse_sp_address

    wallet_ids = await list_background_scan_wallet_ids()
    for wid in wallet_ids:
        try:
            wallet = await get_silnt_wallet(wid)
            if not wallet:
                continue
            # Don't collide with a user-initiated scan already in flight.
            if get_scan_progress(wid).get("active"):
                continue
            blindbit = await get_backend_config(wallet.network)
            if not blindbit.blindbit_url:
                continue
            oracle = BlindBitOracleClient(base_url=blindbit.blindbit_url)
            tip = await oracle.get_chain_tip()
            if not tip:
                continue
            birth = int(wallet.last_height or 0)
            last_scan = int(wallet.last_scan_height or 0)
            covered = max(last_scan, birth)
            if covered >= tip:
                continue  # already caught up
            scan_secret = await get_background_scan_secret(wid)
            if not scan_secret:
                continue
            _, b_spend = parse_sp_address(wallet.sp_address)
            resume = last_scan + 1 if last_scan > birth else birth
            logger.info(f"Background scan {wid}: blocks {resume}–{tip}")
            result = await scan_wallet(
                wallet_id=wid,
                scan_secret_hex=scan_secret,
                spend_pub_hex=b_spend.hex(),
                from_height=resume,
                to_height=tip,
            )
            new_found = (result or {}).get("utxos_found", 0)
            if new_found > 0:
                await _notify_payment_found(
                    wallet, new_found, (result or {}).get("amount_found")
                )
        except Exception as e:
            logger.warning(f"Background scan failed for {wid}: {e}")
            continue


# BIP353
@silnt_api_router.get("/api/v1/bip353/resolve")
async def api_resolve_bip353(
    address: str = Query(
        ..., description="BIP353 address in email format, e.g. alice@domain.com"
    ),
    key_info: WalletTypeInfo = Depends(require_trusted_device),
) -> dict:
    return bip353_resolve(address.strip())


@silnt_api_router.get("/api/v1/bip353/available")
async def api_bip353_available(
    username: str = Query(..., description="Desired BitMail username (no domain)"),
    key_info: WalletTypeInfo = Depends(require_trusted_device),
) -> dict:
    """
    Live availability check for a BitMail username, used by clients before
    submitting a request. Applies the same rules as api_create_bip353_request:
    format, reserved list, already-approved, and existing DNS record.
    Returns {available: bool, reason: 'invalid'|'reserved'|'taken'|None}.
    """
    u = (username or "").strip().lower()
    if not USERNAME_PATTERN.match(u):
        return {"available": False, "reason": "invalid"}
    if u in RESERVED_USERNAMES:
        return {"available": False, "reason": "reserved"}
    if await is_username_taken(u):
        return {"available": False, "reason": "taken"}
    try:
        _cf = await get_cloudflare_config()
        if _cf and _cf.domain and _bip353_exists_in_dns(u, _cf.domain):
            return {"available": False, "reason": "taken"}
    except Exception:
        # A DNS/config hiccup shouldn't block the check — the authoritative
        # validation still runs on submit in api_create_bip353_request.
        pass
    return {"available": True, "reason": None}
    

# Transactions
@silnt_api_router.post("/api/v1/tx/build", dependencies=[Depends(require_trusted_device_admin)])
async def api_build_transaction(
    data: BuildTxRequest, key_info: WalletTypeInfo = Depends(require_trusted_device_admin)
):
    try:
        wallet = await get_silnt_wallet(data.wallet_id)
        if not wallet:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
            )
        if wallet.user != key_info.wallet.user:
            raise HTTPException(
                status_code=HTTPStatus.FORBIDDEN, detail="Access denied."
            )

        if not data.spend_key:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST, detail="spend_key is required."
            )
        if not data.scan_secret:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="scan_secret is required (used to derive change address).",
            )
        # ── Validate UTXOs against the DB: refuse frozen, refuse non-owned ──
        if not data.utxos:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="No UTXOs provided for the transaction.",
            )

        def _txid_of(u):
            return u["txid"] if isinstance(u, dict) else u.txid

        def _vout_of(u):
            if isinstance(u, dict):
                return int(u.get("vout", 0))
            return int(getattr(u, "vout", 0) or 0)
        
        passed_txids_vouts = [(_txid_of(u), _vout_of(u)) for u in data.utxos]
        eligible_rows = await get_eligible_utxos(
            wallet_id=data.wallet_id,
            txid_vout_pairs=passed_txids_vouts,
        )
        eligible_set = {(r["txid"], r["vout"]) for r in eligible_rows}

        # Anything passed but not in eligible_set is either frozen, not unspent,
        # or doesn't belong to this wallet
        rejected = [
            (_txid_of(u), _vout_of(u)) for u in data.utxos
            if (_txid_of(u), _vout_of(u)) not in eligible_set
        ]
        if rejected:
            rejected_str = ", ".join(f"{t[:12]}…:{v}" for t, v in rejected)
            scanning = bool(get_scan_progress(data.wallet_id).get("active"))
            if scanning:
                detail = (
                    f"Cannot spend these UTXOs ({rejected_str}) because a scan is "
                    f"in progress and their state just changed. Refresh your UTXOs "
                    f"and reselect, then try again."
                )
            else:
                detail = (
                    f"Cannot spend these UTXOs ({rejected_str}). "
                    f"They are either frozen, already spent, or don't belong "
                    f"to this wallet. Unfreeze them or remove from selection."
                )
            raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=detail)
        _orig_recipient = data.recipient.strip()
        if "@" in data.recipient:
            user, domain = data.recipient.strip().split("@")
            if user and domain:
                resolved = bip353_resolve(data.recipient)
                result = resolved["result"].replace("bitcoin:?sp=", "")
                if not result.startswith("sp1") and not result.startswith("tsp1"):
                    raise HTTPException(
                        status_code=HTTPStatus.BAD_REQUEST,
                        detail="Address must resolve to Silent Payment address (sp1).",
                    )
                 # Tampering guard: if this BitMail is one WE issued on OUR
                # configured domain, the DNS TXT must still resolve to the SP
                # address we recorded. A mismatch means the record was altered to
                # redirect funds — block the send, alert the admin, and ntfy.
                try:
                    cf = await get_cloudflare_config()
                    our_domain = (getattr(cf, "domain", "") or "").strip().lower()
                except Exception:
                    our_domain = ""
                if our_domain and domain.strip().lower() == our_domain:
                    expected = await get_issued_bitmail_sp_address(user.strip())
                    if expected and expected.strip().lower() != result.strip().lower():
                        detail = (
                            f"BitMail {user}@{domain} resolved to {result} but siLNt "
                            f"issued it for {expected}. The DNS record may have been "
                            f"tampered with to redirect funds. Send blocked."
                        )
                        try:
                            await create_admin_alert(
                                kind="bitmail_tamper",
                                severity="critical",
                                title=f"BitMail tampering: {user}@{domain}",
                                detail=detail,
                                meta=json.dumps({
                                    "bitmail": f"{user}@{domain}",
                                    "resolved_sp": result,
                                    "expected_sp": expected,
                                }),
                            )
                        except Exception as e:
                            logger.error(f"could not record bitmail-tamper alert: {e}")
                        try:
                            await send_ntfy_notification(
                                title="⚠ BitMail tampering detected",
                                message=detail,
                                tags=["rotating_light"],
                                priority="urgent",
                            )
                        except Exception as e:
                            logger.warning(f"ntfy (bitmail tamper) failed: {e}")
                        raise HTTPException(
                            status_code=HTTPStatus.BAD_REQUEST,
                            detail=(
                                "This BitMail resolves to an address that does not match "
                                "what was registered. The send has been blocked and an "
                                "administrator has been alerted. Do not retry — verify the "
                                "recipient address out of band."
                            ),
                        )
                data.recipient = result                
        
        result = build_transaction(
            spend_key_hex=data.spend_key,
            scan_secret_hex = data.scan_secret,
            recipient=data.recipient,
            amount=data.amount,
            fee_rate=data.fee_rate,
            utxos=data.utxos,
            network=wallet.network,
        )
        try:
            await touch_sp_contact(key_info.wallet.user, _orig_recipient, wallet.network)
        except Exception:
            pass
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Transaction build failed: {exc}")
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Failed to build transaction: {str(exc)}",
        ) from exc


@silnt_api_router.post(
    "/api/v1/tx/broadcast", dependencies=[Depends(require_trusted_device_admin)]
)
async def api_broadcast_transaction(data: BroadcastTxRequest):
    try:
        _bwallet = await get_silnt_wallet(data.wallet_id)
        if not _bwallet:
            raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet not found.")
        blindbit = await get_backend_config(_bwallet.network)
        base = (blindbit.mempool_url or "https://mempool.space").rstrip("/")
        mempool_url = f"{base}/api/tx"

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                mempool_url, content=data.tx_hex, headers={"Content-Type": "text/plain"}
            )
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=HTTPStatus.BAD_GATEWAY,
                    detail=f"Broadcast failed: {resp.text}",
                )

            txid = resp.text.strip()

            # ── Mark the spent inputs immediately so Activity shows the Sent tx
            #    without waiting for a rescan. Use the exact outpoints the client
            #    sent; this is keyed on (txid, vout), so it never over-marks.
            if data.wallet_id and data.spent_outpoints:
                # data.spent_outpoints is a list of {txid, vout} models/dicts.
                input_outpoints = [
                    (op.txid, op.vout) if hasattr(op, "txid") else (op["txid"], op["vout"])
                    for op in data.spent_outpoints
                ]
                marked = await mark_utxos_spent_by_tx(
                    wallet_id=data.wallet_id,
                    input_outpoints=input_outpoints,
                    spending_txid=txid,
                )
                logger.info(
                    f"Broadcast {txid}: marked {marked} input UTXO(s) unconfirmed_spent"
                )
            else:
                logger.warning(
                    f"Broadcast {txid}: no spent_outpoints supplied; the Sent tx "
                    f"will only appear in Activity after the next rescan"
                )

            return {"txid": txid}

    except HTTPException:
        raise
    except httpx.ConnectError:
        raise HTTPException(
            status_code=HTTPStatus.BAD_GATEWAY,
            detail=f"Could not connect to {base}",
        )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=HTTPStatus.GATEWAY_TIMEOUT, detail="mempool.space timed out"
        )


@silnt_api_router.post("/api/v1/wallet/{wallet_id}/recover-keys")
async def api_recover_wallet_keys(
    wallet_id: str,
    data: RecoverKeysRequest,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    """
    Re-derive scan_secret and spend_key from mnemonic for an existing wallet.
    Verifies the derived sp_address matches the stored one — protects against
    re-importing the wrong mnemonic.
    Keys are NEVER stored on the server, only returned transiently.
    """
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist.")
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    passphrase = (data.passphrase or "").strip()
    try:
        mnemonic_plain = decrypt_mnemonic(data.mnemonic, str(data.last_height))
        sp_address, scan_secret_hex, spend_key_hex = await generate_silent_wallet_address(
            mnemonic_plain,
            passphrase=passphrase, 
            network=wallet.network,
        )
    except Exception as e:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Could not derive keys from mnemonic: {str(e)}",
        )

    # Verify derived address matches the stored one — wrong mnemonic = rejection
    if sp_address.lower() != wallet.sp_address.lower():
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=(
                "The mnemonic you entered does not match this wallet. "
                "If this wallet was created with a passphrase, make sure you enter "
                "the exact same passphrase."
            ),
        )

    # Return keys transiently — they are not stored anywhere on the server
    return {
        "wallet_id":   wallet_id,
        "scan_secret": scan_secret_hex,
        "spend_key":   spend_key_hex,
    }

@silnt_api_router.get("/api/v1/config")
async def api_get_config(
    network: Optional[str] = Query(None),
    key_info: WalletTypeInfo = Depends(require_trusted_device),
) -> dict:
    # No silent signet fallback: require the client's network explicitly so a
    # mainnet build can't be served signet's min_scan_height / dust threshold.
    if not network:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="A `network` query parameter is required (e.g. ?network=mainnet).",
        )
    blindbit = await get_backend_config(network)
    config = Config()
    # Per-network count so the UI's "wallets used" matches the per-network create
    # limit enforced in api_wallet_create.
    current  = await count_silnt_wallets(key_info.wallet.user, network)
    return {
        "mempool_endpoint": blindbit.mempool_url or "https://mempool.space",
        "sats_denominated": config.sats_denominated,
        "network": config.network,
        "min_scan_height":   blindbit.min_scan_height or 0,
        "wallet_count":         current,
        "dust_threshold_sats": blindbit.dust_threshold_sats or 5000
    }

@silnt_api_router.get(
    "/api/v1/wallet/{wallet_id}/scan/progress",
    dependencies=[Depends(require_trusted_device)],
)
async def api_scan_progress(wallet_id: str):
    return get_scan_progress(wallet_id)


# ── GET Cloudflare config (admin only) ───────────────────────────────────────
@silnt_api_router.get("/api/v1/cloudflare/config")
async def api_get_cloudflare_config(
    key_info: WalletTypeInfo = Depends(require_trusted_device_admin),
) -> CloudflareConfig:
    cf = await get_cloudflare_config()
    # Backfill domain if credentials are present but domain is missing
    # (e.g. config saved before the domain field existed)
    if cf.api_token and cf.zone_id and not cf.domain:
        try:
            cf.domain = await get_zone_domain(cf.api_token, cf.zone_id)
            await update_cloudflare_config(cf)
        except Exception:
            pass
    return cf


# ── PUT Cloudflare config (admin only) ───────────────────────────────────────
@silnt_api_router.put("/api/v1/cloudflare/config")
async def api_update_cloudflare_config(
    data: CloudflareConfig,
    key_info: WalletTypeInfo = Depends(require_trusted_device_admin),
) -> CloudflareConfig:
    require_admin(key_info)
    # Verify token + zone by fetching domain — also auto-populates data.domain
    if data.api_token and data.zone_id:
        try:
            data.domain = await get_zone_domain(data.api_token, data.zone_id)
        except Exception as e:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail=f"Could not verify Cloudflare zone: {str(e)}",
            )
    else:
        data.domain = ""
    return await update_cloudflare_config(data)


# ── POST setup BIP-353 for a wallet via Cloudflare ───────────────────────────
@silnt_api_router.post("/api/v1/wallet/{wallet_id}/bip353/setup")
async def api_setup_bip353(
    wallet_id: str,
    data: SetupBip353Request,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    # Reject if wallet already has BIP-353 — users must remove first, then create
    if wallet.hr_address:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Wallet already has BIP-353 address: {wallet.hr_address}. "
            "Remove it first before creating a new one.",
        )
    # Validate username format
    if not re.match(r"^[a-zA-Z0-9._-]+$", data.username):
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Username must contain only letters, numbers, dots, hyphens, underscores.",
        )

    cf = await get_cloudflare_config()
    if not cf.api_token or not cf.zone_id:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Cloudflare API not configured. Ask your administrator to set it up.",
        )

    try:
        result = await create_bip353_record(
            api_token=cf.api_token,
            zone_id=cf.zone_id,
            domain=cf.domain,
            username=data.username.lower(),
            sp_address=wallet.sp_address,
            ttl=data.ttl,
        )
    except CloudflareError as e:
        raise HTTPException(status_code=HTTPStatus.BAD_GATEWAY, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, detail=str(e))

    # Update wallet hr_address
    await update_hr_address(wallet_id, result["hr_address"])

    return {
        "hr_address": result["hr_address"],
        "record_name": result["record_name"],
        "action": result["action"],
        "sp_address": wallet.sp_address,
    }


# ── DELETE BIP-353 record for a wallet ───────────────────────────────────────
@silnt_api_router.delete("/api/v1/wallet/{wallet_id}/bip353")
async def api_delete_bip353(
    wallet_id: str,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist."
        )
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")
    if not wallet.hr_address:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="No BIP-353 address set."
        )

    cf = await get_cloudflare_config()
    if not cf.api_token or not cf.zone_id:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="Cloudflare API not configured."
        )

    try:
        username = wallet.hr_address.split("@")[0]
        deleted = await delete_bip353_record(cf.api_token, cf.zone_id, cf.domain, username)
    except CloudflareError as e:
        raise HTTPException(status_code=HTTPStatus.BAD_GATEWAY, detail=str(e))

    # Clear hr_address from wallet
    await update_hr_address(wallet_id, "")

    return {"deleted": deleted, "was": wallet.hr_address}

@silnt_api_router.post("/api/v1/auth/register-start")
async def api_register_start(data: RegistrationRequest, request: Request) -> dict:
    return await start_registration(data, request)

@silnt_api_router.post("/api/v1/auth/register-verify")
async def api_register_verify(data: VerifyRegistrationRequest) -> dict:
    return await complete_registration(data.token)

@silnt_api_router.post("/api/v1/auth/forgot-password")
async def api_forgot_password(data: ForgotPasswordRequest, request: Request) -> dict:
    """
    User requests a password reset link by email.
    The link is emailed to them and contains a signed reset_key that can be
    submitted to LNbits's PUT /api/v1/auth/reset endpoint.
    """
    if not data.email or "@" not in data.email:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Valid email address required.",
        )
    return await request_password_reset(data.email.strip().lower(), request)


_INVITE_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@silnt_api_router.post(
    "/api/v1/invite", dependencies=[Depends(require_trusted_device)]
)
async def api_send_invite(
    data: InviteRequest,
    request: Request,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
) -> dict:
    """Invite a friend to Thrilla by email.

    Sends a fixed invite template (naming the inviter) with a link to the
    sign-up page. Rate-limited per user; requires a trusted device. The invitee
    email is used only to send this one message — it is not stored.
    """
    email = (data.email or "").strip().lower()
    if not _INVITE_EMAIL_RE.match(email) or len(email) > 254:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Enter a valid email address.",
        )
    if not lnbits_settings.lnbits_email_notifications_enabled:
        raise HTTPException(
            status_code=HTTPStatus.SERVICE_UNAVAILABLE,
            detail="Email sending isn't available right now. Try again later.",
        )

    user_id = key_info.wallet.user
    check_invite_allowed(user_id, email)

    # Don't email addresses that already have an account (avoids nagging existing
    # users). The response is identical either way, so this doesn't reveal
    # whether an address is registered.
    already = await get_account_by_email(email)
    if not already:
        inviter = await get_account(user_id)
        inviter_name = (inviter.username if inviter else None) or "A Thrilla user"

        from .helpers.appenv import frontend_base_url

        origin = frontend_base_url(request)
        signup_url = f"{origin}/register"
        subject = f"{inviter_name} invited you to try Thrilla"
        body = (
            f"Hi,\n\n"
            f"{inviter_name} is using Thrilla — a Bitcoin wallet built on Silent "
            f"Payments, so you can receive to one reusable address without "
            f"reusing it on-chain — and thought you'd want to try it.\n\n"
            f"Create your free account here:\n\n"
            f"    {signup_url}\n\n"
            f"Not interested? You can ignore this email — you won't be contacted "
            f"again.\n\n"
            f"— The Thrilla team"
        )
        try:
            res = await send_email_notification(
                to_emails=[email], message=body, subject=subject
            )
            if res.get("status") != "ok":
                logger.warning(f"Invite email failed: {res}")
                raise HTTPException(
                    status_code=HTTPStatus.BAD_GATEWAY,
                    detail="Could not send the invitation. Please try again later.",
                )
        except HTTPException:
            raise
        except Exception as exc:
            logger.warning(f"Invite email raised: {exc}")
            raise HTTPException(
                status_code=HTTPStatus.BAD_GATEWAY,
                detail="Could not send the invitation. Please try again later.",
            )
        logger.info(f"Invite sent by {user_id} to {email}")

    record_invite(user_id, email)
    return {"success": True, "message": f"Invitation sent to {email}."}


# UTXO Labels
@silnt_api_router.put("/api/v1/utxos/{txid}/label")
async def api_update_utxo_label(
    txid: str,
    data: UpdateUtxoLabel,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
     # Verify the caller owns the target wallet
    wallet = await get_silnt_wallet(data.wallet_id)
    if not wallet or wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    # Update only rows in that wallet — never globally by txid
    updated = await update_utxo_label_by_txid(txid, data.label, wallet_id=data.wallet_id)
    if updated == 0:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="UTXO not found in this wallet.")

    return {"txid": txid, "label": data.label, "updated": updated}

@silnt_api_router.put("/api/v1/wallet/{wallet_id}/addresses/{addr_id}/label")
async def api_update_address_label(
    wallet_id: str,
    addr_id: str,
    data: UpdateAddressLabelRequest,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist.")
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    # Lookup the address to verify it belongs to this wallet AND grab its old label
    addr = await get_wallet_address(addr_id)
    if not addr:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Labeled address not found.")
    if addr.wallet_id != wallet_id:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Address does not belong to this wallet.")

    new_label = (data.label or "").strip() or None

    await update_address_label(addr_id, new_label)

    return {
        "id":          addr_id,
        "label":       new_label,
        "label_index": addr.label_index,
        "sp_address":  addr.sp_address,
    }

@silnt_api_router.put("/api/v1/utxos/{txid}/{vout}/frozen")
async def api_set_utxo_frozen(
    txid: str,
    vout: int,
    data: UpdateUtxoFrozenRequest,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    utxos = await get_utxos_by_txid(txid)
    if not utxos:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="UTXO not found.")
    owned_wallet_ids = {w.id for w in await get_silnt_wallets(key_info.wallet.user)}
    matching = next(
        (u for u in utxos if u.vout == vout and u.wallet_id in owned_wallet_ids),
        None,
    )
    if not matching:
        if any(u.vout == vout for u in utxos):
            raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="UTXO not found at that vout.")

    if data.frozen:
        await set_utxo_freeze_manual(txid, vout)
    else:
        await clear_utxo_freeze_manual(txid, vout)

    return {"txid": txid, "vout": vout, "frozen": data.frozen}

@silnt_api_router.get("/api/v1/wallet/{wallet_id}/transactions")
async def api_list_wallet_transactions(
    wallet_id: str,
    limit:     int = 50,
    offset:    int = 0,
    key_info:  WalletTypeInfo = Depends(require_trusted_device),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist.")
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    txs = await list_wallet_transactions(wallet_id, limit=limit, offset=offset)
    return {"transactions": txs}


@silnt_api_router.get("/api/v1/wallet/{wallet_id}/transactions/{txid}")
async def api_get_wallet_transaction(
    wallet_id: str,
    txid:      str,
    key_info:  WalletTypeInfo = Depends(require_trusted_device),
):
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet does not exist.")
    if wallet.user != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied.")

    return await get_wallet_transaction_detail(wallet_id, txid, wallet.network)

@silnt_api_router.post("/api/v1/auth/device-check")
async def api_device_check(
    request:  Request,
    response: Response,
    key_info: WalletTypeInfo = Depends(require_invoice_key),
):
    user_id = key_info.wallet.user
    # cookie  = request.cookies.get(cookie_name_for_user(user_id))
    cookie  = read_device_id(request, user_id)
    ua      = request.headers.get("user-agent", "")[:512]
    # Brave (and some others) masquerade as Chrome in the UA. The client sends a
    # reliable brand hint when it can detect one; prefix it so the UA-based label
    # reflects the real browser. Whitelist known values to avoid header injection.
    brand   = (request.headers.get("x-client-brand", "") or "").strip()[:16]
    if brand in ("Brave",) and "Brave" not in ua:
        ua = f"{brand} {ua}"[:512]
    ip      = get_client_ip(request)

    if cookie:
        existing = await get_trusted_device(user_id, cookie)
        if existing:
            await touch_trusted_device(user_id, cookie)
            set_device_cookie(response, user_id, cookie)            # refresh expiry
            return DeviceCheckResponse(
                status       = "trusted",
                device_count = await count_trusted_devices(user_id),
                cap          = MAX_TRUSTED_DEVICES_PER_USER,
            )    
    return DeviceCheckResponse(
        status       = "untrusted",
        device_count = await count_trusted_devices(user_id),
        cap          = MAX_TRUSTED_DEVICES_PER_USER,
    )

@silnt_api_router.post("/api/v1/auth/device-request-confirm")
async def api_device_request_confirm(
    request:  Request,
    response: Response,
    key_info: WalletTypeInfo = Depends(require_invoice_key),
):
    """Explicitly send a new-device confirmation email. Called ONLY when the user
    chooses to confirm this device (the 'Send confirmation email' action on the
    pending-device screen) — never automatically. This is the email-sending half
    that used to live inside device-check."""
    user_id = key_info.wallet.user
    # cookie  = request.cookies.get(cookie_name_for_user(user_id))
    cookie  = read_device_id(request, user_id)
    ua      = request.headers.get("user-agent", "")[:512]
    brand   = (request.headers.get("x-client-brand", "") or "").strip()[:16]
    if brand in ("Brave",) and "Brave" not in ua:
        ua = f"{brand} {ua}"[:512]
    ip      = get_client_ip(request)

    # Already trusted on this browser? Nothing to send.
    if cookie:
        existing = await get_trusted_device(user_id, cookie)
        if existing:
            await touch_trusted_device(user_id, cookie)
            set_device_cookie(response, user_id, cookie)
            return {"status": "already-trusted"}

    new_device_id = secrets.token_urlsafe(24)

    current_count = await count_trusted_devices(user_id)
    if current_count >= MAX_TRUSTED_DEVICES_PER_USER:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=(
                f"This account already has {MAX_TRUSTED_DEVICES_PER_USER} "
                f"trusted devices (the maximum). Sign in from a trusted device "
                f"and revoke one in Settings → Devices before continuing."
            ),
        )

    account = await get_account(user_id)
    if not account or not account.email:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="This account has no email address. Cannot send confirmation.",
        )

    code = f"{secrets.randbelow(1000000):06d}"
    await create_device_code(user_id, code, new_device_id, ua, ip, ttl_secs=600)
    subject = "Your device confirmation code"
    body = (
        f"Hi {account.username or 'there'},\n\n"
        f"Your device confirmation code is:\n\n    {code}\n\n"
        f"Enter it in the app on the device you're signing in from. "
        f"This code expires in 10 minutes.\n\n"
        f"A sign-in was attempted from:\n"
        f"  Browser: {ua or 'unknown'}\n  IP:      {ip or 'unknown'}\n"
        f"  Time:    {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}\n\n"
        f"If this WASN'T you, someone may have your password. Change your "
        f"password and contact your administrator. (The IP shown may be a "
        f"CDN/proxy IP and may not reflect the actual location.)"
    )
    res = await send_email_notification(to_emails=[account.email], message=body, subject=subject)
    if res.get("status") != "ok":
        logger.warning(f"Device code email failed: {res}")
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                            detail="Could not send confirmation code. Please contact your administrator.")
    # No valid trusted-device cookie. This endpoint is CHECK-ONLY: it never sends
    # a confirmation email or mutates state. That avoids auto-emailing on every
    # untrusted check (e.g. right after a user revokes their own device, or when
    # a privacy browser / VPN drops the cookie). The confirmation email is sent
    # only when the user explicitly asks, via /auth/device-request-confirm.
    try:
        existing_count = await count_trusted_devices(user_id)
        if existing_count > 0:
            sig = hashlib.sha256(f"{ua}|{ip}".encode()).hexdigest()[:32]
            if await should_send_login_alert(user_id, sig):
                account = await get_account(user_id)
                if account and account.email:
                    subject = "New device sign-in to your wallet"
                    body = (
                        f"Hi {account.username or 'there'},\n\n"
                        f"Your account was just signed in to from a device that isn't "
                        f"one of your confirmed devices:\n\n"
                        f"  Browser: {ua or 'unknown'}\n"
                        f"  IP:      {ip or 'unknown'}\n"
                        f"  Time:    {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}\n\n"
                        f"If this was you, just confirm the device from the app to start "
                        f"using it — nothing else to do.\n\n"
                        f"If this WASN'T you, someone may have your password. Your wallet "
                        f"is still safe (they can't use it without also confirming the "
                        f"device by email), but you should change your password and "
                        f"contact your administrator.\n\n"
                        f"(Note: the IP shown may be a CDN/proxy IP and may not "
                        f"reflect the actual location.)"
                    )
                    res = await send_email_notification(
                        to_emails=[account.email], message=body, subject=subject
                    )
                    if res.get("status") != "ok":
                        logger.warning(f"Login-alert email failed for {user_id}: {res}")
    except Exception as e:
        logger.warning(f"Login-alert send skipped: {e}")
    return {"status": "sent"}
   
@silnt_api_router.post("/api/v1/auth/device-verify-code")
async def api_device_verify_code(request: Request, response: Response,
                                 key_info: WalletTypeInfo = Depends(require_invoice_key)):
    user_id = key_info.wallet.user
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    code = str((payload or {}).get("code", "")).strip()
    if not code.isdigit() or len(code) != 6:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Enter the 6-digit code.")
    pending = await verify_device_code(user_id, code)
    if not pending:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST,
                            detail="That code is incorrect or expired. Request a new one if needed.")
    current_count = await count_trusted_devices(user_id)
    if current_count >= MAX_TRUSTED_DEVICES_PER_USER:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST,
                            detail=f"This account already has {MAX_TRUSTED_DEVICES_PER_USER} trusted devices. Revoke one before adding another.")
    device_id = pending["device_id"]
    await add_trusted_device(user_id=user_id, device_id=device_id,
                             user_agent=pending.get("user_agent") or "", ip=pending.get("ip") or "")
    set_device_cookie(response, user_id, device_id)
    return DeviceConfirmResponse(confirmed=True, device_count=current_count + 1, cap=MAX_TRUSTED_DEVICES_PER_USER, device_id = device_id)


@silnt_api_router.get("/api/v1/devices")
async def api_list_devices(
    request:  Request,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    user_id = key_info.wallet.user
    devices = await list_trusted_devices(user_id)
    # current = request.cookies.get(cookie_name_for_user(user_id))
    current  = read_device_id(request, user_id)
    return DeviceListResponse(
        devices        = devices,
        current_device = current,
        cap            = MAX_TRUSTED_DEVICES_PER_USER,
    )


@silnt_api_router.delete("/api/v1/devices/{device_row_id}")
async def api_revoke_device(
    device_row_id: str,
    request:  Request,
    response: Response,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    user_id = key_info.wallet.user
    devices = await list_trusted_devices(user_id)
    target  = next((d for d in devices if d.id == device_row_id), None)
    if not target:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Device not found.")

    deleted = await revoke_trusted_device(user_id, device_row_id)

    # current = request.cookies.get(cookie_name_for_user(user_id))
    current  = read_device_id(request, user_id)
    was_current = (target.device_id == current)
    if was_current:
        clear_device_cookie(response, user_id)

    return {"deleted": bool(deleted), "device_row_id": device_row_id, "was_current": was_current}


@silnt_api_router.post("/api/v1/devices/sign-out-others")
async def api_sign_out_others(
    request:  Request,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    user_id = key_info.wallet.user
    # current = request.cookies.get(cookie_name_for_user(user_id))
    current  = read_device_id(request, user_id)
    if not current:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="No active device.")
    removed = await revoke_all_other_devices(user_id, current)
    return {"removed_count": removed}

@silnt_api_router.get("/api/v1/auth/is-admin")
async def api_is_admin(key_info: WalletTypeInfo = Depends(require_invoice_key)):
    return {"is_admin": is_lnbits_admin(key_info.wallet.user)}
    
@silnt_api_router.get("/api/v1/auth/me")
async def api_whoami(
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    """Return basic info about the current authenticated user."""    
    account = await get_account(key_info.wallet.user)
    return WhoamiResponse(
        user_id  = key_info.wallet.user,
        username = account.username if account else None,
        email    = account.email    if account else None,
        is_admin = is_lnbits_admin(key_info.wallet.user),
    )

@silnt_api_router.get("/api/v1/user/prefs")
async def api_get_user_prefs(
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    """
    Get the current user's prefs + the admin default (so the UI can show
    'You have no override set — using admin default of N sats').
    """
    user_id  = key_info.wallet.user
    prefs    = await get_user_prefs(user_id)
    backend  = await get_backend_config(DEFAULT_CONFIG_NETWORK)
    admin_default = int(backend.dust_threshold_sats or 5000)
    return {
        "user_id":                    user_id,
        "dust_threshold_sats":        prefs.dust_threshold_sats if prefs else None,
        "admin_default_dust":         admin_default,
        "effective_dust_threshold":   await get_effective_dust_threshold(user_id),
    }


@silnt_api_router.put("/api/v1/user/prefs")
async def api_update_user_prefs(
    data: UpdateUserPrefsRequest,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    """
    Update the current user's prefs. Passing dust_threshold_sats=None (or 0)
    clears the override — user falls back to admin default.
    """
    user_id = key_info.wallet.user

    dts = data.dust_threshold_sats
    if dts is not None:
        try:
            dts = int(dts)
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="dust_threshold_sats must be an integer or null.",
            )
        if dts <= 0:
            # Treat 0 / negative as "revert to admin default"
            dts = None
        elif dts > 10_000:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="dust_threshold_sats too large (max 10000).",
            )

    await upsert_user_prefs(user_id, dts)
    # Re-evaluate existing UTXOs against the new threshold so the change applies
    # to what's already in the wallet — not just to UTXOs found on the next scan.
    reevaluated = 0
    try:
        for w in await get_silnt_wallets(user_id):
            try:
                await evaluate_dust_for_wallet(w.id)
                reevaluated = 1
            except Exception as e:
                logger.warning(f"dust re-eval failed for wallet {w.id}: {e}")
    except Exception as e:
        logger.warning(f"dust re-eval skipped after prefs update: {e}")
    backend = await get_backend_config(DEFAULT_CONFIG_NETWORK)
    return {
        "user_id":                    user_id,
        "dust_threshold_sats":        dts,
        "admin_default_dust":         int(backend.dust_threshold_sats or 5000),
        "effective_dust_threshold":   await get_effective_dust_threshold(user_id),
        "wallets_reevaluated":        reevaluated
    }

@silnt_api_router.post("/api/v1/bip353/request")
async def api_create_bip353_request(
    data: CreateBip353Request,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    user_id  = key_info.wallet.user    
    username = (data.requested_username or "").strip().lower()

    if not USERNAME_PATTERN.match(username):
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Username must be 3–20 chars, lowercase letters, digits, dash, or underscore.",
        )
    if username in RESERVED_USERNAMES:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="This username is reserved. Choose another.",
        )
    if await is_username_taken(username):
        raise HTTPException(
            status_code=HTTPStatus.CONFLICT,
            detail="That BitMail username is already taken. Choose another.",
        )
    _cf = await get_cloudflare_config()
    if _cf and _cf.domain and _bip353_exists_in_dns(username, _cf.domain):
        raise HTTPException(
            status_code=HTTPStatus.CONFLICT,
            detail="That BitMail username is already taken. Choose another.",
        )
    # Verify wallet ownership FIRST so all checks below are wallet-scoped
    wallet = await get_silnt_wallet(data.wallet_id)
    if not wallet or wallet.user != user_id:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Wallet not found.")
    if not wallet.sp_address:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Wallet has no SP address yet — scan first.",
        )

    # Resolve the TARGET address: None = wallet base address; else a labeled address row.
    address_id = data.address_id
    if address_id is None:
        target_sp_address = wallet.sp_address
        current_hr        = (wallet.hr_address or "").strip()
    else:
        addr = await get_wallet_address(address_id)
        if not addr or addr.wallet_id != data.wallet_id:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="Labeled address not found on this wallet.",
            )
        target_sp_address = addr.sp_address
        current_hr        = (addr.hr_address or "").strip()

    # This specific address already HAS a BitMail right now.
    if current_hr:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"This address already has the BitMail {current_hr}. "
                   f"Remove it first — note a removed BitMail cannot be re-added to the same address.",
        )

    # Assign-once: this address was granted a BitMail before (even if since removed).
    if await address_has_approved_bitmail(data.wallet_id, address_id) or await sp_address_has_approved_bitmail(target_sp_address):
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN,
            detail="This address previously had a BitMail and cannot be assigned another. "
                   "BitMail assignment is permanent per address.",
        )

    # Wallet-wide cap across base + labeled addresses (base + 2 labeled = 3).
    used = await count_approved_bip353_for_wallet(data.wallet_id)
    if used >= BITMAIL_MAX_ACQUISITIONS:
        raise HTTPException(
            HTTPStatus.FORBIDDEN,
            f"This wallet has reached the limit of {BITMAIL_MAX_ACQUISITIONS} "
            f"BitMail addresses and cannot request another.",
        )
    req = await create_bip353_request(
            user_id            = user_id,
            wallet_id          = data.wallet_id,
            sp_address         = target_sp_address,            
            requested_username = username,
            message            = data.message,
            address_id         = address_id,
        )
    # Notify admins there's a new BitMail request awaiting review (best-effort).
    try:        
        acct = await get_account(user_id)
        requester = (getattr(acct, "username", None) or "").strip() if acct else ""
        requester_label = requester or user_id
        await send_ntfy_notification(
            title="New BitMail request",
             message=(
                f"User '{requester_label}' requested the BitMail username "
                f"'{username}' and is awaiting approval."
            ),
            tags=["email"],
        )
    except Exception as e:
        logger.warning(f"ntfy notify (new bitmail request) failed: {e}")     
    return req

@silnt_api_router.get("/api/v1/bip353/requests")
async def api_list_user_requests(
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    requests = await list_user_bip353_requests(key_info.wallet.user)
    return {"requests": requests}


@silnt_api_router.delete("/api/v1/bip353/requests/{req_id}")
async def api_cancel_user_request(
    req_id: str,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    cancelled = await cancel_user_request(req_id, key_info.wallet.user)
    if not cancelled:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="No pending request found with that ID.",
        )
    return {"cancelled": True}

def _bip353_exists_in_dns(username: str, domain: str) -> bool:
    """True if {username}@{domain} already resolves as a BIP-353 DNS record."""
    if not domain:
        return False
    try:
        res = bip353_resolve(f"{username}@{domain}")
        return bool(res and res.get("result"))
    except HTTPException as e:
        if e.status_code == HTTPStatus.NOT_FOUND:
            return False
        return True
    except Exception:
        return False

@silnt_api_router.get("/api/v1/bip353/admin/requests")
async def api_admin_list_requests(
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    require_admin(key_info)
    pending = await list_pending_bip353_requests()
    # Enrich each with requester info for easier display
    enriched = []
    for r in pending:
        account = await get_account(r.user_id)
        enriched.append({
            **r.dict(),
            "requester_username": account.username if account else None,
            "requester_email":    account.email    if account else None,
        })
    return {"requests": enriched}


@silnt_api_router.post("/api/v1/bip353/admin/requests/{req_id}/approve")
async def api_admin_approve_request(
    req_id: str,
    data: ApproveBip353Request,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    require_admin(key_info)
    req = await get_bip353_request(req_id)
    if not req:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Request not found.")
    if req.status != "pending":
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Request is already {req.status}.",
        )

    final_username = (data.final_username or req.requested_username).strip().lower()
    if not USERNAME_PATTERN.match(final_username):
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Final username is invalid.",
        )
    if await sp_address_has_approved_bitmail(req.sp_address):
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN,
            detail="This address previously had a BitMail and cannot be assigned "
                   "another. BitMail assignment is permanent per address.",
        )
    _cf_check = await get_cloudflare_config()
    if await is_username_approved_elsewhere(final_username, req_id) or (
        _cf_check and _cf_check.domain
        and _bip353_exists_in_dns(final_username, _cf_check.domain)
    ):
        raise HTTPException(
            status_code=HTTPStatus.CONFLICT,
            detail="That username is already taken (already published).",
        )

   # Verify CF integration is configured
    cf_config = await get_cloudflare_config()
    if not cf_config or not cf_config.api_token or not cf_config.zone_id or not cf_config.domain:
        raise HTTPException(
            status_code=HTTPStatus.PRECONDITION_FAILED,
            detail="Cloudflare integration is not configured. "
                   "Set it up in Settings → Cloudflare first.",
        )

    # 1. Write the Cloudflare TXT record.
    #    ★ Confirm the function name + arg order matches your bip353_cloudflare.py ★
    try:
        await create_bip353_record(
            api_token  = cf_config.api_token,
            zone_id    = cf_config.zone_id,
            domain     = cf_config.domain,
            username   = final_username,
            sp_address = req.sp_address,
        )
    except Exception as e:
        logger.error(f"Cloudflare BIP-353 create failed for {final_username}: {e}")
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail=f"Cloudflare record creation failed: {str(e)}",
        )

    full_address = f"{final_username}@{cf_config.domain}"
    try:
        if req.address_id is None:
            await update_hr_address(req.wallet_id, full_address)         # base address
        else:
            await update_label_hr_address(req.address_id, full_address)  # labeled address
    except Exception as e:
        logger.error(f"hr_address update failed after CF create: {e}")
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Cloudflare record was created but the wallet update failed. "
                   "Contact your administrator.",
        )

    # 3. Mark the request approved
    await update_bip353_request_status(
        req_id         = req_id,
        status         = "approved",
        processed_by   = key_info.wallet.user,
        final_username = final_username,
    )

    return {
        "approved":       True,
        "final_username": final_username,
        "hr_address":     full_address,
    }

@silnt_api_router.post("/api/v1/bip353/admin/requests/{req_id}/reject")
async def api_admin_reject_request(
    req_id: str,
    data: RejectBip353Request,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    require_admin(key_info)
    req = await get_bip353_request(req_id)
    if not req:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Request not found.")
    if req.status != "pending":
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"Request is already {req.status}.",
        )

    await update_bip353_request_status(
        req_id        = req_id,
        status        = "rejected",
        processed_by  = key_info.wallet.user,
        reject_reason = data.reason.strip()[:500],
    )
    return {"rejected": True}

@silnt_api_router.get("/api/v1/bitmail/domain")
async def api_get_bitmail_domain(
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    """
    BitMail domain for display. Read from the existing cloudflare_config.domain.
    No secrets (api_token/zone_id) are returned.
    """
    cf = await get_cloudflare_config()      # your existing getter
    domain = ""
    if cf:
        # cf may be a model or a dict — handle both
        domain = getattr(cf, "domain", None) or (cf.get("domain") if isinstance(cf, dict) else "") or ""
    return {"domain": domain}

@silnt_api_router.post(
    "/api/v1/utxos/restore", dependencies=[Depends(require_trusted_device_admin)]
)
async def api_restore_utxo(data: RestoreUtxoRequest):
    wallet = await get_silnt_wallet(data.wallet_id)
    if not wallet:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Wallet not found.")

    # Find the UTXO and confirm it's unconfirmed_spent
    utxo = await get_utxo(data.wallet_id, data.txid, data.vout)
    if not utxo:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="UTXO not found.")
    if utxo["utxo_state"] != "unconfirmed_spent":
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f"UTXO is '{utxo['utxo_state']}', not 'unconfirmed_spent' — nothing to restore.",
        )

    # Verify the spending tx is actually gone (don't restore a still-pending or
    # confirmed spend — that would corrupt state).
    blindbit = await get_backend_config(wallet.network)
    status = await get_tx_status(
        blindbit.mempool_url or "https://mempool.space", utxo["spent_in_txid"]
    )
    if status is not None and not status.get("unknown"):
        if status.get("confirmed"):
            raise HTTPException(
                status_code=HTTPStatus.CONFLICT,
                detail="The spending transaction has confirmed — this UTXO is genuinely spent.",
            )
        raise HTTPException(
            status_code=HTTPStatus.CONFLICT,
            detail="The spending transaction is still pending in the mempool. "
                   "Wait until it drops before restoring.",
        )
    if status is not None and status.get("unknown"):
        raise HTTPException(
            status_code=HTTPStatus.BAD_GATEWAY,
            detail="Couldn't verify the transaction status right now. Try again shortly.",
        )

    # status is None → tx is gone → safe to restore
    restored = await restore_utxo_to_unspent(data.wallet_id, data.txid, data.vout)
    if restored == 0:
        # Race: state changed between read and write (e.g. a concurrent scan).
        raise HTTPException(
            status_code=HTTPStatus.CONFLICT,
            detail="UTXO state changed before it could be restored. Refresh and try again.",
        )

    # Recompute and persist balance from the now-updated UTXO set
    balance = await get_wallet_unspent_balance(data.wallet_id)
    await update_balance(data.wallet_id, balance)

    return {"restored": True, "txid": data.txid, "vout": data.vout, "balance": balance}

@silnt_api_router.delete("/api/v1/wallet/{wallet_id}/bip353")
async def api_remove_bip353(
    wallet_id: str,
    address_id: Optional[str] = Query(None),   # None = wallet base address; else a labeled address
    key_info: WalletTypeInfo = Depends(require_trusted_device),  # any logged-in user
):
    # 1. Resolve the wallet and ENFORCE OWNERSHIP — the whole security boundary.
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(HTTPStatus.NOT_FOUND, "Wallet not found.")
    if wallet.user != key_info.wallet.user:
        raise HTTPException(HTTPStatus.FORBIDDEN, "Not your wallet.")

    # 2. Resolve which address's BitMail we're removing.
    label_addr = None
    if address_id is None:
        hr = (wallet.hr_address or "").strip()
    else:
        label_addr = await get_wallet_address(address_id)
        if not label_addr or label_addr.wallet_id != wallet_id:
            raise HTTPException(HTTPStatus.BAD_REQUEST, "Labeled address not found on this wallet.")
        hr = (label_addr.hr_address or "").strip()

    if not hr:
        return {"removed": False, "reason": "no BitMail address on this address"}

    # 3. Delete the DNS record (Cloudflare). The DNS-write capability is contained
    #    to the caller's OWN address by the ownership check above.
    cf = await get_cloudflare_config()
    if cf and getattr(cf, "api_token", "") and getattr(cf, "zone_id", ""):
        if "@" in hr:
            uname = hr.split("@", 1)[0]
            try:                
                await delete_bip353_record(cf.api_token, cf.zone_id, cf.domain, uname)
                logger.info(f"Removed BitMail DNS for {hr} (owner {key_info.wallet.user})")
            except Exception as e:
                logger.error(f"BitMail DNS removal failed for {hr}: {e}")
                raise HTTPException(
                    HTTPStatus.BAD_GATEWAY,
                    "Could not remove the BitMail DNS record. Please try again.",
                )
    else:
        logger.warning("Cloudflare not configured; clearing hr_address without DNS delete.")

    # 4. Clear hr_address on the right row. The bip353_requests 'approved' row is
    #    left intact, so address_has_approved_bitmail() keeps the slot burned —
    #    a removed BitMail cannot be re-added to the same address.
    if address_id is None:
        await clear_wallet_hr_address(wallet_id)
    else:
        await clear_label_hr_address(address_id)
    return {"removed": True, "hr_address": hr}

@silnt_api_router.post(
    "/api/v1/account/close", dependencies=[Depends(require_trusted_device)]
)
async def api_close_account(
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    user_id = key_info.wallet.user

    # 1. Best-effort: remove any BitMail DNS records this user's wallets own, so
    #    we don't leave dangling TXT records pointing at deleted wallets.    
    try:
        cf = await get_cloudflare_config()
        if cf and getattr(cf, "api_token", "") and getattr(cf, "zone_id", ""):
            hr_addresses = await get_user_hr_addresses(user_id)
            for hr in hr_addresses:
                if "@" in hr:
                    uname = hr.split("@", 1)[0]
                    try:                        
                        await delete_bip353_record(cf.api_token, cf.zone_id, cf.domain, uname)
                        logger.info(f"Removed BitMail DNS for {hr} during account close")
                    except Exception as e:
                        logger.warning(f"Could not remove BitMail DNS for {hr}: {e}")
    except Exception as e:
        logger.warning(f"BitMail cleanup skipped during account close: {e}")

    # 2. Delete all siLNt data for this user
    deleted_wallet_ids = []
    try:
        stats = await delete_all_silnt_data_for_user(user_id)
        deleted_wallet_ids = stats.get("wallet_ids", [])
        logger.info(f"Deleted siLNt data for user {user_id}: {stats}")
    except Exception as e:
        logger.error(f"Failed to delete siLNt data for {user_id}: {e}")
        raise HTTPException(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "Could not remove wallet data. Account not closed — please try again.",
        )

    # 3. Delete the LNbits account itself (removes the user, their wallets, keys)
    try:
        await delete_account(user_id)        # delete_account(account_id) — user_id IS the account id
        logger.info(f"LNbits account deleted: {user_id}")
    except Exception as e:
        logger.error(f"Failed to delete LNbits account {user_id}: {e}")
        raise HTTPException(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "Wallet data was removed but the account could not be fully deleted. "
            "Please contact the administrator.",
        )

    return {"closed": True, "wallet_ids": deleted_wallet_ids}

@silnt_api_router.get(
    "/api/v1/fees/recommended", dependencies=[Depends(require_trusted_device)]
)
async def api_recommended_fees(network: str = Query(DEFAULT_CONFIG_NETWORK)):
    """Recommended fee tiers (sat/vB) for the configured network."""
    return await get_recommended_fees(network)

@silnt_api_router.get(
    "/api/v1/rate/usd", dependencies=[Depends(require_trusted_device)]
)
async def api_btc_usd_rate():
    """BTC/USD rate for the unit toggle. {'rate': <float>} (0 if unavailable)."""
    return {"rate": await get_btc_usd_rate()}

@silnt_api_router.get("/api/v1/tx/{txid}/confirmation")
async def api_tx_confirmation(
    txid: str,
    wallet_id: str,
    key_info: WalletTypeInfo = Depends(require_admin_key),
):
    """
    Check whether an outgoing send tx has confirmed. If confirmed, transition the
    wallet's spent inputs from 'unconfirmed_spent' to 'spent' and refresh balance.
    Lightweight: one mempool/esplora lookup for this txid — NOT a scan.
    Returns {confirmed: bool, block_height: int|None, balance: int}.
    """
    # Ownership: only let a wallet query a tx it actually sent.
    wallet = await get_silnt_wallet(wallet_id)
    if not wallet:
        raise HTTPException(HTTPStatus.NOT_FOUND, "Wallet not found.")
    # (Add your usual user/wallet ownership check here, matching other endpoints.)

    cfg = await get_backend_config(wallet.network)
    mempool = (cfg.mempool_url or "").rstrip("/")
    if not mempool:
        raise HTTPException(HTTPStatus.SERVICE_UNAVAILABLE, "Mempool URL not configured.")

    confirmed = False
    block_height = None
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.get(f"{mempool}/api/tx/{txid}/status")
        if r.status_code == 200:
            st = r.json()
            confirmed = bool(st.get("confirmed"))
            block_height = st.get("block_height")

    if confirmed:
        # Finalize: unconfirmed_spent -> spent for this tx's inputs in this wallet.
        await mark_utxos_confirmed_spent_by_tx(wallet_id, txid)
        # Recompute balance from unspent UTXOs and persist it.
        new_balance = await get_wallet_unspent_balance(wallet_id)
        await update_balance(wallet_id, new_balance)
    else:
        new_balance = await get_wallet_unspent_balance(wallet_id)

    return {"confirmed": confirmed, "block_height": block_height, "balance": new_balance}


@silnt_api_router.get("/api/v1/admin/blindbit/health")
async def api_blindbit_health(
    network: str = Query("signet"),
    key_info: WalletTypeInfo = Depends(require_admin_key),
):
    """
    Health = BlindBit reachable AND in sync with the chain tip (mempool/esplora).
    Comparing heights is robust to bursty block production (mainnet can go hours
    with no block); a real stall shows up as BlindBit falling behind the tip.
    Returns up/down + whether the heights diverge (+ the heights only when they do).
    """
    blindbit = await get_backend_config(network)
    bb_url = (blindbit.blindbit_url or "").rstrip("/")
    mp_url = (blindbit.mempool_url or "").rstrip("/")
    if not bb_url:
        return {"ok": False, "in_sync": False, "error": "BlindBit Oracle URL not configured.",
                "blindbit_height": None, "tip_height": None, "behind_by": None, "latency_ms": None}

    started = _time.monotonic()
    # 1) BlindBit height (the thing we're checking)
    try:
        async with httpx.AsyncClient(timeout=8.0, verify=False) as c:
            r = await c.get(f"{bb_url}/info")
        latency_ms = int((_time.monotonic() - started) * 1000)
        if r.status_code != 200:
            await notify_service_health_change("BlindBit Oracle", False, f"HTTP {r.status_code}")
            return {"ok": False, "in_sync": False, "error": f"Oracle returned HTTP {r.status_code}.",
                    "blindbit_height": None, "tip_height": None, "behind_by": None, "latency_ms": latency_ms}
        bb_height = int(r.json().get("height"))
    except Exception as exc:
        latency_ms = int((_time.monotonic() - started) * 1000)
        await notify_service_health_change("BlindBit Oracle", False, str(exc)[:120])
        return {"ok": False, "in_sync": False, "error": str(exc)[:200],
                "blindbit_height": None, "tip_height": None, "behind_by": None, "latency_ms": latency_ms}

    # 2) Chain tip from mempool/esplora (the reference). If we can't get it, we
    #    can still report BlindBit is UP, just can't assess sync.
    tip_height = None
    if mp_url:
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as c:
                rt = await c.get(f"{mp_url}/api/blocks/tip/height")
            if rt.status_code == 200:
                tip_height = int(rt.text.strip())
        except Exception:
            tip_height = None

    if tip_height is None:
        await notify_service_health_change("BlindBit Oracle", True)
        # BlindBit is up but we couldn't fetch the tip to compare.
        return {"ok": True, "in_sync": None, "error": "Could not fetch chain tip to compare.",
                "blindbit_height": bb_height, "tip_height": None, "behind_by": None, "latency_ms": latency_ms}

    behind_by = tip_height - bb_height           # positive = BlindBit is behind
    in_sync = behind_by <= BLINDBIT_SYNC_TOLERANCE   # ahead or within tolerance = healthy
    await notify_service_health_change("BlindBit Oracle", True)
    return {
        "ok": True,
        "in_sync": in_sync,
        "error": None,
        "blindbit_height": bb_height,
        "tip_height": tip_height,
        "behind_by": behind_by,
        "latency_ms": latency_ms,
    }

@silnt_api_router.get("/api/v1/bip353/admin/requests/history")
async def api_admin_request_history(
    limit: int = 13,
    offset: int = 0,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    require_admin(key_info)
    reqs = await list_all_bip353_requests(limit=limit, offset=offset)
    enriched = []
    for r in reqs:
        account = await get_account(r.user_id)
        enriched.append({
            **r.dict(),
            "requester_username": account.username if account else None,
            "requester_email":    account.email    if account else None,
        })
    return {"requests": enriched}


@silnt_api_router.delete("/api/v1/bip353/admin/requests/{req_id}")
async def api_admin_purge_request(
    req_id: str,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    require_admin(key_info)
    deleted = await delete_bip353_request_if_terminal(req_id)
    if not deleted:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Only rejected or cancelled requests can be purged.",
        )
    return {"purged": True, "id": req_id}


@silnt_api_router.post("/api/v1/bip353/admin/requests/purge-terminal")
async def api_admin_purge_terminal(
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    require_admin(key_info)
    count = await delete_terminal_bip353_requests()
    return {"purged": count}

# ── fulcrum config (host/port for SYNC) ───────────────────────────────────────
# Sync uses Fulcrum; broadcast uses mempool (reused). Pull Fulcrum host/port from
# blindbit config — add fields there, or hardcode per-instance for now.
async def _fulcrum_cfg(network: str):
    cfg = await get_backend_config(network)
    return (
        getattr(cfg, "fulcrum_host", "127.0.0.1"),
        int(getattr(cfg, "fulcrum_port", 50001)),
        bool(getattr(cfg, "fulcrum_tls", False)),
        network,
    )


async def _broadcast_via_mempool(tx_hex: str, network: str) -> str:
    """Reuse siLNt's mempool broadcast path (same as /api/v1/tx/broadcast)."""
    blindbit = await get_backend_config(network)
    base = (blindbit.mempool_url or "https://mempool.space").rstrip("/")
    url = f"{base}/api/tx"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, content=tx_hex, headers={"Content-Type": "text/plain"})
        if resp.status_code != 200:
            raise HTTPException(status_code=HTTPStatus.BAD_GATEWAY,
                                detail=f"Broadcast failed: {resp.text}")
        return resp.text.strip()

# ── descriptors ───────────────────────────────────────────────────────────────
@silnt_api_router.post("/api/v1/payjoin/descriptors")
async def api_payjoin_import_descriptor(
    data: ImportDescriptorData,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    network = data.network
    try:
        d = await create_payjoin_descriptor(
            user_id=key_info.wallet.user, descriptor=data.descriptor,
            network=network, label=data.label,
        )
    except ValueError as e:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(e))
    return d.dict()


@silnt_api_router.get("/api/v1/payjoin/descriptors")
async def api_payjoin_list_descriptors(
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    rows = await list_payjoin_descriptors(key_info.wallet.user)
    return [r.dict() for r in rows]


@silnt_api_router.delete("/api/v1/payjoin/descriptors/{did}")
async def api_payjoin_delete_descriptor(
    did: str, key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    d = await get_payjoin_descriptor(did)
    if not d or d.user_id != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not found.")
    await delete_payjoin_descriptor(did, key_info.wallet.user)
    return {"deleted": True}


@silnt_api_router.get("/api/v1/payjoin/descriptors/{did}/utxos")
async def api_payjoin_utxos(
    did: str, key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    d = await get_payjoin_descriptor(did)
    if not d or d.user_id != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not found.")
    host, port, tls, network = await _fulcrum_cfg(d.network)
    try:
        res = sync_wallet(d.descriptor, network, host, port, use_tls=tls)
    except Exception as e:
        logger.warning(f"payjoin sync failed: {e}")
        raise HTTPException(status_code=HTTPStatus.BAD_GATEWAY,
                            detail=f"Fulcrum sync failed: {e}")
    reserved = await get_reserved_outpoints(key_info.wallet.user)
    utxos_out = []
    for u in res.utxos:
        d2 = dict(u.__dict__)
        d2["reserved"] = f"{u.txid}:{u.vout}" in reserved
        d2["unconfirmed"] = int(getattr(u, "height", 0) or 0) <= 0
        utxos_out.append(d2)
    return {
        "confirmed_sats": res.confirmed_sats,
        "unconfirmed_sats": res.unconfirmed_sats,
        "utxos": utxos_out,
    }


# ── propose (sender) ──────────────────────────────────────────────────────────
@silnt_api_router.post("/api/v1/payjoin/contacts")
async def api_payjoin_contact_request(
    data: CreateContactData,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    uid = key_info.wallet.user
    username = (data.username or "").strip().lower()
    if not username:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Enter a username.")

    target = await get_account_by_username(username)
    target_id = target.id if target else None

    # Clear error if you enter your OWN username (harmless self-oracle — you know
    # your own handle). Otherwise stay neutral (no username-existence oracle).
    me = await get_account(uid)
    if me and me.username and me.username.strip().lower() == username:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST,
                            detail="That's your own username — connect with someone else.")

    if target_id and target_id != uid:
        await create_payjoin_contact(uid, target_id)
    return {"status": "sent"}


@silnt_api_router.get("/api/v1/payjoin/contacts")
async def api_payjoin_contacts(
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    """All of my connections: accepted, incoming pending, outgoing pending.
    Usernames + this user's private labels resolved here (never stored together)."""
    uid = key_info.wallet.user
    res = await list_payjoin_contacts(uid)
    labels = await get_payjoin_contact_labels(uid)
    cache = {}
    async def uname(u):
        if u not in cache:
            acct = await get_account(u)
            cache[u] = (acct.username if acct and acct.username else u)
        return cache[u]
    for group in res.values():
        for d in group:
            d["counterparty_username"] = await uname(d["counterparty_user_id"])
            d["label"] = labels.get(d["id"], "")
    return res


@silnt_api_router.post("/api/v1/payjoin/contacts/{cid}/approve")
async def api_payjoin_contact_approve(
    cid: str, key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    """The TARGET of a pending request approves it -> ACCEPTED (mutual)."""
    c = await get_payjoin_contact(cid)
    if not c or c.target_user_id != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Request not found.")
    if c.status != "PENDING":
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Not pending.")
    await set_payjoin_contact_status(cid, "ACCEPTED")
    return {"status": "ACCEPTED"}


@silnt_api_router.post("/api/v1/payjoin/contacts/{cid}/decline")
async def api_payjoin_contact_decline(
    cid: str, key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    """The TARGET declines a pending request -> status DECLINED (kept so the
    requester sees the outcome; they dismiss it to remove)."""
    c = await get_payjoin_contact(cid)
    if not c or c.target_user_id != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Request not found.")
    if c.status != "PENDING":
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Not pending.")
    await set_payjoin_contact_status(cid, "DECLINED")
    return {"status": "DECLINED"}


@silnt_api_router.delete("/api/v1/payjoin/contacts/{cid}")
async def api_payjoin_contact_remove(
    cid: str, key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    """Either party removes the connection (pending or accepted)."""
    c = await get_payjoin_contact(cid)
    uid = key_info.wallet.user
    if not c or uid not in (c.requester_user_id, c.target_user_id):
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not found.")
    await delete_payjoin_contact(cid)
    return {"status": "REMOVED"}


@silnt_api_router.post("/api/v1/payjoin/contacts/{cid}/label")
async def api_payjoin_contact_label(
    cid: str, data: ContactLabelData,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    """Set/clear this user's PRIVATE label for a connection (only they see it)."""
    c = await get_payjoin_contact(cid)
    uid = key_info.wallet.user
    if not c or uid not in (c.requester_user_id, c.target_user_id):
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Not found.")
    await set_payjoin_contact_label(cid, uid, data.label or "")
    return {"status": "ok"}


@silnt_api_router.get("/api/v1/payjoin/payers")
async def api_payjoin_payers(
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    """My connected counterparties, for the invoice payer-picker. Only ACCEPTED
    connections. Includes this user's private label (shown if set)."""
    uid = key_info.wallet.user
    pairs = await list_accepted_contacts_with_ids(uid)
    labels = await get_payjoin_contact_labels(uid)
    payers = []
    for p in pairs:
        acct = await get_account(p["user_id"])
        if acct and acct.username:
            payers.append({
                "user_id": p["user_id"], "username": acct.username,
                "label": labels.get(p["contact_id"], ""),
            })
    payers.sort(key=lambda x: (x["label"] or x["username"]).lower())
    return {"payers": payers}


@silnt_api_router.post("/api/v1/payjoin/invoices")
async def api_payjoin_create_invoice(
    data: CreateInvoiceData,
    key_info: WalletTypeInfo = Depends(require_trusted_device_admin),
):
    """A (payee) creates a directed invoice for payer B. A picks their receiving
    wallet + one contributed input + B (from the dropdown) + amount/memo."""
    payee_uid = key_info.wallet.user

    # A's receiving wallet
    rd = await get_payjoin_descriptor(data.receiver_descriptor_id)
    if not rd or rd.user_id != payee_uid:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Your wallet not found.")

    # resolve payer B
    payer = await get_account_by_username(data.payer_username)
    if not payer:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Payer username not found.")
    if payer.id == payee_uid:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="You can't invoice yourself.")

    # payer must be an accepted connection (consent-based; no invoicing strangers)
    connected = await list_accepted_contact_user_ids(payee_uid)
    if payer.id not in set(connected):
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN,
                            detail="You can only invoice a connected user. Send a connection request first.")

    # A's contributed input must not already be reserved
    reserved = await get_reserved_outpoints(payee_uid)
    ri = data.receiver_input
    if f"{ri['txid']}:{ri['vout']}" in reserved:
        raise HTTPException(status_code=HTTPStatus.CONFLICT,
                            detail="That input is already reserved by another pending PayJoin.")

    # A's payment address at next-unused receive index (avoid reuse)
    host, port, tls, network = await _fulcrum_cfg(rd.network)
    try:
        pay_index = next_unused_receive_index(rd.descriptor, network, host, port, use_tls=tls)
    except Exception as e:
        logger.warning(f"payjoin: next-index sync failed, using 0: {e}")
        pay_index = 0
    payment_address = derive_descriptor_address(rd.descriptor, network, 0, pay_index)

    payee_acct = await get_account(payee_uid)
    payee_username = (payee_acct.username if payee_acct else None) or payee_uid

    inv = await create_payjoin_invoice(
        payee_user_id=payee_uid, payee_username=payee_username,
        payee_descriptor_id=rd.id, payee_input=data.receiver_input,
        payment_address=payment_address,
        payer_user_id=payer.id, payer_username=data.payer_username,
        amount_sats=data.amount_sats, fee_rate=data.fee_rate, memo=data.memo,
    )
    return inv.dict()


@silnt_api_router.get("/api/v1/payjoin/invoices")
async def api_payjoin_invoices(
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    """Open invoices directed to me (to pay)."""
    uid = key_info.wallet.user
    payable = await list_payjoin_invoices_for_payer(uid)
    return {"payable": [r.dict() for r in payable]}


@silnt_api_router.post("/api/v1/payjoin/invoices/{rid}/pay")
async def api_payjoin_pay_invoice(
    rid: str, data: PayInvoiceData,
    key_info: WalletTypeInfo = Depends(require_trusted_device_admin),
):
    """B (payer) pays an OPEN invoice: commits wallet + inputs. siLNt builds the
    merged PSBT (B's inputs + A's pre-chosen input) and moves to CLAIMED. Both
    then sign the same unsigned PSBT."""
    req = await get_payjoin_request(rid)
    if not req or req.sender_user_id != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Invoice not found.")
    if req.status != "OPEN":
        raise HTTPException(status_code=HTTPStatus.CONFLICT,
                            detail=f"Invoice is no longer open (state {req.status}).")

    # B's wallet
    sd = await get_payjoin_descriptor(data.sender_descriptor_id)
    if not sd or sd.user_id != key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Your wallet not found.")

    # B's inputs must not be reserved
    reserved = await get_reserved_outpoints(key_info.wallet.user)
    clash = [f"{u['txid']}:{u['vout']}" for u in data.sender_inputs
             if f"{u['txid']}:{u['vout']}" in reserved]
    if clash:
        raise HTTPException(status_code=HTTPStatus.CONFLICT,
                            detail="Some of your selected inputs are already reserved.")

    # A's wallet + pre-chosen input (stored at invoice creation)
    rd = await get_payjoin_descriptor(req.receiver_descriptor_id)
    if not rd:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Payee wallet missing.")
    payee_input = json.loads(req.receiver_input)

    host, port, tls, network = await _fulcrum_cfg(rd.network)
    try:
        built = build_merged_payjoin(
            sender_descriptor=sd.descriptor,           # payer B
            sender_inputs=data.sender_inputs,
            receiver_descriptor=rd.descriptor,         # payee A
            receiver_input=payee_input,
            network=network,
            destination=req.payment_address,           # A's address
            amount=req.amount_sats,
            fee_rate=req.fee_rate,
        )
    except Exception as e:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=f"Build failed: {e}")

    await update_payjoin_request(
        rid, status="CLAIMED",
        sender_descriptor_id=sd.id,
        sender_inputs=json.dumps(data.sender_inputs),
        fee_sats=built["fee"],
        unsigned_psbt=built["psbt_base64"],
    )
    return {"status": "CLAIMED", "unsigned_psbt": built["psbt_base64"]}


# ── list requests ─────────────────────────────────────────────────────────────
@silnt_api_router.get("/api/v1/payjoin/requests")
async def api_payjoin_requests(
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    uid = key_info.wallet.user
    incoming = await list_payjoin_requests_for_receiver(uid)
    outgoing = await list_payjoin_requests_for_sender(uid)
    try:
        blindbit = await get_backend_config(DEFAULT_CONFIG_NETWORK)
        mempool_base = blindbit.mempool_url or "https://mempool.space"
        seen = set()
        for r in [*incoming, *outgoing]:
            if r.status == "BROADCAST" and r.txid and r.id not in seen:
                seen.add(r.id)
                try:
                    st = await get_tx_status(mempool_base, r.txid)
                    if st and st.get("confirmed"):
                        await update_payjoin_request(r.id, status="CONFIRMED")
                        r.status = "CONFIRMED"
                except Exception:
                    pass  # explorer hiccup — leave as BROADCAST, retry next fetch
    except Exception:
        pass  # config/explorer unavailable — non-fatal, statuses unchanged
    return {
        "incoming": [r.dict() for r in incoming],
        "outgoing": [r.dict() for r in outgoing],
    }


@silnt_api_router.get("/api/v1/payjoin/requests/{rid}/unsigned")
async def api_payjoin_unsigned(
    rid: str, key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    req = await get_payjoin_request(rid)
    uid = key_info.wallet.user
    if not req or uid not in (req.sender_user_id, req.receiver_user_id):
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Request not found.")
    if not req.unsigned_psbt:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST,
                            detail="No unsigned PSBT yet — invoice not paid.")
    return {"status": req.status, "unsigned_psbt": req.unsigned_psbt}


# ── either party submits their signed copy; broadcast when BOTH present ───────
@silnt_api_router.post("/api/v1/payjoin/requests/{rid}/sign")
async def api_payjoin_sign(
    rid: str, data: SignPayjoinData,
    key_info: WalletTypeInfo = Depends(require_trusted_device_admin),
):
    req = await get_payjoin_request(rid)
    uid = key_info.wallet.user
    if not req or uid not in (req.sender_user_id, req.receiver_user_id):
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Request not found.")
    if req.status != "CLAIMED":
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST,
                            detail=f"Cannot sign in state {req.status}.")

    # store this party's signed copy in their slot (payee=receiver, payer=sender)
    if uid == req.receiver_user_id:
        await update_payjoin_request(rid, receiver_signed_psbt=data.signed_psbt)
    else:
        await update_payjoin_request(rid, sender_signed_psbt=data.signed_psbt)

    req = await get_payjoin_request(rid)
    # still waiting on the other party?
    if not (req.receiver_signed_psbt and req.sender_signed_psbt):
        return {"status": "CLAIMED", "waiting_for_other": True}

    # both present → combine + broadcast
    try:
        result = combine_and_finalize([req.receiver_signed_psbt, req.sender_signed_psbt])
    except Exception as e:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=f"Combine failed: {e}")
    if not result["finalized"]:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST,
                            detail=f"Not fully signed: {result.get('finalize_error')}")

    tx_hex = result["tx_hex"]    
    _sd = await get_payjoin_descriptor(req.sender_descriptor_id)
    _net = _sd.network if _sd else "signet"
    try:
        txid = await _broadcast_via_mempool(tx_hex, _net)
    except HTTPException:
        await update_payjoin_request(rid, tx_hex=tx_hex)
        raise
    except Exception as e:
        await update_payjoin_request(rid, tx_hex=tx_hex)
        raise HTTPException(status_code=HTTPStatus.BAD_GATEWAY, detail=f"Broadcast failed: {e}")

    await update_payjoin_request(rid, status="BROADCAST", tx_hex=tx_hex, txid=txid)
    return {"status": "BROADCAST", "txid": txid, "waiting_for_other": False}


# ── cancel (payee cancels OPEN invoice) / abandon (payer backs out) ──────────
@silnt_api_router.post("/api/v1/payjoin/requests/{rid}/cancel")
async def api_payjoin_cancel(
    rid: str, key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    req = await get_payjoin_request(rid)
    uid = key_info.wallet.user
    if not req or uid not in (req.sender_user_id, req.receiver_user_id):
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Request not found.")
    if req.status in ("BROADCAST", "CANCELLED"):
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Already terminal.")
    who = "payee" if uid == req.receiver_user_id else "payer"
    await update_payjoin_request(rid, status="CANCELLED", reject_reason=f"cancelled by {who}")
    return {"status": "CANCELLED"}


@silnt_api_router.get("/api/v1/admin/fulcrum/health")
async def api_fulcrum_health(
    network: str = Query("signet"),
    key_info: WalletTypeInfo = Depends(require_admin_key),
):
    """
    Health = Fulcrum reachable AND in sync with the chain tip (mempool/esplora).
    Mirrors the BlindBit health check. Returns up/down + whether heights diverge.
    """    
    cfg = await get_backend_config(network)
    host = getattr(cfg, "fulcrum_host", "") or ""
    port = int(getattr(cfg, "fulcrum_port", 50003) or 50003)
    tls = bool(getattr(cfg, "fulcrum_tls", False))
    mp_url = (getattr(cfg, "mempool_url", "") or "").rstrip("/")

    if not host:
        await notify_service_health_change("Fulcrum", False, "Fulcrum host not configured.")
        return {"ok": False, "in_sync": False, "error": "Fulcrum host not configured.",
                "fulcrum_height": None, "tip_height": None, "behind_by": None, "latency_ms": None}

    started = _time.monotonic()
    try:
        c = ElectrumClient(host, port, use_tls=tls)
        c.connect()
        ver = c.server_version()
        fh = c.server_height()
        c.close()
        latency_ms = int((_time.monotonic() - started) * 1000)
    except Exception as exc:
        latency_ms = int((_time.monotonic() - started) * 1000)
        await notify_service_health_change("Fulcrum", False, str(exc)[:120])
        return {"ok": False, "in_sync": False, "error": str(exc)[:200],
                "fulcrum_height": None, "tip_height": None, "behind_by": None,
                "latency_ms": latency_ms}
    try:
        fh_int = int(fh)
    except (TypeError, ValueError):
        fh_int = 0
    if not fh_int or fh_int <= 0:
        await notify_service_health_change("Fulcrum", False, "No block height returned.")
        return {"ok": False, "in_sync": False, "error": "Fulcrum returned no block height.",
                "fulcrum_height": fh, "tip_height": None, "behind_by": None,
                "latency_ms": latency_ms}
    fh = fh_int

    # chain tip from mempool/esplora for the sync comparison
    tip_height = None
    if mp_url:
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
                rt = await client.get(f"{mp_url}/api/blocks/tip/height")
            if rt.status_code == 200:
                tip_height = int(rt.text.strip())
        except Exception:
            tip_height = None

    if tip_height is None:
        await notify_service_health_change("Fulcrum", True)
        return {"ok": True, "in_sync": None, "error": "Could not fetch chain tip to compare.",
                "fulcrum_height": fh, "tip_height": None, "behind_by": None,
                "latency_ms": latency_ms, "server_version": ver}

    behind_by = tip_height - fh
    in_sync = behind_by <= FULCRUM_SYNC_TOLERANCE
    await notify_service_health_change("Fulcrum", True)
    return {
        "ok": True, "in_sync": in_sync, "error": None,
        "fulcrum_height": fh, "tip_height": tip_height, "behind_by": behind_by,
        "latency_ms": latency_ms, "server_version": ver,
    }

# ── SP send contacts (per-user private address book) ──────────────────────────
@silnt_api_router.get("/api/v1/contacts")
async def api_sp_contacts_list(
    network: Optional[str] = Query(None),
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    # The address book is per-network; require it explicitly so a mainnet build
    # can't be served a signet account's contacts (and vice versa).
    if not network:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="A `network` query parameter is required (e.g. ?network=mainnet).",
        )
    rows = await list_sp_contacts(key_info.wallet.user, network)
    return {"contacts": [c.dict() for c in rows]}


@silnt_api_router.post("/api/v1/contacts")
async def api_sp_contacts_create(
    data: CreateSpContactData,
    network: Optional[str] = Query(None),
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    if not network:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="A `network` query parameter is required (e.g. ?network=mainnet).",
        )
    value = (data.value or "").strip()
    if not value:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Recipient is required.")
    if "@" in value:
        user, _, domain = value.partition("@")
        if not user or not domain or "." not in domain:
            raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Invalid BitMail name.")
    elif not (value.startswith("sp1") or value.startswith("tsp1")):
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="Recipient must be a BitMail name (name@domain) or an SP address (sp1…/tsp1…).",
        )
    try:
        c = await create_sp_contact(key_info.wallet.user, data.label, value, network)
    except ValueError as e:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(e))
    return c.dict()

@silnt_api_router.patch("/api/v1/contacts/{cid}")
async def api_sp_contacts_update(
    cid: str,
    data: UpdateSpContactData,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    try:
        await update_sp_contact_label(cid, key_info.wallet.user, data.label)
    except ValueError as e:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(e))
    return {"ok": True}


@silnt_api_router.delete("/api/v1/contacts/{cid}")
async def api_sp_contacts_delete(
    cid: str,
    key_info: WalletTypeInfo = Depends(require_trusted_device),
):
    await delete_sp_contact(cid, key_info.wallet.user)
    return {"ok": True}

# ── Admin: delete a user account ──────────────────────────────────────────────
async def _resolve_account(identifier: str):
    """Resolve a username-or-email to (user_id, username). (None, None) if not found."""
    ident = (identifier or "").strip()
    if not ident:
        return (None, None)
    try:
        acct = await get_account_by_username(ident)
        if acct:
            return (acct.id, getattr(acct, "username", None) or ident)
    except Exception:
        pass
    if "@" in ident:
        uid, uname = await get_account_id_by_email(ident)
        if uid:
            return (uid, uname or ident)
    return (None, None)


@silnt_api_router.get(
    "/api/v1/admin/account/lookup",
    dependencies=[Depends(require_trusted_device_admin)],
)
async def api_admin_account_lookup(
    identifier: str,
    key_info: WalletTypeInfo = Depends(require_trusted_device_admin),
):
    require_admin(key_info)
    user_id, username = await _resolve_account(identifier)
    if not user_id:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="No such account.")
    wallets = await get_silnt_wallets(user_id)
    hr_addresses = await get_user_hr_addresses(user_id)
    return {
        "user_id": user_id,
        "username": username,
        "wallet_count": len(wallets),
        "bitmail_addresses": hr_addresses,
        "is_self": user_id == key_info.wallet.user,
    }


@silnt_api_router.post(
    "/api/v1/admin/account/delete",
    dependencies=[Depends(require_trusted_device_admin)],
)
async def api_admin_account_delete(
    data: AdminDeleteAccountData,
    key_info: WalletTypeInfo = Depends(require_trusted_device_admin),
):
    require_admin(key_info)
    user_id, username = await _resolve_account(data.identifier)
    if not user_id:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="No such account.")
    if (data.confirm_username or "").strip() != (username or ""):
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST,
                            detail="Confirmation does not match the account username.")
    if user_id == key_info.wallet.user:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST,
                            detail="You can't delete your own admin account from here.")
    try:
        if user_id == getattr(lnbits_settings, "super_user", None):
            raise HTTPException(status_code=HTTPStatus.BAD_REQUEST,
                                detail="The superuser account can't be deleted.")
    except HTTPException:
        raise
    except Exception:
        pass
    if data.delete_bitmail:
        try:
            cf = await get_cloudflare_config()
            if cf and getattr(cf, "api_token", "") and getattr(cf, "zone_id", ""):
                for hr in await get_user_hr_addresses(user_id):
                    if "@" in hr:
                        try:
                            await delete_bip353_record(cf.api_token, cf.zone_id, cf.domain, hr.split("@", 1)[0])
                        except Exception as e:
                            logger.warning(f"admin delete: BitMail DNS cleanup failed for {hr}: {e}")
        except Exception as e:
            logger.warning(f"admin delete: BitMail cleanup skipped: {e}")
    try:
        stats = await delete_all_silnt_data_for_user(user_id)
    except Exception as e:
        logger.error(f"admin delete: siLNt data removal failed for {user_id}: {e}")
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                            detail="Could not remove the user's wallet data. Account not deleted.")
    try:
        await delete_account(user_id)
    except Exception as e:
        logger.error(f"admin delete: LNbits account removal failed for {user_id}: {e}")
        raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                            detail="Wallet data removed, but the account could not be fully deleted.")
    logger.info(f"admin {key_info.wallet.user} deleted account {user_id} ({username}): {stats}")
    return {"deleted": True, "username": username, "wallet_ids": stats.get("wallet_ids", [])}

# ── Admin: delete a user account ──────────────────────────────────────────────
@silnt_api_router.get(
    "/api/v1/admin/accounts",
    dependencies=[Depends(require_trusted_device_admin)],
)
async def api_admin_accounts_list(
    network: str = Query("signet"),
    key_info: WalletTypeInfo = Depends(require_trusted_device_admin),
):
    require_admin(key_info)
    out = []
    for uid in await list_silnt_user_ids_for_network(network):
        acct = await get_account(uid)
        # Skip orphaned references: siLNt rows whose LNbits account no longer
        # exists (deleted user leaving stale device/descriptor rows).
        if not acct:
            continue
        # get_account may return an object or a mapping depending on LNbits
        # version — read defensively so an odd shape can't 500 the page.
        uname = getattr(acct, "username", None)
        email = getattr(acct, "email", None)
        if uname is None and isinstance(acct, dict):
            uname = acct.get("username")
            email = acct.get("email")
        wallets = await get_silnt_wallets(uid, network)
        out.append({
            "user_id": uid,
            "username": uname or uid,
            "email": email or "",
            "wallet_count": len(wallets),
            "bitmail_addresses": await get_user_hr_addresses(uid),
            "is_self": uid == key_info.wallet.user,
        })
    out.sort(key=lambda a: (a["username"] or "").lower())
    return {"accounts": out}

# ── Ntfy notifications config (admin only) ───────────────────────────────────
@silnt_api_router.get("/api/v1/ntfy/config")
async def api_get_ntfy_config(
    key_info: WalletTypeInfo = Depends(require_trusted_device_admin),
) -> NtfyConfig:
    require_admin(key_info)
    return await get_ntfy_config()


@silnt_api_router.put("/api/v1/ntfy/config")
async def api_update_ntfy_config(
    data: NtfyConfig,
    key_info: WalletTypeInfo = Depends(require_trusted_device_admin),
) -> NtfyConfig:
    require_admin(key_info)
    # Normalize: trim server URL, clean the topic list, validate priority.
    data.server_url = (data.server_url or "https://ntfy.bitaurus.net").strip().rstrip("/")
    data.topics = [t.strip() for t in (data.topics or []) if t and t.strip()]
    if data.priority not in ("min", "low", "default", "high", "urgent"):
        data.priority = "default"
    if data.enabled and (not data.server_url or not data.topics):
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="A server URL and at least one topic are required to enable ntfy.",
        )
    return await update_ntfy_config(data)


@silnt_api_router.post("/api/v1/ntfy/test")
async def api_test_ntfy(
    key_info: WalletTypeInfo = Depends(require_trusted_device_admin),
):
    require_admin(key_info)
    cfg = await get_ntfy_config()
    if not cfg.enabled:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Ntfy is disabled.")
    result = await send_ntfy_notification(
        title="siLNt test notification",
        message="If you can read this, ntfy notifications are working.",
        tags=["white_check_mark"],
    )
    if not result.get("sent"):
        raise HTTPException(
            status_code=HTTPStatus.BAD_GATEWAY,
            detail=f"No notifications delivered. {result.get('errors') or result.get('skipped') or ''}",
        )
    return result

# ── Admin alerts (e.g. BitMail tampering) ────────────────────────────────────
@silnt_api_router.get("/api/v1/admin/alerts")
async def api_admin_alerts_list(
    include_acknowledged: bool = False,
    key_info: WalletTypeInfo = Depends(require_trusted_device_admin),
):
    require_admin(key_info)
    alerts = await list_admin_alerts(include_acknowledged=include_acknowledged)
    return {
        "alerts": [a.dict() for a in alerts],
        "open_count": await count_open_admin_alerts(),
    }


@silnt_api_router.post("/api/v1/admin/alerts/{alert_id}/ack")
async def api_admin_alert_ack(
    alert_id: str,
    key_info: WalletTypeInfo = Depends(require_trusted_device_admin),
):
    require_admin(key_info)
    ok = await acknowledge_admin_alert(alert_id)
    if not ok:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Alert not found.")
    return {"acknowledged": True, "id": alert_id}

_tamper_sweep_lock = asyncio.Lock()


async def _notify_and_mark_tamper(bitmail: str, detail: str) -> None:
    """Send the tamper ntfy once and, on success, mark the open alert notified so
    subsequent sweeps stay quiet. Kept separate so ntfy count tracks alert rows."""
    try:
        _ntfy_res = await send_ntfy_notification(
            title="BitMail tampering detected",
            message=detail,
            tags=["rotating_light"],
            priority="urgent",
        )
        logger.warning(f"tamper sweep: ntfy result for {bitmail}: {_ntfy_res}")
        if _ntfy_res and _ntfy_res.get("sent"):
            await mark_tamper_notified("bitmail_tamper", bitmail)
    except Exception as e:
        logger.warning(f"tamper sweep: ntfy failed for {bitmail}: {e}")

async def run_bitmail_tamper_sweep() -> dict:
    """
    Check EVERY BitMail siLNt issued: resolve its DNS TXT and compare to the SP
    address we recorded. Any mismatch → an admin alert (once, until acknowledged)
    + an urgent ntfy. This detects tampering with any user's BitMail proactively,
    independent of whether anyone is sending to it. Best-effort — never raises.
    Returns a small summary.
    """
    # Prevent overlapping sweeps (scheduled loop + manual endpoint, or a slow
    # run) from racing the check-then-create dedup and producing duplicate
    # alerts/ntfys for the same bitmail. If one is already running, skip — it
    # covers the same BitMails.
    if _tamper_sweep_lock.locked():
        return {"checked": 0, "mismatches": 0, "skipped": "already_running"}
    async with _tamper_sweep_lock:
        return await _run_bitmail_tamper_sweep_inner()

async def _run_bitmail_tamper_sweep_inner() -> dict:
    try:
        cf = await get_cloudflare_config()
        our_domain = (getattr(cf, "domain", "") or "").strip().lower()
    except Exception:
        our_domain = ""
    if not our_domain:
        return {"checked": 0, "mismatches": 0, "skipped": "no_domain"}

    try:
        issued = await list_approved_bitmails()
    except Exception as e:
        logger.error(f"tamper sweep: could not list issued BitMails: {e}")
        return {"checked": 0, "mismatches": 0, "error": str(e)[:120]}

    checked = 0
    mismatches = 0
    for row in issued:
        uname = (row.get("final_username") or "").strip()
        expected = (row.get("sp_address") or "").strip()
        if not uname or not expected:
            continue
        # If the owning wallet has been deleted, this is a stale record left over
        # from a wallet removal. Purge it (request row + any alerts) and skip — a
        # dead wallet must not keep generating tamper checks/alerts. This also
        # self-heals orphans created before delete-time cleanup existed.
        wid = (row.get("wallet_id") or "").strip()
        if wid and not await get_silnt_wallet(wid):
            try:
                await delete_bip353_requests_for_wallet(wid)
                await delete_admin_alerts_for_wallet(wid)
                logger.info(f"tamper sweep: purged stale BitMail records for deleted wallet {wid}")
            except Exception as e:
                logger.warning(f"tamper sweep: could not purge stale records for {wid}: {e}")
            continue
        bitmail = f"{uname}@{our_domain}"
        checked += 1
        try:
            resolved = bip353_resolve(bitmail)
            result = (resolved.get("result", "") or "").replace("bitcoin:?sp=", "").replace("sp=", "").strip()
        except Exception:
            # A resolution failure is not proof of tampering (DNS hiccup, record
            # removed by the owner, etc.) — don't alert on it here.
            continue
        if not result:
            continue
        if result.lower() == expected.lower():
            # Resolves correctly — clear any stale open tamper alert for this
            # bitmail (e.g. the DNS record was corrected after a prior alert).
            try:
                cleared = await resolve_open_alerts_for("bitmail_tamper", bitmail)
                if cleared:
                    logger.warning(f"tamper sweep: cleared {cleared} stale alert(s) for {bitmail} (now matches)")
            except Exception as e:
                logger.warning(f"tamper sweep: could not clear stale alert for {bitmail}: {e}")
            continue
        if result.lower() != expected.lower():
            mismatches += 1
            detail = (
                f"{bitmail} resolves to {result} but siLNt issued it for {expected}. "
                f"The DNS record may have been tampered with to redirect funds."
            )
            # De-dupe on the tamper SIGNATURE (bitmail  rogue address), including
            # acknowledged rows, so dismissing an ongoing tamper doesn't resurrect it.
            if await tamper_signature_alerted(bitmail, result):
                continue
            # No alert yet — create exactly one row, then notify for it.
            try:
                await create_admin_alert(
                    kind="bitmail_tamper",
                    severity="critical",
                    title=f"BitMail tampering: {bitmail}",
                    detail=detail,
                    meta=json.dumps({
                        "bitmail": bitmail,
                        "resolved_sp": result,
                        "expected_sp": expected,
                        "user_id": row.get("user_id"),
                        "wallet_id": row.get("wallet_id"),
                    }),
                )
            except Exception as e:
                logger.error(f"tamper sweep: could not record alert for {bitmail}: {e}")
            await _notify_and_mark_tamper(bitmail, detail)
    return {"checked": checked, "mismatches": mismatches}

async def probe_blindbit_health() -> None:
    """Reachability probe for the BlindBit Oracle, callable from a background
    loop (no auth). Fires the down/up ntfy via notify_service_health_change on a
    state change. Best-effort — never raises."""
    try:
        blindbit = await get_backend_config(DEFAULT_CONFIG_NETWORK)
        bb_url = (blindbit.blindbit_url or "").rstrip("/")
        if not bb_url:
            await notify_service_health_change("BlindBit Oracle", False, "URL not configured.")
            return
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as c:
                r = await c.get(f"{bb_url}/info")
            if r.status_code != 200:
                await notify_service_health_change("BlindBit Oracle", False, f"HTTP {r.status_code}")
                return
            int(r.json().get("height"))          # ensure it's a sane response
            await notify_service_health_change("BlindBit Oracle", True)
        except Exception as exc:
            await notify_service_health_change("BlindBit Oracle", False, str(exc)[:120])
    except Exception as e:
        logger.warning(f"probe_blindbit_health error: {e}")


async def probe_fulcrum_health() -> None:
    """Reachability probe for Fulcrum, callable from a background loop (no auth).
    Fires the down/up ntfy on a state change. Best-effort — never raises."""
    try:
        cfg = await get_backend_config(DEFAULT_CONFIG_NETWORK)
        host = getattr(cfg, "fulcrum_host", "") or ""
        port = int(getattr(cfg, "fulcrum_port", 50001) or 50001)
        tls = bool(getattr(cfg, "fulcrum_tls", False))
        if not host:
            await notify_service_health_change("Fulcrum", False, "Fulcrum host not configured.")
            return
        try:
            c = ElectrumClient(host, port, use_tls=tls)
            c.connect()
            c.server_version()
            fh = c.server_height()
            c.close()
        except Exception as exc:
            await notify_service_health_change("Fulcrum", False, str(exc)[:120])
            return
        try:
            fh_int = int(fh)
        except (TypeError, ValueError):
            fh_int = 0
        if not fh_int or fh_int <= 0:
            await notify_service_health_change("Fulcrum", False, "No block height returned.")
            return
        await notify_service_health_change("Fulcrum", True)
    except Exception as e:
        logger.warning(f"probe_fulcrum_health error: {e}")


async def run_health_probes() -> None:
    """Run both service probes once (for the background monitor loop)."""
    await probe_blindbit_health()
    await probe_fulcrum_health()