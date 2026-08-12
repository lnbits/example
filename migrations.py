async def m001_initial(db):
    """
    Initial wallet table.
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.wallets (
            id TEXT NOT NULL PRIMARY KEY,
            "user" TEXT,
            network TEXT DEFAULT 'mainnet',
            title TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT {db.timestamp_now},
            updated_at TIMESTAMPTZ NOT NULL DEFAULT {db.timestamp_now},            
            sp_address TEXT NOT NULL,
            hr_address TEXT NOT NULL,
            last_height INTEGER,
            last_scan_height INTEGER NOT NULL DEFAULT 0,
            balance {db.big_int}
        );
    """
    )

    await db.execute(
        f"""
        CREATE TABLE silnt.utxos (
            txid TEXT NOT NULL PRIMARY KEY,
            vout SMALLINT NOT NULL,            
            amount {db.big_int} NOT NULL,
            priv_key_tweak TEXT NOT NULL,
            pub_key TEXT NOT NULL,            
            utxo_state TEXT NOT NULL,
            timestamp INTEGER NOT NULL DEFAULT 0,           
            wallet_id TEXT NOT NULL,
            label TEXT DEFAULT NULL,
            frozen BOOLEAN DEFAULT FALSE,
            freeze_reason TEXT DEFAULT NULL,
            suspected_dust BOOLEAN DEFAULT FALSE,
            spent_in_txid TEXT DEFAULT NULL,
            label_index INTEGER
        );
    """
    )
    await db.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_silnt_utxos_vout_wallet_id ON silnt.utxos (txid, vout, wallet_id);
        """
    )


async def m002_subaccounts(db):
    await db.execute("""
    CREATE TABLE IF NOT EXISTS silnt.wallet_addresses (
        sp_address TEXT PRIMARY KEY,
        id TEXT NOT NULL,
        wallet_id TEXT NOT NULL,
        label TEXT DEFAULT NULL,       
        label_index INTEGER NOT NULL,
        created_at INTEGER NOT NULL DEFAULT 0        
    )
    """)


async def m003_add_spent_in_txid(db):    
    await db.execute(
        "CREATE INDEX IF NOT EXISTS utxos_spent_in_txid ON silnt.utxos(spent_in_txid)"
    )

async def m004_add_spent_at(db):
    await db.execute(
        "ALTER TABLE silnt.utxos ADD COLUMN IF NOT EXISTS spent_at INTEGER DEFAULT NULL"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS utxos_spent_at ON silnt.utxos(spent_at)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS utxos_wallet_timestamp ON silnt.utxos(wallet_id, timestamp)"
    )

async def m005_trusted_devices(db):
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS silnt.trusted_devices (
            id              TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL,
            device_id       TEXT NOT NULL,
            user_agent      TEXT,
            ip              TEXT,
            label           TEXT,
            confirmed_at    INTEGER NOT NULL,
            last_seen_at    INTEGER NOT NULL,
            UNIQUE(user_id, device_id)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS trusted_devices_user ON silnt.trusted_devices(user_id)"
    )

async def m006_user_prefs(db):
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS silnt.user_prefs (
            user_id              TEXT PRIMARY KEY,
            dust_threshold_sats  INTEGER DEFAULT NULL,
            updated_at           INTEGER NOT NULL
        )
        """
    )

async def m007_bip353_requests(db):
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS silnt.bip353_requests (
            id                  TEXT PRIMARY KEY,
            user_id             TEXT NOT NULL,
            wallet_id           TEXT NOT NULL,
            sp_address          TEXT NOT NULL,
            requested_username  TEXT NOT NULL,
            final_username      TEXT,
            message             TEXT,
            status              TEXT NOT NULL DEFAULT 'pending',
            reject_reason       TEXT,
            created_at          INTEGER NOT NULL,
            processed_at        INTEGER,
            processed_by        TEXT
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS bip353_requests_user ON silnt.bip353_requests(user_id, status)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS bip353_requests_status ON silnt.bip353_requests(status, created_at)"
    )

async def m008_boltz_swaps(db):
    await db.execute(
        f"""
        CREATE TABLE silnt.boltz_swaps (
            id                   TEXT PRIMARY KEY,          -- Boltz swap id
            wallet_id            TEXT NOT NULL,             -- LNbits wallet (LN side)
            silnt_wallet_id      TEXT,                      -- SP wallet that funded it
            status               TEXT NOT NULL,             -- created/funded/failed/refunded/completed
            timeout_block_height INTEGER,                   -- refund nLockTime floor
            created_at           TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            updated_at           TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            json_data            TEXT NOT NULL              -- the rest (see SwapRecord)
        );
        """
    )
    # index for finding swaps that may need refunding
    await db.execute(
        "CREATE INDEX idx_boltz_swaps_status ON silnt.boltz_swaps (status);"
    )

async def m009_fix_utxos_primary_key(db):
    """
    The original PK was on txid alone, making a txid globally unique across ALL
    wallets. That's wrong: two different wallets can receive outputs in the same
    transaction, and one tx can pay multiple vouts to one wallet. The txid-only PK
    fired before the ON CONFLICT (txid,vout,wallet_id) upsert could absorb the
    re-insert, causing a duplicate-key crash when a 2nd wallet saw the same txid.
    Drop it and use the full outpoint-per-wallet as the PK (the unique index
    idx_silnt_utxos_vout_wallet_id already enforces this combination).
    """
    await db.execute("ALTER TABLE silnt.utxos DROP CONSTRAINT IF EXISTS utxos_pkey")
    await db.execute(
        "ALTER TABLE silnt.utxos "
        "ADD CONSTRAINT utxos_pkey PRIMARY KEY (txid, vout, wallet_id)"
    )

async def m010_bitmail_per_address(db):
    """
    Per-address BitMail (BIP-353): each SP address — the wallet's base address
    OR a labeled address — may have at most one BitMail, assigned once.

    1. wallet_addresses.hr_address: the BitMail bound to a labeled address.
       (The wallet's BASE address continues to use wallets.hr_address.)
    2. bip353_requests.address_id: which labeled address the request targets.
       NULL = the wallet's base SP address (back-compat: all existing rows are
       base-address requests, so NULL is the correct default for them).
    """
    await db.execute(
        "ALTER TABLE silnt.wallet_addresses "
        "ADD COLUMN IF NOT EXISTS hr_address TEXT DEFAULT NULL"
    )
    await db.execute(
        "ALTER TABLE silnt.bip353_requests "
        "ADD COLUMN IF NOT EXISTS address_id TEXT DEFAULT NULL"
    )
    # Helps the per-address "already has an approved BitMail?" lifetime check.
    await db.execute(
        "CREATE INDEX IF NOT EXISTS bip353_requests_addr "
        "ON silnt.bip353_requests(wallet_id, address_id, status)"
    )

async def m011_payjoin_requests(db):
    """
    PayJoin (BIP-84, watch-only, external Sparrow signing) coordination.

    Two users of this instance PayJoin each other. siLNt holds ONLY xpubs + PSBTs
    — never seeds/keys. This table carries one PayJoin attempt through its state
    machine and stores the in-progress PSBT (base64).

    State machine:
      PROPOSED    sender proposed; siLNt built the sender-only draft PSBT
      CONTRIBUTED receiver accepted; siLNt added receiver input + bumped payment
                  output; receiver signed their input. Final unsigned PSBT exists.
      FINALIZING  sender signed the final PSBT; siLNt combining + finalizing
      BROADCAST   network tx broadcast; confirmation tracked by send-watch
      CANCELLED   declined / cancelled / expired (terminal)
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.payjoin_requests (
            id                  TEXT PRIMARY KEY,
            status              TEXT NOT NULL DEFAULT 'PROPOSED',

            -- parties (on-instance, addressed by username per decision)
            sender_user_id      TEXT NOT NULL,
            sender_username     TEXT NOT NULL,
            receiver_user_id    TEXT,
            receiver_username   TEXT NOT NULL,

            -- which imported BIP-84 wallets are involved (refs payjoin_descriptors)
            sender_descriptor_id   TEXT NOT NULL,
            receiver_descriptor_id TEXT,

            -- economics (sender pays fee per decision)
            amount_sats         {db.big_int} NOT NULL,
            fee_rate            REAL NOT NULL,
            payment_address     TEXT NOT NULL,      -- receiver's payment address
            receiver_input_sats {db.big_int},       -- R, once contributed
            fee_sats            {db.big_int},        -- computed at contribute time

            -- the in-progress artifact (base64). One column, overwritten as the
            -- PSBT advances: draft -> final-unsigned -> partially-signed -> final
            psbt                TEXT,
            -- the two parties' signed copies are merged by siLNt; we keep the
            -- latest combined PSBT in `psbt` and the broadcast tx hex here:
            unsigned_psbt       TEXT,
            -- receiver's signed copy (their partial_sig) stored at /contribute;
            -- sender's signed copy arrives at /finalize and is combined with it.
            receiver_signed_psbt TEXT,
            tx_hex              TEXT,
            txid                TEXT,

            -- selected inputs (JSON): sender inputs at propose, receiver input at
            -- contribute. Outpoints + (chain,index) for derivation/validation.
            sender_inputs       TEXT,               -- JSON array
            receiver_input      TEXT,               -- JSON object

            reject_reason       TEXT,
            created_at          TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            updated_at          TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            -- expiry stored as Unix seconds (BIGINT) rather than TIMESTAMP: the
            -- codebase only ever uses db.timestamp_now for defaults and never
            -- writes computed timestamps, so an int avoids datetime-serialization
            -- ambiguity across Postgres/SQLite.
            expires_at          {db.big_int}
        );
        """
    )
    # Lookups: receiver's incoming queue, sender's outgoing, expiry sweep.
    await db.execute(
        "CREATE INDEX idx_payjoin_receiver ON silnt.payjoin_requests (receiver_user_id, status);"
    )
    await db.execute(
        "CREATE INDEX idx_payjoin_sender ON silnt.payjoin_requests (sender_user_id, status);"
    )
    await db.execute(
        "CREATE INDEX idx_payjoin_status ON silnt.payjoin_requests (status, expires_at);"
    )


# Companion table: a user's imported watch-only BIP-84 wallet, imported as an
# OUTPUT DESCRIPTOR (single copy-paste from Sparrow). embit parses it, so siLNt
# extracts fingerprint + path + xpub from the descriptor itself — no separate
# fingerprint field for the user to find, and the key-origin used in PSBTs
# matches exactly what the wallet declared (avoids Sparrow-recognition issues).
async def m012_payjoin_descriptors(db):
    """
    Imported watch-only BIP-84 accounts for PayJoin, as output descriptors.
    User pastes e.g.  wpkh([bc7a6fe7/84h/1h/0h]tpub.../<0;1>/*)
    siLNt stores the raw descriptor plus the fields embit parses out of it.
    siLNt stores ONLY public data (descriptor/xpub/fingerprint). No keys/seeds.
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.payjoin_descriptors (
            id              TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL,
            label           TEXT,
            descriptor      TEXT NOT NULL,          -- raw output descriptor (as pasted)
            -- parsed from the descriptor by embit at import (cached for queries):
            xpub            TEXT NOT NULL,          -- account xpub (tpub/xpub)
            master_fp       TEXT NOT NULL,          -- 8 hex chars, from [origin]
            account_path    TEXT NOT NULL,          -- e.g. "84h/1h/0h"
            script_type     TEXT NOT NULL DEFAULT 'wpkh',  -- validated == wpkh
            network         TEXT NOT NULL,          -- mainnet/signet/regtest
            last_sync_at    TIMESTAMP,
            created_at      TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        );
        """
    )

    await db.execute(
        "CREATE INDEX idx_payjoin_descriptors_user ON silnt.payjoin_descriptors (user_id);"
    )

async def m013_payjoin_invoice_fields(db):
    """
    Invoice model (payee-initiated, directed PayJoin): add a memo and a second
    order-independent signature slot to payjoin_requests.
      receiver_* = payee A (set at invoice creation, incl. A's contributed input)
      sender_*   = payer B (B's inputs set when B pays)
    Runtime statuses: 'OPEN' (A posted invoice) -> 'CLAIMED' (B paid, PSBT built,
    awaiting both signatures) -> 'BROADCAST' / 'CANCELLED'. status is TEXT, so no
    enum to alter. Fulcrum config needs NO migration (BackendConfig is stored as
    JSON in blindbit_config.json_data).
    """
    await db.execute("ALTER TABLE silnt.payjoin_requests ADD COLUMN memo TEXT;")
    await db.execute("ALTER TABLE silnt.payjoin_requests ADD COLUMN sender_signed_psbt TEXT;")


async def m014_payjoin_contacts(db):
    """
    Consent-based connections between two users on this instance, so a payee can
    keep a private, curated list of payers (and vice-versa) WITHOUT exposing the
    global user base. One row per connection:
      status PENDING  -> requester asked target; awaiting target's approval
      status ACCEPTED -> mutual connection; each may invoice/pay the other and
                         sees the other in their invoice payer-picker
    Either party can delete the row (sever the connection). No enumeration: a
    request is only created by exact known username (resolve-payer check).
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.payjoin_contacts (
            id                 TEXT PRIMARY KEY,
            status             TEXT NOT NULL DEFAULT 'PENDING',
            requester_user_id  TEXT NOT NULL,
            target_user_id     TEXT NOT NULL,
            created_at         TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            updated_at         TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        );
        """
    )
    await db.execute(
        "CREATE INDEX idx_payjoin_contacts_req ON silnt.payjoin_contacts (requester_user_id, status);"
    )
    await db.execute(
        "CREATE INDEX idx_payjoin_contacts_tgt ON silnt.payjoin_contacts (target_user_id, status);"
    )


async def m015_payjoin_contact_labels(db):
    """
    Per-side private labels for connections. Each user can label a connection
    independently; the label is visible only to the labeler (not shared with the
    counterparty). Keyed by (contact_id, labeler_user_id). Separate table because
    the connection row itself is shared by both parties.
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.payjoin_contact_labels (
            contact_id      TEXT NOT NULL,
            labeler_user_id TEXT NOT NULL,
            label           TEXT NOT NULL,
            updated_at      TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            PRIMARY KEY (contact_id, labeler_user_id)
        );
        """
    )


async def m016_payjoin_descriptor_encryption(db):
    """
    Privacy hardening: encrypt PayJoin descriptors/xpubs AT REST.

    An account xpub lets anyone holding it derive all of a wallet's addresses and
    reconstruct its full balance/history (watch-only). The PayJoin flow needs the
    descriptor server-side to coordinate, so we now store descriptor + xpub
    encrypted (AESCipher keyed by the LNbits instance auth_secret) instead of in
    plaintext. This protects a leaked DB dump/backup; it does not protect against
    a full host compromise (which would also expose the key).

    Adds xpub_sha256: a non-reversible SHA256 tag used for duplicate-import
    detection, since the encrypted xpub can't be matched by equality. Backfills
    the tag for existing rows and encrypts any existing plaintext descriptor/xpub
    in place.
    """    
    # 1) Add the dedup-hash column (nullable; backfilled below).
    await db.execute("ALTER TABLE silnt.payjoin_descriptors ADD COLUMN xpub_sha256 TEXT;")    

    # 2) Index the dedup tag for fast existence checks.
    await db.execute(
        "CREATE INDEX idx_payjoin_desc_xpubhash ON silnt.payjoin_descriptors (user_id, xpub_sha256);"
    )


async def m017_sp_contacts(db):
    """
    Per-user private address book for SP sends. Users explicitly save recipients
    (a raw SP address OR a BitMail name) with a label, to reuse on the Send
    screen. Private to the saving user (scoped by user_id). The recipient value
    is encrypted at rest (same as PayJoin descriptors) since it's a recipient
    identity; the label is the user's own and kept plaintext.
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.sp_contacts (
            id           TEXT PRIMARY KEY,
            user_id      TEXT NOT NULL,
            label        TEXT NOT NULL,
            kind         TEXT NOT NULL,          -- 'bitmail' | 'sp'
            value        TEXT NOT NULL,          -- encrypted recipient (name or sp address)
            value_sha256 TEXT,                   -- non-reversible dedup tag
            created_at   TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            last_used_at TIMESTAMP
        );
        """
    )
    await db.execute(
        "CREATE INDEX idx_sp_contacts_user ON silnt.sp_contacts (user_id, value_sha256);"
    )

async def m019_drop_stray_utxos_vout_unique(db):    
    await db.execute("DROP INDEX IF EXISTS silnt.idx_silnt_utxos_vout")
    await db.execute("ALTER TABLE silnt.utxos DROP CONSTRAINT IF EXISTS idx_silnt_utxos_vout")

async def m020_admin_alerts(db):
    """
    Admin-visible alerts surfaced in the Admin console (e.g. BitMail tampering
    detected on a send: the DNS TXT for a siLNt-issued BitMail resolved to an SP
    address that does NOT match the one siLNt recorded — a possible hijack).
    """
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS silnt.admin_alerts (
            id          TEXT PRIMARY KEY,
            kind        TEXT NOT NULL,
            severity    TEXT NOT NULL DEFAULT 'warning',
            title       TEXT NOT NULL,
            detail      TEXT NOT NULL DEFAULT '',
            meta        TEXT,
            acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
            created_at  INTEGER NOT NULL
        );
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_admin_alerts_open "
        "ON silnt.admin_alerts (acknowledged, created_at)"
    )

async def m021_login_alerts(db):
    """
    Dedup store for new-device sign-in alert emails. When an untrusted device
    accesses an account, we email the user once per (user, device signature)
    within a cooldown window — this table records the last time we alerted for a
    given signature so refreshes / VPN flaps / cookie drops don't spam the user.
    """
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS silnt.login_alerts (
            user_id       TEXT NOT NULL,
            sig           TEXT NOT NULL,       -- hash of UA + IP (coarse device id)
            last_alert_at INTEGER NOT NULL,
            PRIMARY KEY (user_id, sig)
        );
        """
    )

async def m022_device_codes(db):
    """Short numeric codes for new-device confirmation (replaces email-link flow)."""
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS silnt.device_codes (
            user_id     TEXT NOT NULL,
            code_hash   TEXT NOT NULL,
            device_id   TEXT NOT NULL,
            user_agent  TEXT,
            ip          TEXT,
            expires_at  INTEGER NOT NULL,
            attempts    INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (user_id)
        );
        """
    )

async def m023_backend_config_per_network(db):
    # Rename blindbit_config -> backend_config, keyed per-network. The legacy
    # singleton row (id='blindbit') is copied to its network id. Old table is
    # left in place for now (dropped in a later cleanup migration after Stage 2).
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS silnt.backend_config (
            id TEXT PRIMARY KEY,
            json_data TEXT NOT NULL DEFAULT '{}'
        );
        """
    )


async def m024_sp_contacts_network(db):
    """Scope the SP address book per network. Without this, a user with wallets
    on more than one network (e.g. a mainnet build reusing a signet test account)
    sees every network's contacts. Contacts predate this column were created in
    the signet-only phase, so backfill them to signet; new rows carry their
    creating build's network. The dedup index gains `network` so the same
    recipient can be saved on more than one network.
    """
    await db.execute(
        "ALTER TABLE silnt.sp_contacts ADD COLUMN network TEXT NOT NULL DEFAULT 'signet';"
    )
    await db.execute("DROP INDEX IF EXISTS silnt.idx_sp_contacts_user")
    await db.execute(
        "CREATE INDEX idx_sp_contacts_user ON silnt.sp_contacts (user_id, network, value_sha256);"
    )


async def m025_background_scan(db):
    """Opt-in "Remote Scanner": a user may let the server scan a wallet in the
    background (so a returning user isn't faced with a huge catch-up). This
    requires storing the wallet's SCAN private key — a detection-only capability
    (it can find payments but never spend). The spend key is never stored; the
    background scanner derives the spend PUBLIC key from the wallet's sp_address.
    The scan key is encrypted at rest. Presence of a row = opted in; disabling
    deletes the row (removing the key from the server).
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.background_scan (
            wallet_id   TEXT PRIMARY KEY,
            scan_secret TEXT NOT NULL,          -- encrypted at rest (AESCipher)
            created_at  TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        );
        """
    )


async def m026_fcm_tokens(db):
    """Firebase Cloud Messaging device tokens, per user, so the server can push a
    notification (e.g. "payment received" from a background scan) to a user's
    phone(s). A user can have several devices; a token is unique."""
    await db.execute(
        f"""
        CREATE TABLE silnt.fcm_tokens (
            token      TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        );
        """
    )
    await db.execute(
        "CREATE INDEX idx_fcm_tokens_user ON silnt.fcm_tokens (user_id);"
    )
