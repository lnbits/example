# SiLNt — Silent Payments Wallet Extension for LNbits

A [LNbits](https://lnbits.com) extension for managing [Silent Payment](https://silentpayments.xyz) Bitcoin wallets, with blockchain scanning powered by a self-hosted [BlindBit Oracle](https://github.com/ponthief/blindbit-oracle).

---

## Features

- Generate Silent Payment addresses from a BIP39 mnemonic
- Store and manage multiple Silent Payment wallet accounts per user
- Generate up to 10 BIP352 labeled SP subaccount addresses per wallet
- Human Readable Address support ([BIP353](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki) email format) — validated against SP address on create/update
- Blockchain scanning via a self-hosted BlindBit Oracle with real-time progress tracking and stop/resume
- UTXO tracking with automatic balance updates (unspent only)
- Send to Silent Payment, on-chain, or BIP353 email addresses
- Configurable Mempool URL (supports local instances via http or https)
- Admin-controlled BlindBit Oracle connection settings
- QR code display for SP addresses and subaccount addresses

---

## Requirements

- LNbits instance (self-hosted)
- Python dependencies: `embit`, `httpx`, `coincurve`, `cryptography`, `dnspython`, `ecdsa`
- A running [blindbit-oracle](https://github.com/ponthief/blindbit-oracle) instance for blockchain scanning

---

## Installation

1. As Admin user, navigate to **Settings → Extensions** and add Source:
   [Ponthief-Extensions](https://raw.githubusercontent.com/ponthief/lnbits-extensions/extensions/extensions.json)
2. Install/Enable the extension from the LNbits admin panel under **Extensions**.
3. Database migrations run automatically on first load.

---

## Configuration

### BlindBit Oracle Connection

Before scanning, an admin must configure the BlindBit Oracle connection via the **Settings** button (⚙️) in the extension UI, or via the API:

```bash
curl -X PUT https://<your-lnbits>/siLNt/api/v1/backend/config \
  -H "X-Api-Key: <admin_key>" \
  -H "Content-Type: application/json" \
  -d '{
    "blindbit_url": "http://localhost:8001",
    "blindbit_user": "",
    "blindbit_pass": "",
    "mempool_url": "https://mempool.space"
  }'
```

### Mempool URL

The Mempool URL is configured alongside the BlindBit Oracle settings. It defaults to `https://mempool.space` but can be pointed to a local Mempool instance for added privacy. Both `http` and `https` are supported.

---

## Usage

### 1. Add a Wallet Account

Click **Silent Payments Wallet Account → New Wallet Account** and fill in:

| Field | Description |
|---|---|
| Mnemonic | 12-word BIP39 seed phrase (AES-encrypted client-side, never stored) |
| Born at Height | Block height of the wallet's first transaction — reduces scan time |
| Human Readable Address | Optional BIP353 email-format address (e.g. `alice@domain.com`) — must resolve to this wallet's SP address |

> The mnemonic is AES-encrypted using the born-at height as the key before transmission. It is never stored in the database.

### 2. Generate Labeled SP Addresses (Subaccounts)

Click **+** on a wallet row to generate a new BIP352 labeled SP address (up to 10 per wallet). Labeled addresses appear inline below the main SP address with an amber border. Click **Save** to persist to the database — unsaved addresses are marked with an `unsaved` badge.

### 3. Scan the Blockchain

Click the **Bitcoin** icon button on a wallet row to open the scan dialog. The dialog shows:
- **Scan From** — last scanned height (editable)
- **Chain Tip** — fetched live from the Oracle (editable)
- **Blocks to Scan** — calculated automatically

Click **Sync to Tip** to start scanning. A progress bar shows real-time progress. Click **Stop** to pause — progress is saved and the next scan resumes from where it left off.

### 4. Load UTXOs from DB

Click the **database** icon button on a wallet row to load previously scanned UTXOs from the local database.

### 5. Make a Payment

Click **Send** to open the Send Payment flow:
1. Select UTXOs to spend (checkbox + amount shown)
2. Enter recipient (SP address, on-chain address, or BIP353 email)
3. Set amount and fee rate
4. Click **Build Transaction** — reviews fee before broadcasting
5. Click **Broadcast** → confirm in the confirmation dialog

After broadcast, selected UTXOs are marked as spent and a Mempool link is shown in the notification.

### 6. Resolve BIP353

Click **Resolve BIP353** to look up a BIP353 email-format address and display the resolved SP address.

---

## API Reference

All endpoints are prefixed with `/siLNt/api/v1`. Authentication uses the `X-Api-Key` header.

### Wallets

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/wallet` | Invoice Key | List all wallet accounts |
| `GET` | `/wallet/{wallet_id}` | Invoice Key | Get a wallet account |
| `POST` | `/wallet` | Invoice Key | Create a wallet account |
| `PUT` | `/wallet/{wallet_id}` | Invoice Key | Update hr_address, last_height, title, balance |
| `DELETE` | `/wallet/{wallet_id}` | Invoice Key | Delete wallet, UTXOs and labeled addresses |

### Labeled SP Addresses

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/wallet/{wallet_id}/addresses` | Invoice Key | List saved labeled SP addresses |
| `POST` | `/wallet/{wallet_id}/addresses/preview` | Invoice Key | Preview a labeled SP address (not saved) |
| `POST` | `/wallet/{wallet_id}/addresses` | Invoice Key | Save a labeled SP address to DB |
| `DELETE` | `/wallet/{wallet_id}/addresses/{address_id}` | Invoice Key | Delete a labeled SP address |

### Scanning

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/wallet/{wallet_id}/scan` | Invoice Key | Scan blockchain for UTXOs |
| `POST` | `/wallet/{wallet_id}/scan/stop` | Invoice Key | Stop an in-progress scan |
| `GET` | `/wallet/{wallet_id}/scan/progress` | Invoice Key | Get real-time scan progress |

### UTXOs

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/utxos?wallet_id=` | Invoice Key | Load UTXOs from DB for a wallet |

### BlindBit Oracle

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/blindbit/config` | Invoice Key | Get Oracle connection settings |
| `PUT` | `/blindbit/config` | Admin Key | Update Oracle connection settings incl. Mempool URL |
| `GET` | `/oracle/tip` | Invoice Key | Get current chain tip from Oracle |

### BIP353

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/bip353/resolve?address=` | Invoice Key | Resolve a BIP353 email-format address |

### Transactions

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/tx/build` | Admin Key | Build and sign a transaction |
| `POST` | `/tx/broadcast` | Admin Key | Broadcast a signed transaction |

### Config

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/config` | Invoice Key | Get app config including mempool endpoint |

Full interactive docs at `/docs#/siLNt` on your LNbits instance.

---

## Data Models

### WalletAccount

```json
{
  "id": "abc123xyz",
  "user": "usr_abc123",
  "title": "sp1qqw...",
  "balance": 100000,
  "hr_address": "alice@domain.com",
  "network": "mainnet",
  "last_height": 840000,
  "last_scan_height": 842000,
  "sp_address": "sp1qqw..."
}
```

### WalletAddress (Labeled SP)

```json
{
  "id": "xyz789",
  "wallet_id": "abc123xyz",
  "sp_address": "sp1qq...",
  "label_index": 1,
  "created_at": 1710000000
}
```

### BackendConfig

```json
{
  "blindbit_url": "http://localhost:8001",
  "blindbit_user": "",
  "blindbit_pass": "",
  "mempool_url": "https://mempool.space"
}
```

### UTXORecord

```json
{
  "txid": "a1b2c3...",
  "vout": 0,
  "amount": 50000,
  "priv_key_tweak": "...",
  "pub_key": "...",
  "timestamp": 1710000000,
  "utxo_state": "unspent",
  "wallet_id": "abc123xyz"
}
```

---

## Security Notes

- Mnemonics are **never stored**. AES-encrypted client-side before transmission, used only to derive keys at creation time.
- The `scan_secret` (scan private key) is encrypted at rest using a server-side Fernet key.
- The `spend_key` is encrypted at rest using the `scan_secret` as the AES key — double-layered protection.
- BIP353 `hr_address` is validated server-side on create and update — it must resolve to the wallet's SP address.
- Configure `mempool_url` to point to a local Mempool instance for transaction broadcasting privacy.
- Admin Key is required for all write operations that affect funds (tx build, broadcast, BlindBit config).

---

## Project Structure

```
siLNt/
├── __init__.py
├── views.py                    # Page routes
├── views_api.py                # REST API endpoints
├── crud.py                     # Database operations
├── models.py                   # Pydantic models
├── migrations.py               # DB schema migrations
├── helpers/
│   ├── wallet.py               # SP address derivation, key encryption, tx building
│   ├── scan.py                 # Blockchain scanner (BlindBit Oracle client)
│   ├── address_resolver.py     # BIP353 DNS resolution
│   └── curve.py                # secp256k1 EC math helpers
├── static/
│   ├── js/
│   │   ├── index.js            # Main Vue app
│   │   ├── tables.js           # Table column definitions
│   │   ├── map.js              # Data mapping functions
│   │   ├── utils.js            # Utility functions
│   │   └── bip39-word-list.js  # BIP39 word list for mnemonic validation
│   └── components/
│       ├── wallet-config.js / .html   # BlindBit Oracle settings
│       ├── wallet-list.js / .html     # Wallet table with labeled addresses
│       └── utxo-list.js / .html       # UTXO table
└── templates/
    └── silnt/
        ├── index.html
        └── _api_docs.html
```

---

## References

- [BIP352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [BIP353 — DNS Payment Instructions](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki)
- [BIP352 Light Client Specification](https://github.com/setavenger/BIP0352-light-client-specification)
- [BlindBit Oracle](https://github.com/ponthief/blindbit-oracle)

---

## Contributing

Pull requests welcome. Please open an issue first to discuss significant changes.

---

## Author

Created by [Ponthief](https://github.com/ponthief) at [Bitaurus](https://bitaurus.net)

---

## License

MIT