"""
swap_crypto.py — encrypt/decrypt the Boltz refund private key AT REST.

Reuses the SAME encryption siLNt already uses for email verification tokens
(email_verification.py): LNbits' internal-message helpers, keyed on
settings.auth_secret_key. One encryption path across the extension = one thing
to audit.

⚠️ Import matches email_verification.py exactly:
    from lnbits.helpers import encrypt_internal_message, decrypt_internal_message
The email-verification token base64-wraps the ciphertext for URL-safety; that's
NOT needed here (DB storage, not a URL), so we store the ciphertext directly.

Threat model: protects against DB-only exposure (dumps, backups, read-only
access). Does NOT protect against full app compromise (attacker with DB + the
server secret can decrypt). Blast radius is one swap's refund, only while that
swap is failed/timed-out with funds still locked. Regtest: legacy plaintext rows
are NOT supported — re-create swaps after deploying.
"""

# Match email_verification.py exactly: these come from lnbits.helpers.
from lnbits.helpers import encrypt_internal_message, decrypt_internal_message
from loguru import logger

_PREFIX = "enc:"   # marks an encrypted value


def _strip_pkcs7(s: str) -> str:
    """Remove PKCS#7 block padding that decrypt_internal_message may leave on the
    plaintext (observed: a trailing run of 0x10 bytes). Only strips a valid
    padding run (final byte value n, 1..16, repeated n times at the end)."""
    if not s:
        return s
    n = ord(s[-1])
    if 1 <= n <= 16 and len(s) >= n and all(ord(c) == n for c in s[-n:]):
        return s[:-n]
    return s

def encrypt_refund_key(privkey_hex: str) -> str:
    """Encrypt a refund private key for storage. Returns 'enc:<ciphertext>'."""
    if not privkey_hex:
        return privkey_hex
    if privkey_hex.startswith(_PREFIX):
        return privkey_hex  # idempotent
    enc = encrypt_internal_message(privkey_hex)
    if not enc:
        # Matches email_verification.py, which treats a falsy result as fatal.
        raise RuntimeError("Could not encrypt refund key.")
    return _PREFIX + enc


def decrypt_refund_key(stored: str) -> str:
    """Decrypt a stored refund key. Expects an 'enc:'-prefixed value."""
    if not stored:
        return stored
    if not stored.startswith(_PREFIX):
        # On regtest we don't support legacy plaintext — surface loudly rather
        # than silently signing with an unexpected value.
        raise ValueError("refund key is not encrypted (expected 'enc:' prefix)")
    dec = decrypt_internal_message(stored[len(_PREFIX):])
    if not dec:
        raise ValueError("Could not decrypt refund key.")
    dec = _strip_pkcs7(dec).strip()    
    return dec