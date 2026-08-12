"""
BIP-353 DNS record management via Cloudflare API.
Creates/updates TXT records of the form:
  {username}.user._bitcoin-payment.{domain}  →  "bitcoin:?sp={sp_address}"
"""

import httpx
from loguru import logger
from ..crud import get_cloudflare_config

CF_API = "https://api.cloudflare.com/client/v4"


class CloudflareError(Exception):
    pass


def _headers(api_token: str) -> dict:
    return {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }


def bip353_record_name(username: str, domain: str) -> str:
    """Full DNS name for a BIP-353 TXT record."""
    return f"{username}.user._bitcoin-payment.{domain}"


def bip353_record_content(sp_address: str) -> str:
    """TXT record content per BIP-353 spec."""
    return f"bitcoin:?sp={sp_address}"


async def get_zone_domain(api_token: str, zone_id: str) -> str:
    """Fetch the domain name for a Cloudflare zone."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            f"{CF_API}/zones/{zone_id}",
            headers=_headers(api_token),
        )
        data = resp.json()
        if not data.get("success"):
            raise CloudflareError(f"Failed to fetch zone: {data.get('errors')}")
        return data["result"]["name"]


async def find_existing_record(
    api_token: str, zone_id: str, record_name: str
) -> str | None:
    """Return the record ID if a TXT record already exists, else None."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            f"{CF_API}/zones/{zone_id}/dns_records",
            headers=_headers(api_token),
            params={"type": "TXT", "name": record_name},
        )
        data = resp.json()
        if not data.get("success"):
            raise CloudflareError(f"Failed to query DNS records: {data.get('errors')}")
        results = data.get("result", [])
        return results[0]["id"] if results else None


async def create_bip353_record(
    api_token: str,
    zone_id: str,
    domain: str,
    username: str,
    sp_address: str,
    ttl: int = 300,
) -> dict:
    """
    Create or update a BIP-353 TXT record in Cloudflare.
    Returns {"record_name": ..., "hr_address": ..., "action": "created"|"updated"}
    """    
    record_name = bip353_record_name(username, domain)
    content = bip353_record_content(sp_address)

    existing_id = await find_existing_record(api_token, zone_id, record_name)

    payload = {
        "type": "TXT",
        "name": record_name,
        "content":  '"' + content + '"',
        "ttl": ttl,
        "comment": "BIP-353 Silent Payment address — managed by Thrilla",
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        if existing_id:
            # Update existing record
            resp = await client.put(
                f"{CF_API}/zones/{zone_id}/dns_records/{existing_id}",
                headers=_headers(api_token),
                json=payload,
            )
            action = "updated"
        else:
            # Create new record
            resp = await client.post(
                f"{CF_API}/zones/{zone_id}/dns_records",
                headers=_headers(api_token),
                json=payload,
            )
            action = "created"

    data = resp.json()
    if not data.get("success"):
        errors = data.get("errors", [])
        msg = errors[0].get("message", "Unknown error") if errors else "Unknown error"
        raise CloudflareError(f"Cloudflare DNS {action} failed: {msg}")

    hr_address = f"{username}@{domain}"
    logger.info(f"BIP-353 record {action}: {record_name} → {content}")

    return {
        "record_name": record_name,
        "hr_address": hr_address,
        "domain": domain,
        "action": action,
    }


async def delete_bip353_record(
    api_token: str,
    zone_id: str,
    domain: str,
    username: str,
) -> bool:
    """Delete a BIP-353 TXT record. Returns True if deleted, False if not found."""    
    record_name = bip353_record_name(username, domain)
    record_id = await find_existing_record(api_token, zone_id, record_name)

    if not record_id:
        return False

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.delete(
            f"{CF_API}/zones/{zone_id}/dns_records/{record_id}",
            headers=_headers(api_token),
        )
        data = resp.json()
        if not data.get("success"):
            raise CloudflareError(f"Failed to delete record: {data.get('errors')}")

    logger.info(f"BIP-353 record deleted: {record_name}")
    return True
