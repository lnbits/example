# ══════════════════════════════════════════════════════════════════════════════
# Live fee rates from the configured mempool (blindbit_config.mempool_url)
# ══════════════════════════════════════════════════════════════════════════════
# Proxies GET {mempool_url}/api/v1/fees/recommended so the client gets fee tiers
# without calling mempool.space directly (the app's CSP is connect-src 'self', so
# a direct browser→mempool call would be blocked — this MUST be server-side).
#
# Mempool returns:
#   {fastestFee, halfHourFee, hourFee, economyFee, minimumFee}  (sat/vB)
# We pass those through, plus a sane fallback if the mempool is unreachable.
# ══════════════════════════════════════════════════════════════════════════════

import httpx
import time
from http import HTTPStatus
from fastapi import Depends, HTTPException
from loguru import logger
from ..crud import get_backend_config, DEFAULT_CONFIG_NETWORK

# Fallback tiers if the mempool can't be reached (signet/regtest or outage).
# 1 sat/vB across the board is safe for test networks and won't block a send.
_FALLBACK = {
    "fastestFee": 2, "halfHourFee": 2, "hourFee": 1, "economyFee": 1, "minimumFee": 1,
}

_CG_URL = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd"

# Simple in-process cache: (rate, fetched_at)
_rate_cache = {"rate": 0.0, "ts": 0.0}
_CACHE_TTL = 180  # seconds (3 min)

async def get_btc_usd_rate() -> float:
    """Return BTC price in USD from CoinGecko, cached. 0.0 on any failure."""
    now = time.time()
    if _rate_cache["rate"] > 0 and (now - _rate_cache["ts"]) < _CACHE_TTL:
        return _rate_cache["rate"]
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(_CG_URL, headers={"accept": "application/json"})
            if r.status_code != 200:
                logger.warning(f"CoinGecko rate → {r.status_code}")
                return _rate_cache["rate"]   # serve stale if we have it, else 0
            data = r.json()
            rate = float(data.get("bitcoin", {}).get("usd", 0) or 0)
            if rate > 0:
                _rate_cache["rate"] = rate
                _rate_cache["ts"] = now
            return rate
    except Exception as e:
        logger.warning(f"CoinGecko rate fetch failed: {e}")
        return _rate_cache["rate"]   # stale or 0

async def get_recommended_fees(network: str = DEFAULT_CONFIG_NETWORK) -> dict:
    """
    Fetch recommended fee tiers (sat/vB) from the configured mempool. Returns the
    mempool shape, or a safe fallback on any error. Never raises — a fee lookup
    failing should not block the user; they can still send at the fallback rate.
    """
    backend = await get_backend_config(network)
    base = (backend.mempool_url or "https://mempool.space").rstrip("/")
    url = f"{base}/api/v1/fees/recommended"
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as c:
            r = await c.get(url)
            if r.status_code != 200:
                logger.warning(f"fee lookup {url} → {r.status_code}; using fallback")
                return {**_FALLBACK, "source": "fallback"}
            data = r.json()
            # Validate the expected keys exist; fall back if the shape is odd.
            tiers = {}
            for k in ("fastestFee", "halfHourFee", "hourFee", "economyFee", "minimumFee"):
                v = data.get(k)
                if not isinstance(v, (int, float)) or v <= 0:
                    logger.warning(f"fee lookup missing/invalid '{k}'; using fallback")
                    return {**_FALLBACK, "source": "fallback"}
                tiers[k] = int(v)
            tiers["source"] = "mempool"
            return tiers
    except Exception as e:
        logger.warning(f"fee lookup failed ({url}): {e}; using fallback")
        return {**_FALLBACK, "source": "fallback"}