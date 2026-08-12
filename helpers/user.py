from lnbits.settings import settings as lnbits_settings
from lnbits.core.models import WalletTypeInfo
from http import HTTPStatus
from fastapi import HTTPException
from ..crud import get_backend_config, DEFAULT_CONFIG_NETWORK

def require_admin(key_info: WalletTypeInfo) -> None:
    """Raise 403 if the caller is not an LNbits admin."""
    if not is_lnbits_admin(key_info.wallet.user):
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN,
            detail="Admin privileges required.",
        )

def is_lnbits_admin(user_id: str) -> bool:
    """
    Check if the user_id has admin rights in LNbits.
    Admin users are configured via LNBITS_ADMIN_USERS env var (comma-separated)
    plus the LNBITS_SUPER_USER.
    """
    # super_user is a single string or None
    super_user = getattr(lnbits_settings, "super_user", "") or ""
    if user_id and user_id == super_user:
        return True

    # admin_users is either a list[str] or a comma-separated string depending
    # on LNbits version — handle both
    admin_users = getattr(lnbits_settings, "lnbits_admin_users", []) or []
    if isinstance(admin_users, str):
        admin_users = [u.strip() for u in admin_users.split(",") if u.strip()]
    return user_id in admin_users

async def validate_born_height(last_height, network: str = DEFAULT_CONFIG_NETWORK) -> int | None:
    """
    Validate a requested born-at height against the system minimum.
    Returns the validated int height, or None if not provided. Raises 400 if below min.
    """
    if last_height is None or last_height == "":
        return None
    try:
        h = int(last_height)
    except (TypeError, ValueError):
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Born-at height must be a number.")
    if h < 0:
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Born-at height must be positive.")

    backend = await get_backend_config(network)
    min_h = int(getattr(backend, "min_scan_height", 0) or 0)
    if min_h > 0 and h < min_h:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST,
            f"Born-at height ({h}) is below the system minimum of {min_h}.",
        )
    return h