# Shared resolver for siLNt's custom SILNT_* configuration.
#
# Reads a value from the process environment first, then — because some LNbits
# deployments load .env into pydantic settings WITHOUT exporting it into
# os.environ — falls back to parsing the .env file LNbits actually loads. This
# makes a `SILNT_*=value` line in LNbits' .env take effect regardless of how the
# process environment is wired up (bare process, docker env_file, systemd, …).
#
# Only python-stdlib + (optional) python-dotenv are used; every import is
# guarded, so this never raises on a minimal install.
import os


def clean(v: str) -> str:
    """Trim whitespace and matching surrounding quotes from a raw value."""
    return (v or "").strip().strip('"').strip("'").strip()


def _manual_env_parse(path: str) -> dict:
    """Tiny KEY=VALUE parser used when python-dotenv isn't importable."""
    out = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip()
    except Exception:
        pass
    return out


def candidate_env_files() -> list:
    """LNbits .env locations to check, most-specific first: an explicit
    LNBITS_ENV_FILE, the .env in the dir LNbits was started from, and one at (or
    alongside) the data folder."""
    candidates = []
    explicit = os.environ.get("LNBITS_ENV_FILE", "").strip()
    if explicit:
        candidates.append(explicit)
    try:
        from dotenv import find_dotenv

        found = find_dotenv(usecwd=True)
        if found:
            candidates.append(found)
    except Exception:
        pass
    candidates.append(os.path.join(os.getcwd(), ".env"))
    data_folder = os.environ.get("LNBITS_DATA_FOLDER", "").strip()
    if data_folder:
        candidates.append(os.path.join(data_folder, ".env"))
        parent = os.path.dirname(data_folder.rstrip("/\\"))
        if parent:
            candidates.append(os.path.join(parent, ".env"))
    # De-dupe, preserving order.
    seen, ordered = set(), []
    for c in candidates:
        if c and c not in seen:
            seen.add(c)
            ordered.append(c)
    return ordered


def read_from_env_files(key: str):
    """Parse LNbits' .env directly for `key`. Returns (value, source_path), or
    ('', '') if not present in any candidate file."""
    for path in candidate_env_files():
        if not os.path.exists(path):
            continue
        try:
            from dotenv import dotenv_values

            vals = dotenv_values(path)
        except Exception:
            vals = _manual_env_parse(path)
        v = clean(vals.get(key, ""))
        if v:
            return v, path
    return "", ""


def silnt_env(key: str, default: str = "") -> str:
    """Resolve a SILNT_* value: process environment → LNbits .env file → default.
    Empty/whitespace values are treated as unset so they fall through to the
    next source."""
    v = clean(os.environ.get(key, ""))
    if v:
        return v
    v, _ = read_from_env_files(key)
    if v:
        return v
    return default


def frontend_base_url(request=None) -> str:
    """Canonical Thrilla web-app base URL for building email links (verify /
    reset). Prefers the configured SILNT_FRONTEND_URL so links resolve no matter
    how the request arrived: a browser sends an Origin/Referer header, but the
    mobile app's fetch does NOT — so without a configured URL a mobile
    registration's link falls back to the API host, which doesn't serve the web
    app's SPA routes (/verify, /reset) and 404s. Falls back to the request
    origin/host only when SILNT_FRONTEND_URL is unset (web-only deployments)."""
    configured = silnt_env("SILNT_FRONTEND_URL")
    if configured:
        return configured.rstrip("/")
    origin = ""
    if request is not None:
        origin = (
            request.headers.get("origin")
            or request.headers.get("referer")
            or ""
        )
        if not origin:
            origin = f"https://{request.headers.get('host', '')}"
    origin = origin.rstrip("/")
    # Strip any path from a Referer down to scheme://host.
    if origin.count("/") > 2:
        origin = "/".join(origin.split("/")[:3])
    return origin
