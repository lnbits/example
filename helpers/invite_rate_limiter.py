"""
Rate limiting for the "invite a friend" endpoint.

The invite endpoint sends an email (via the shared SMTP server) to an
address the caller chooses. The body is a fixed invite template — it can't be
used as an open relay for arbitrary content — but without limits a user could
still spam or harass an inbox. Two limits, both per authenticated user:

  1. Daily cap: at most MAX_INVITES_PER_USER_DAY invites in a rolling 24h.
  2. Per-recipient cooldown: the same address can't be re-invited by the same
     user more often than every RESEND_COOLDOWN_SECONDS.

State is in-memory — fine for single-process LNbits, and invites are low-stakes
enough that a counter reset on restart is acceptable.
"""

import time
from collections import defaultdict
from http import HTTPStatus

from fastapi import HTTPException

MAX_INVITES_PER_USER_DAY = 20
RESEND_COOLDOWN_SECONDS = 300  # 5 min between re-inviting the same address

_user_invite_log: dict = defaultdict(list)  # user_id -> [ts, ...]
_recent_pairs: dict = {}                     # (user_id, email) -> ts


def _prune(entries: list, age_seconds: int) -> list:
    cutoff = time.time() - age_seconds
    return [t for t in entries if t >= cutoff]


def check_invite_allowed(user_id: str, email: str) -> None:
    """Raise HTTPException(429) if this invite would exceed a limit. Call before
    sending; does not mutate counters (see record_invite)."""
    log = _user_invite_log[user_id] = _prune(_user_invite_log[user_id], 86400)
    if len(log) >= MAX_INVITES_PER_USER_DAY:
        raise HTTPException(
            status_code=HTTPStatus.TOO_MANY_REQUESTS,
            detail=(
                f"You've reached the daily invite limit "
                f"({MAX_INVITES_PER_USER_DAY}). Please try again tomorrow."
            ),
        )
    last = _recent_pairs.get((user_id, email.lower()), 0)
    wait = int(RESEND_COOLDOWN_SECONDS - (time.time() - last))
    if wait > 0:
        raise HTTPException(
            status_code=HTTPStatus.TOO_MANY_REQUESTS,
            detail=f"You just invited that address. Try again in {wait} seconds.",
        )


def record_invite(user_id: str, email: str) -> None:
    """Record a completed invite so it counts toward both limits."""
    now = time.time()
    _user_invite_log[user_id].append(now)
    _recent_pairs[(user_id, email.lower())] = now
