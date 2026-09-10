"""repo_policy — repositories an install is never allowed to fetch.

Some content is deliberately not distributed as source. The private sensor
repository behind the Threat Monitor is the case this module exists for: it
holds the decoy paths, the bait format and the detection logic, and an install
that can clone it holds the honeypot itself rather than the benefit of it.

That content now arrives as a data subscription
(:mod:`security.tm_client`), which is revocable per install. This module closes
the door the subscription replaced, because a subscription is only a boundary
if the old path is actually shut:

* ``site_ext`` takes an operator-supplied repo URL.
* ``update_pipeline`` derives sibling repo URLs from the hub repo's owner as
  ``github.com/<owner>/<key>.git``, so a module key of ``tm`` resolves straight
  to the sensor repo without anybody configuring it.
* ``repo_sync`` runs ``git pull`` on every checkout found under
  ``provisioning_repos/``, so anything placed there stays updated.

Three independent ways in, so the check belongs in one place that all three
consult rather than three separate patches that can drift apart.

The match is on the repository identity, not on a literal string. A denylist
that compared full URLs would be defeated by ``.git``, by ``git@`` SSH form, by
a trailing slash, by case, or by a token embedded in the URL — none of which
change which repository is being fetched.

This is a policy control, not a security boundary against the operator: root on
the box can clone anything. It exists so that no *product* path — a config
field, a derived default, a sync loop — fetches the sensor repo, and so that a
future change that reintroduces one fails a test instead of shipping.
"""
from __future__ import annotations

import logging
import re
from typing import Optional, Tuple

logger = logging.getLogger("Hub")

# owner/name pairs that no install may fetch, lowercased. Keyed by name only
# where the owner is irrelevant would be too broad -- "tm" is a plausible name
# for an unrelated repo -- so both halves are matched.
FORBIDDEN_REPOS = frozenset({
    ("lbockenstedt", "tm"),
})

# Matches the shapes git accepts for a GitHub remote:
#   https://github.com/owner/name(.git)(/)
#   https://<user>:<token>@github.com/owner/name.git
#   git@github.com:owner/name.git
#   ssh://git@github.com/owner/name.git
_GITHUB_RE = re.compile(
    r"""^
    (?:
        (?:https?://|ssh://)?            # optional scheme
        (?:[^/@\s]+@)?                   # optional credential or git@
        github\.com                      # host
        [:/]                             # ':' for scp-style, '/' otherwise
      |
        (?=[^/\s]+/[^/\s]+$)             # bare "owner/name" with no host
    )
    (?P<owner>[^/\s]+)
    /
    (?P<name>[^/\s?#]+?)
    (?:\.git)?
    /?
    $""",
    re.VERBOSE | re.IGNORECASE,
)


def parse_repo(url: str) -> Optional[Tuple[str, str]]:
    """``(owner, name)`` lowercased for a GitHub URL, else ``None``.

    ``None`` means "not a GitHub repo this module can reason about", which
    callers must treat as *not cleared* rather than *allowed* only when they
    have some other reason to distrust it. A self-hosted git URL is simply not
    what this policy is about.
    """
    s = (url or "").strip()
    if not s:
        return None
    m = _GITHUB_RE.match(s)
    if not m:
        return None
    return m.group("owner").lower(), m.group("name").lower()


def is_forbidden(url: str) -> bool:
    """Whether ``url`` names a repository no install may fetch."""
    parsed = parse_repo(url)
    return parsed in FORBIDDEN_REPOS if parsed else False


def refuse_reason(url: str) -> str:
    """Operator-facing explanation, or ``""`` when the URL is allowed.

    Names the replacement. An operator who set this deliberately is not doing
    something unreasonable -- they are trying to get threat content -- and a
    bare "refused" would leave them with no idea that a supported path exists.
    """
    if not is_forbidden(url):
        return ""
    return ("this repository is not distributed as source; its content is "
            "delivered as a data subscription instead — enable the threat "
            "monitor subscription in Setup › Security")


def guard(url: str, *, context: str) -> bool:
    """Log and refuse a forbidden fetch. Returns True when the caller must stop.

    Logs at WARNING rather than silently skipping: an operator who configured
    this is waiting for content that will never arrive, and a silent no-op
    would look exactly like a repository that is merely empty.
    """
    if not is_forbidden(url):
        return False
    logger.warning("%s: refusing to fetch %s — %s", context, url,
                   refuse_reason(url))
    return True
