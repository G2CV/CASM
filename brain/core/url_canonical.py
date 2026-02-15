
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def canonicalize_url(raw_url: str) -> str:
    """Normalize a URL for stable comparisons and deduping.

    Args:
        raw_url (str): Raw URL string.

    Returns:
        str: Canonicalized URL with normalized scheme/host/port/path/query.

    Notes:
        Default ports and query parameter ordering are normalized so the same
        endpoint compares equal across inputs and tool outputs.
    """
    parts = urlsplit(raw_url)
    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower()
    port = parts.port

    if scheme == "https" and port == 443:
        port = None
    if scheme == "http" and port == 80:
        port = None

    host = hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if port is not None:
        netloc = f"{host}:{port}"
    else:
        netloc = host

    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]

    query_items = parse_qsl(parts.query, keep_blank_values=True)
    query_items.sort(key=lambda item: (item[0], item[1]))
    query = urlencode(query_items, doseq=True)

    return urlunsplit((scheme, netloc, path, query, ""))
