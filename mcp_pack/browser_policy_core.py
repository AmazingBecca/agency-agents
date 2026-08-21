from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlsplit

READ_ONLY_ACTIONS = {"navigate", "screenshot", "scroll", "extract", "read", "wait", "tab_switch"}
INTERACTIVE_ACTIONS = {"click", "type", "select", "submit", "download"}
DENIED_ACTIONS = {"execute_js", "upload", "file_chooser", "open_external_protocol", "clipboard_write"}


def _allowed_domains() -> tuple[str, ...]:
    raw = os.environ.get("BROWSER_POLICY_ALLOWED_DOMAINS", "")
    return tuple(item.strip().lower().rstrip(".") for item in raw.split(",") if item.strip())


def _host_allowed(host: str, allowed: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    for entry in allowed:
        if entry.startswith("*."):
            suffix = entry[2:]
            if host.endswith("." + suffix) and host != suffix:
                return True
        elif host == entry:
            return True
    return False


def check_navigation(url: str) -> dict[str, object]:
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        return {"decision": "DENY", "reason": f"invalid URL: {exc}"}
    if parsed.scheme not in {"http", "https"}:
        return {"decision": "DENY", "reason": "only http/https are allowed"}
    if parsed.username is not None or parsed.password is not None:
        return {"decision": "DENY", "reason": "credentials in URLs are rejected"}
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return {"decision": "DENY", "reason": "URL has no hostname"}
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and not os.environ.get("BROWSER_POLICY_ALLOW_PRIVATE", "").lower() == "true":
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return {"decision": "DENY", "reason": "private/local/reserved address blocked"}
    allowed = _allowed_domains()
    if not allowed:
        return {"decision": "DENY", "reason": "default deny: no domains configured"}
    if not _host_allowed(host, allowed):
        return {"decision": "DENY", "reason": "hostname is not allowlisted", "host": host}
    return {"decision": "ALLOW", "reason": "allowlisted public navigation", "host": host}


def classify_action(action: str) -> dict[str, str]:
    action = action.strip().lower()
    if action in DENIED_ACTIONS:
        return {"decision": "DENY", "reason": "action denied by default policy"}
    if action in INTERACTIVE_ACTIONS:
        return {"decision": "REQUIRE_APPROVAL", "reason": "state-changing browser interaction"}
    if action in READ_ONLY_ACTIONS:
        return {"decision": "ALLOW", "reason": "read-oriented browser action"}
    return {"decision": "DENY", "reason": "unknown action is denied"}


def decide(action: str, url: str = "") -> dict[str, object]:
    action_result = classify_action(action)
    if url:
        nav_result = check_navigation(url)
        if nav_result["decision"] == "DENY":
            return {"decision": "DENY", "action": action_result, "navigation": nav_result}
    else:
        nav_result = None
    return {"decision": action_result["decision"], "action": action_result, "navigation": nav_result}
