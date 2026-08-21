from __future__ import annotations

import os

from fastmcp import FastMCP

from browser_policy_core import check_navigation, classify_action, decide

mcp = FastMCP("browser-policy-gate")


def _limits() -> dict[str, object]:
    max_steps = int(os.environ.get("BROWSER_POLICY_MAX_STEPS", "40"))
    timeout_seconds = float(os.environ.get("BROWSER_POLICY_TIMEOUT_SECONDS", "30"))
    if max_steps < 1 or max_steps > 200:
        raise ValueError("BROWSER_POLICY_MAX_STEPS must be between 1 and 200")
    if timeout_seconds < 1 or timeout_seconds > 120:
        raise ValueError("BROWSER_POLICY_TIMEOUT_SECONDS must be between 1 and 120")
    return {
        "max_steps": max_steps,
        "timeout_seconds": timeout_seconds,
        "sensitive_data_masking_required": True,
        "disable_browser_security_permitted": False,
        "unknown_actions": "DENY",
        "interactive_actions": "REQUIRE_APPROVAL",
    }


@mcp.tool
def policy_snapshot() -> dict[str, object]:
    """Return deterministic browser boundary configuration; this server does not browse."""
    return {
        "allowed_domains": [
            item.strip() for item in os.environ.get("BROWSER_POLICY_ALLOWED_DOMAINS", "").split(",") if item.strip()
        ],
        "allow_private_addresses": os.environ.get("BROWSER_POLICY_ALLOW_PRIVATE", "").lower() == "true",
        **_limits(),
        "enforcement_boundary": "Must be called/wired before the actual browser or computer-use tool; policy output alone cannot constrain a bypassing client.",
    }


@mcp.tool
def check_url(url: str) -> dict[str, object]:
    """Check a candidate navigation against default-deny domain/network rules."""
    return check_navigation(url)


@mcp.tool
def check_action(action: str) -> dict[str, str]:
    """Classify a browser/computer-use action as ALLOW, REQUIRE_APPROVAL, or DENY."""
    return classify_action(action)


@mcp.tool
def authorize_browser_step(action: str, url: str = "") -> dict[str, object]:
    """Produce the deterministic pre-action decision consumed by a browser executor."""
    result = decide(action, url)
    return {**result, "limits": _limits()}


if __name__ == "__main__":
    mcp.run()
