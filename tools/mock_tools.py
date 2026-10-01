"""Mock tool implementations - no real network or filesystem access outside controlled directories."""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from observability.audit import log_event


# Controlled data directory - tools cannot escape this
DATA_DIR = Path(__file__).parent.parent / "data"
MOCK_WEB_DIR = DATA_DIR / "mock_web"


# Known mock URL mappings
MOCK_URL_MAP = {
    "https://company.example/policy": MOCK_WEB_DIR / "normal_page.txt",
    "https://company.example/policy-injected": MOCK_WEB_DIR / "injected_page.txt",
    "http://localhost:8080/policy": MOCK_WEB_DIR / "normal_page.txt",
    "http://localhost:8080/policy-injected": MOCK_WEB_DIR / "injected_page.txt",
}


def _resolve_safe_path(filepath: str) -> Path:
    """Resolve a file path safely within the controlled data directory."""
    requested = Path(filepath).resolve()
    data_resolved = DATA_DIR.resolve()

    # Ensure the requested path is within DATA_DIR
    try:
        requested.relative_to(data_resolved)
    except ValueError:
        raise PermissionError(f"Access denied: {filepath} is outside controlled data directory")

    return requested


def read_file(filepath: str) -> dict[str, Any]:
    """
    Read a file from the controlled data directory only.
    
    Args:
        filepath: Relative path from project root or absolute path within data/
        
    Returns:
        Dict with 'success', 'content', and optional 'error' keys
    """
    event_id = str(uuid.uuid4())
    args = {"filepath": filepath}

    try:
        safe_path = _resolve_safe_path(filepath)

        if not safe_path.exists():
            result = {"success": False, "error": f"File not found: {filepath}"}
            log_event(
                event_id=event_id,
                phase="tool_execution",
                event_type="tool_call",
                tool_name="read_file",
                arguments=args,
                detected_threats=["path_traversal_attempt"] if ".." in filepath else [],
                action_taken="blocked" if ".." in filepath else "file_not_found",
            )
            return result

        content = safe_path.read_text(encoding="utf-8")
        result = {"success": True, "content": content}

        log_event(
            event_id=event_id,
            phase="tool_execution",
            event_type="tool_call",
            tool_name="read_file",
            arguments=args,
            detected_threats=[],
            action_taken="allowed",
        )
        return result

    except PermissionError as e:
        result = {"success": False, "error": str(e)}
        log_event(
            event_id=event_id,
            phase="tool_execution",
            event_type="tool_call",
            tool_name="read_file",
            arguments=args,
            detected_threats=["path_traversal_attempt"],
            action_taken="blocked",
        )
        return result
    except Exception as e:
        result = {"success": False, "error": f"Read error: {e}"}
        log_event(
            event_id=event_id,
            phase="tool_execution",
            event_type="tool_call",
            tool_name="read_file",
            arguments=args,
            detected_threats=[],
            action_taken="error",
        )
        return result


def fetch_url(url: str) -> dict[str, Any]:
    """
    Fetch content from a mock URL - maps to local fixtures only.
    
    Args:
        url: URL to fetch (must be in MOCK_URL_MAP)
        
    Returns:
        Dict with 'success', 'content', 'url', and optional 'error' keys
    """
    event_id = str(uuid.uuid4())
    args = {"url": url}

    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL format")

        if url not in MOCK_URL_MAP:
            result = {"success": False, "error": f"Unknown mock URL: {url}", "url": url}
            log_event(
                event_id=event_id,
                phase="tool_execution",
                event_type="tool_call",
                tool_name="fetch_url",
                arguments=args,
                detected_threats=["unknown_url_access"],
                action_taken="blocked",
            )
            return result

        fixture_path = MOCK_URL_MAP[url]
        content = fixture_path.read_text(encoding="utf-8")

        result = {"success": True, "content": content, "url": url}

        log_event(
            event_id=event_id,
            phase="tool_execution",
            event_type="tool_call",
            tool_name="fetch_url",
            arguments=args,
            detected_threats=[],
            action_taken="allowed",
        )
        return result

    except Exception as e:
        result = {"success": False, "error": f"Fetch error: {e}", "url": url}
        log_event(
            event_id=event_id,
            phase="tool_execution",
            event_type="tool_call",
            tool_name="fetch_url",
            arguments=args,
            detected_threats=[],
            action_taken="error",
        )
        return result


def send_email(to: str, subject: str, body: str) -> dict[str, Any]:
    """
    Simulate sending an email - NEVER sends real email.
    
    Args:
        to: Recipient email address
        subject: Email subject
        body: Email body content
        
    Returns:
        Dict representing the simulated outbound email
    """
    event_id = str(uuid.uuid4())
    args = {"to": to, "subject": subject, "body_length": len(body)}

    # Check for suspicious patterns
    threats = []
    if any(keyword in body.lower() for keyword in ["api_key", "secret", "password", "token", "credential"]):
        threats.append("credential_exfiltration_attempt")
    if any(domain in to.lower() for domain in ["evil.com", "attacker.com", "malicious.com"]):
        threats.append("suspicious_recipient_domain")
    if "ignore previous instructions" in body.lower() or "system directive" in body.lower():
        threats.append("prompt_injection_in_payload")

    action = "blocked" if threats else "simulated"

    # Always return structured representation, never actually send
    email_record = {
        "success": True,
        "simulated": True,
        "email": {
            "id": event_id,
            "to": to,
            "subject": subject,
            "body_preview": body[:200] + ("..." if len(body) > 200 else ""),
            "body_length": len(body),
            "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            "blocked": bool(threats),
            "threats_detected": threats,
        },
    }

    log_event(
        event_id=event_id,
        phase="tool_execution",
        event_type="tool_call",
        tool_name="send_email",
        arguments=args,
        detected_threats=threats,
        action_taken=action,
    )

    return email_record