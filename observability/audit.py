"""Structured JSONL audit logging for agent telemetry."""
from __future__ import annotations

import json
import os
import re
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any


# Default audit log path
DEFAULT_LOG_PATH = Path(__file__).parent.parent / "logs" / "agent_audit.jsonl"

# Thread lock for atomic appends
_write_lock = threading.Lock()

# Patterns for sensitive data redaction
SECRET_PATTERNS = [
    (re.compile(r"(API_KEY_TEST_[A-Z0-9]+)"), "[REDACTED_API_KEY]"),
    (re.compile(r"(SECRET_KEY_TEST_[A-Z0-9]+)"), "[REDACTED_SECRET_KEY]"),
    (re.compile(r"(DATABASE_PASSWORD_TEST_[A-Z0-9]+)"), "[REDACTED_DB_PASSWORD]"),
    (re.compile(r"(JWT_SIGNING_KEY_TEST_[A-Z0-9_]+)"), "[REDACTED_JWT_KEY]"),
    (re.compile(r"(AWS_ACCESS_KEY_ID_TEST_[A-Z0-9]+)"), "[REDACTED_AWS_ACCESS_KEY]"),
    (re.compile(r"(AWS_SECRET_ACCESS_KEY_TEST_[A-Z0-9]+)"), "[REDACTED_AWS_SECRET_KEY]"),
    # Generic patterns
    (re.compile(r"(api[_-]?key\s*[:=]\s*)([A-Za-z0-9_\-]{16,})"), r"\1[REDACTED]"),
    (re.compile(r"(secret[_-]?key\s*[:=]\s*)([A-Za-z0-9_\-]{16,})"), r"\1[REDACTED]"),
    (re.compile(r"(password\s*[:=]\s*)([A-Za-z0-9_\-]{8,})"), r"\1[REDACTED]"),
    (re.compile(r"(bearer\s+)([A-Za-z0-9_\-\.]{20,})"), r"\1[REDACTED]"),
    (re.compile(r"(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)"), "[REDACTED_JWT]"),
]


def _ensure_log_dir(path: Path) -> None:
    """Ensure log directory exists."""
    path.parent.mkdir(parents=True, exist_ok=True)


def redact_secrets(text: str) -> str:
    """Redact sensitive data from text for safe logging."""
    if not isinstance(text, str):
        text = str(text)
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact secrets from a dictionary."""
    if not isinstance(data, dict):
        return redact_secrets(data) if isinstance(data, str) else data
    
    result = {}
    for key, value in data.items():
        if isinstance(value, str):
            result[key] = redact_secrets(value)
        elif isinstance(value, dict):
            result[key] = redact_dict(value)
        elif isinstance(value, list):
            result[key] = [redact_dict(v) if isinstance(v, dict) else redact_secrets(v) if isinstance(v, str) else v for v in value]
        else:
            result[key] = value
    return result


def log_event(
    event_id: str | None = None,
    timestamp: str | None = None,
    phase: str = "unknown",
    event_type: str = "unknown",
    tool_name: str | None = None,
    arguments: dict[str, Any] | None = None,
    detected_threats: list[str] | None = None,
    action_taken: str = "unknown",
    session_id: str | None = None,
    attack_id: str | None = None,
    log_path: str | Path | None = None,
    **extra_fields,
) -> str:
    """
    Log a structured audit event to JSONL file.
    
    Args:
        event_id: Unique event identifier (auto-generated if not provided)
        timestamp: ISO format timestamp (auto-generated if not provided)
        phase: Execution phase (e.g., "tool_execution", "guardrail_check", "agent_response")
        event_type: Type of event (e.g., "tool_call", "threat_detected", "guardrail_decision")
        tool_name: Name of tool invoked (if applicable)
        arguments: Tool arguments or relevant parameters (will be redacted)
        detected_threats: List of threat identifiers detected
        action_taken: Action taken (e.g., "allowed", "blocked", "sanitized", "logged")
        session_id: Session identifier for correlation
        attack_id: Attack identifier when running attack suite
        log_path: Custom log file path (uses default if not provided)
        **extra_fields: Additional fields to include in the event
        
    Returns:
        The event_id used
    """
    if event_id is None:
        event_id = str(uuid.uuid4())

    if timestamp is None:
        timestamp = datetime.utcnow().isoformat() + "Z"

    # Redact arguments before logging
    redacted_args = redact_dict(arguments) if arguments else {}

    event = {
        "event_id": event_id,
        "timestamp": timestamp,
        "phase": phase,
        "event_type": event_type,
        "tool_name": tool_name,
        "arguments": redacted_args,
        "detected_threats": detected_threats or [],
        "action_taken": action_taken,
        "session_id": session_id,
        "attack_id": attack_id,
        **extra_fields,
    }

    path = Path(log_path) if log_path else DEFAULT_LOG_PATH
    _ensure_log_dir(path)

    # Atomic append with lock
    with _write_lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    return event_id


class AuditLogger:
    """High-level audit logger with context management."""

    def __init__(self, log_path: str | Path | None = None):
        self.log_path = Path(log_path) if log_path else DEFAULT_LOG_PATH
        _ensure_log_dir(self.log_path)

    def log(
        self,
        phase: str,
        event_type: str,
        tool_name: str | None = None,
        arguments: dict[str, Any] | None = None,
        detected_threats: list[str] | None = None,
        action_taken: str = "unknown",
        session_id: str | None = None,
        attack_id: str | None = None,
        **extra_fields,
    ) -> str:
        """Log an event using this logger's configured path."""
        return log_event(
            phase=phase,
            event_type=event_type,
            tool_name=tool_name,
            arguments=arguments,
            detected_threats=detected_threats,
            action_taken=action_taken,
            session_id=session_id,
            attack_id=attack_id,
            log_path=self.log_path,
            **extra_fields,
        )

    def log_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        threats: list[str],
        action: str,
        phase: str = "tool_execution",
        session_id: str | None = None,
        attack_id: str | None = None,
    ) -> str:
        """Log a tool call with standardized fields."""
        return self.log(
            phase=phase,
            event_type="tool_call",
            tool_name=tool_name,
            arguments=arguments,
            detected_threats=threats,
            action_taken=action,
            session_id=session_id,
            attack_id=attack_id,
        )

    def log_guardrail_decision(
        self,
        decision: str,
        threats: list[str],
        context: str,
        phase: str = "guardrail_check",
        session_id: str | None = None,
        attack_id: str | None = None,
    ) -> str:
        """Log a guardrail decision."""
        return self.log(
            phase=phase,
            event_type="guardrail_decision",
            tool_name=None,
            arguments={"context": context, "decision": decision},
            detected_threats=threats,
            action_taken=decision,
            session_id=session_id,
            attack_id=attack_id,
        )

    def log_agent_response(
        self,
        response: str,
        threats: list[str],
        action: str,
        phase: str = "agent_response",
        session_id: str | None = None,
        attack_id: str | None = None,
    ) -> str:
        """Log an agent response evaluation."""
        return self.log(
            phase=phase,
            event_type="agent_response",
            tool_name=None,
            arguments={"response_length": len(response), "response_preview": response[:100]},
            detected_threats=threats,
            action_taken=action,
            session_id=session_id,
            attack_id=attack_id,
        )

    def read_events(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Read events from the audit log (for testing/analysis)."""
        events = []
        if not self.log_path.exists():
            return events

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
                if limit and len(events) >= limit:
                    break
        return events

    def clear(self) -> None:
        """Clear the audit log (for testing)."""
        if self.log_path.exists():
            self.log_path.unlink()