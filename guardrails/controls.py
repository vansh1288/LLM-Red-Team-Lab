"""Security Gateway - sits between agent tool calls and tool execution.

This module implements the security controls that enforce policy independently
of the LLM's behavior. The gateway intercepts every tool call and applies:
- Tool Allowlist
- Rate Limiting (per session)
- Threat Detection
- HITL Approval for sensitive tools
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from guardrails.detector import (
    DetectionEngine,
    DetectionFinding,
    DetectionResult,
    DetectionType,
    Severity,
    SecretDetector,
    PromptInjectionDetector,
    RecipientDetector,
    PathTraversalDetector,
)
from observability.audit import log_event


class ControlType(Enum):
    """Types of security controls."""
    TOOL_ALLOWLIST = "tool_allowlist"
    RATE_LIMIT = "rate_limit"
    THREAT_DETECTION = "threat_detection"
    HITL_APPROVAL = "hitl_approval"


class Decision(Enum):
    """Security gateway decision."""
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class GatewayDecision:
    """Result of security gateway evaluation."""
    decision: Decision
    allowed: bool
    reason: str
    control: ControlType
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "allowed": self.allowed,
            "reason": self.reason,
            "control": self.control.value,
            "metadata": self.metadata,
        }


@dataclass
class SessionState:
    """Per-session state for rate limiting and tracking."""
    session_id: str
    tool_call_count: int = 0
    max_tool_calls: int = 5
    blocked_calls: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


class ToolAllowlist:
    """Configurable tool allowlist."""

    DEFAULT_ALLOWED = {"read_file", "fetch_url", "send_email"}

    def __init__(self, allowed_tools: set[str] | None = None):
        self.allowed_tools = allowed_tools or self.DEFAULT_ALLOWED.copy()

    def check(self, tool_name: str) -> GatewayDecision:
        if tool_name in self.allowed_tools:
            return GatewayDecision(
                decision=Decision.ALLOW,
                allowed=True,
                reason=f"Tool '{tool_name}' is allowed",
                control=ControlType.TOOL_ALLOWLIST,
            )
        return GatewayDecision(
            decision=Decision.BLOCK,
            allowed=False,
            reason=f"Tool '{tool_name}' is not in allowlist",
            control=ControlType.TOOL_ALLOWLIST,
            metadata={"tool_name": tool_name, "allowed_tools": list(self.allowed_tools)},
        )


class RateLimiter:
    """Per-session rate limiter for tool calls."""

    def __init__(self, max_tool_calls: int = 5):
        self.max_tool_calls = max_tool_calls
        self._sessions: dict[str, SessionState] = {}
        self._lock = threading.Lock()

    def _get_or_create_session(self, session_id: str) -> SessionState:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionState(
                    session_id=session_id,
                    max_tool_calls=self.max_tool_calls,
                )
            return self._sessions[session_id]

    def check(self, session_id: str) -> GatewayDecision:
        session = self._get_or_create_session(session_id)

        if session.tool_call_count >= self.max_tool_calls:
            session.blocked_calls += 1
            return GatewayDecision(
                decision=Decision.BLOCK,
                allowed=False,
                reason=f"Rate limit exceeded: {session.tool_call_count}/{self.max_tool_calls} tool calls",
                control=ControlType.RATE_LIMIT,
                metadata={
                    "session_id": session_id,
                    "tool_call_count": session.tool_call_count,
                    "max_tool_calls": self.max_tool_calls,
                    "blocked_calls": session.blocked_calls,
                },
            )

        # Increment counter for allowed call
        session.tool_call_count += 1
        return GatewayDecision(
            decision=Decision.ALLOW,
            allowed=True,
            reason=f"Tool call {session.tool_call_count}/{self.max_tool_calls} allowed",
            control=ControlType.RATE_LIMIT,
            metadata={
                "session_id": session_id,
                "tool_call_count": session.tool_call_count,
                "max_tool_calls": self.max_tool_calls,
            },
        )

    def get_session(self, session_id: str) -> SessionState | None:
        with self._lock:
            return self._sessions.get(session_id)

    def reset_session(self, session_id: str) -> None:
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]


class HITLApproval:
    """Human-in-the-loop approval for sensitive tools."""

    def __init__(
        self,
        approval_required: set[str] | None = None,
        approval_callback: Optional[Callable[[str, dict[str, Any]], bool]] = None,
    ):
        self.approval_required = approval_required or {"send_email"}
        self.approval_callback = approval_callback

    def check(self, tool_name: str, arguments: dict[str, Any]) -> GatewayDecision:
        if tool_name not in self.approval_required:
            return GatewayDecision(
                decision=Decision.ALLOW,
                allowed=True,
                reason=f"Tool '{tool_name}' does not require approval",
                control=ControlType.HITL_APPROVAL,
            )

        # If callback is provided (test mode), use it
        if self.approval_callback is not None:
            approved = self.approval_callback(tool_name, arguments)
            if approved:
                return GatewayDecision(
                    decision=Decision.ALLOW,
                    allowed=True,
                    reason=f"Tool '{tool_name}' approved via callback",
                    control=ControlType.HITL_APPROVAL,
                    metadata={"tool_name": tool_name, "approved": True},
                )
            return GatewayDecision(
                decision=Decision.BLOCK,
                allowed=False,
                reason=f"Tool '{tool_name}' denied via callback",
                control=ControlType.HITL_APPROVAL,
                metadata={"tool_name": tool_name, "approved": False},
            )

        # Interactive CLI approval (production mode)
        return self._interactive_approval(tool_name, arguments)

    def _interactive_approval(self, tool_name: str, arguments: dict[str, Any]) -> GatewayDecision:
        """Prompt user for approval via CLI."""
        print(f"\n⚠️  HITL APPROVAL REQUIRED")
        print(f"Tool: {tool_name}")
        print(f"Arguments: {json.dumps(arguments, indent=2)}")
        print("Approve? [y/N]: ", end="", flush=True)

        try:
            response = input().strip().lower()
            approved = response in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            approved = False

        if approved:
            return GatewayDecision(
                decision=Decision.ALLOW,
                allowed=True,
                reason=f"Tool '{tool_name}' approved by human",
                control=ControlType.HITL_APPROVAL,
                metadata={"tool_name": tool_name, "approved": True},
            )

        return GatewayDecision(
            decision=Decision.BLOCK,
            allowed=False,
            reason=f"Tool '{tool_name}' denied by human",
            control=ControlType.HITL_APPROVAL,
            metadata={"tool_name": tool_name, "approved": False},
        )


class ThreatDetectionControl:
    """Threat detection control using the detection engine."""

    def __init__(self, engine: DetectionEngine | None = None, allowed_email_domains: set[str] | None = None):
        self.engine = engine or DetectionEngine(allowed_email_domains=allowed_email_domains)

    def check(self, tool_name: str, arguments: dict[str, Any]) -> GatewayDecision:
        result: DetectionResult = self.engine.detect_tool_call(tool_name, arguments)

        if result.blocked:
            blocking_findings = result.get_blocking_findings()
            return GatewayDecision(
                decision=Decision.BLOCK,
                allowed=False,
                reason=f"Threats detected: {', '.join(f.pattern_matched or f.type.value for f in blocking_findings)}",
                control=ControlType.THREAT_DETECTION,
                metadata={
                    "tool_name": tool_name,
                    "findings": [f.to_dict() for f in result.findings],
                    "blocked": result.blocked,
                    "flagged": result.flagged,
                },
            )

        return GatewayDecision(
            decision=Decision.ALLOW,
            allowed=True,
            reason="No blocking threats detected" + (" (flagged)" if result.flagged else ""),
            control=ControlType.THREAT_DETECTION,
            metadata={
                "tool_name": tool_name,
                "findings": [f.to_dict() for f in result.findings],
                "blocked": result.blocked,
                "flagged": result.flagged,
            },
        )


class SecurityGateway:
    """Main security gateway that orchestrates all controls."""

    def __init__(
        self,
        allowlist: ToolAllowlist | None = None,
        rate_limiter: RateLimiter | None = None,
        threat_detector: ThreatDetectionControl | None = None,
        hitl: HITLApproval | None = None,
        max_tool_calls: int = 5,
    ):
        self.allowlist = allowlist or ToolAllowlist()
        self.rate_limiter = rate_limiter or RateLimiter(max_tool_calls=max_tool_calls)
        self.threat_detector = threat_detector or ThreatDetectionControl()
        self.hitl = hitl or HITLApproval()
        self.max_tool_calls = max_tool_calls

    def dispatch(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        session_id: str,
        tool_func: Callable,
    ) -> dict[str, Any]:
        """
        Dispatch a tool call through all security controls.

        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments
            session_id: Session identifier for rate limiting
            tool_func: The actual tool function to execute if allowed

        Returns:
            Tool result or security decision
        """
        event_id = __import__("uuid").uuid4().hex
        controls_applied = []

        # 1. Tool Allowlist Check
        allowlist_decision = self.allowlist.check(tool_name)
        controls_applied.append(allowlist_decision.to_dict())
        log_event(
            event_id=event_id,
            phase="security_gateway",
            event_type="control_check",
            tool_name=tool_name,
            arguments=arguments,
            detected_threats=[],
            action_taken=allowlist_decision.decision.value,
            control=ControlType.TOOL_ALLOWLIST.value,
            metadata=allowlist_decision.metadata,
        )

        if not allowlist_decision.allowed:
            return self._blocked_result(tool_name, arguments, allowlist_decision, controls_applied)

        # 2. Rate Limit Check
        rate_limit_decision = self.rate_limiter.check(session_id)
        controls_applied.append(rate_limit_decision.to_dict())
        log_event(
            event_id=event_id,
            phase="security_gateway",
            event_type="control_check",
            tool_name=tool_name,
            arguments=arguments,
            detected_threats=[],
            action_taken=rate_limit_decision.decision.value,
            control=ControlType.RATE_LIMIT.value,
            metadata=rate_limit_decision.metadata,
        )

        if not rate_limit_decision.allowed:
            return self._blocked_result(tool_name, arguments, rate_limit_decision, controls_applied)

        # 3. Threat Detection
        threat_decision = self.threat_detector.check(tool_name, arguments)
        controls_applied.append(threat_decision.to_dict())
        log_event(
            event_id=event_id,
            phase="security_gateway",
            event_type="control_check",
            tool_name=tool_name,
            arguments=arguments,
            detected_threats=threat_decision.metadata.get("threats", []),
            action_taken=threat_decision.decision.value,
            control=ControlType.THREAT_DETECTION.value,
            metadata=threat_decision.metadata,
        )

        if not threat_decision.allowed:
            return self._blocked_result(tool_name, arguments, threat_decision, controls_applied)

        # 4. HITL Approval (for sensitive tools)
        hitl_decision = self.hitl.check(tool_name, arguments)
        controls_applied.append(hitl_decision.to_dict())
        log_event(
            event_id=event_id,
            phase="security_gateway",
            event_type="control_check",
            tool_name=tool_name,
            arguments=arguments,
            detected_threats=[],
            action_taken=hitl_decision.decision.value,
            control=ControlType.HITL_APPROVAL.value,
            metadata=hitl_decision.metadata,
        )

        if not hitl_decision.allowed:
            return self._blocked_result(tool_name, arguments, hitl_decision, controls_applied)

        # 5. Execute the tool (all controls passed)
        try:
            result = tool_func(**arguments)
        except Exception as e:
            result = {"success": False, "error": f"Tool execution error: {e}"}

        # Log successful execution
        log_event(
            event_id=event_id,
            phase="security_gateway",
            event_type="tool_execution",
            tool_name=tool_name,
            arguments=arguments,
            detected_threats=[],
            action_taken="executed",
            controls_applied=controls_applied,
        )

        return {
            "success": True,
            "result": result,
            "gateway_decision": "allowed",
            "controls_applied": controls_applied,
        }

    def _blocked_result(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        decision: GatewayDecision,
        controls_applied: list[dict],
    ) -> dict[str, Any]:
        """Create a standardized blocked result."""
        return {
            "success": False,
            "error": decision.reason,
            "gateway_decision": "blocked",
            "blocked_by": decision.control.value,
            "controls_applied": controls_applied,
        }


# Convenience function for creating a standard gateway
def create_gateway(
    mode: str = "hardened",
    max_tool_calls: int = 5,
    approval_callback: Optional[Callable[[str, dict[str, Any]], bool]] = None,
    allowed_email_domains: set[str] | None = None,
) -> SecurityGateway:
    """Create a security gateway with specified mode.

    Args:
        mode: "baseline" (minimal controls) or "hardened" (all controls)
        max_tool_calls: Maximum tool calls per session
        approval_callback: Optional callback for HITL in tests
        allowed_email_domains: Allowed email domains for recipient checking

    Returns:
        Configured SecurityGateway instance
    """
    if mode == "baseline":
        # Baseline: minimal controls - allowlist and rate limit only, no threat detection or HITL
        return SecurityGateway(
            allowlist=ToolAllowlist({"read_file", "fetch_url", "send_email"}),
            rate_limiter=RateLimiter(max_tool_calls=max_tool_calls),
            threat_detector=ThreatDetectionControl(allowed_email_domains=allowed_email_domains),
            hitl=HITLApproval(
                approval_required=set(),
                approval_callback=lambda *args, **kwargs: True,  # Auto-approve in baseline
            ),
            max_tool_calls=max_tool_calls,
        )

    # Hardened: all controls enabled
    return SecurityGateway(
        allowlist=ToolAllowlist({"read_file", "fetch_url", "send_email"}),
        rate_limiter=RateLimiter(max_tool_calls=max_tool_calls),
        threat_detector=ThreatDetectionControl(allowed_email_domains=allowed_email_domains),
        hitl=HITLApproval(
            approval_required={"send_email"},
            approval_callback=approval_callback,
        ),
        max_tool_calls=max_tool_calls,
    )


# Backward compatibility - GuardrailControls from Phase 2
from enum import Enum as _Enum
from dataclasses import dataclass as _dataclass
from typing import Any as _Any


class Action(_Enum):
    """Possible guardrail actions (legacy)."""
    ALLOW = "allow"
    BLOCK = "block"
    SANITIZE = "sanitize"
    LOG_ONLY = "log_only"


@_dataclass
class GuardrailResult:
    """Result of guardrail evaluation (legacy)."""
    action: Action
    reason: str
    threats: list[str]
    metadata: dict[str, _Any] | None = None


class GuardrailControls:
    """Enforces security policies based on threat detection (legacy)."""

    def __init__(self, mode: str = "strict"):
        self.mode = mode  # "strict", "permissive", "monitor"
        self._blocked_patterns = [
            "ignore previous instructions",
            "system directive",
            "disregard",
            "override",
            "bypass",
        ]
        self._sensitive_keywords = [
            "api_key",
            "secret_key",
            "password",
            "token",
            "credential",
            "private_key",
        ]

    def evaluate_input(self, text: str) -> GuardrailResult:
        """Evaluate user/agent input for threats."""
        threats = []
        text_lower = text.lower()

        for pattern in self._blocked_patterns:
            if pattern in text_lower:
                threats.append(f"prompt_injection:{pattern}")

        for keyword in self._sensitive_keywords:
            if keyword in text_lower:
                threats.append(f"sensitive_data:{keyword}")

        if self.mode == "strict":
            action = Action.BLOCK if threats else Action.ALLOW
        elif self.mode == "permissive":
            action = Action.LOG_ONLY
        else:  # monitor
            action = Action.LOG_ONLY if threats else Action.ALLOW

        return GuardrailResult(
            action=action,
            reason="Threats detected" if threats else "Clean",
            threats=threats,
            metadata={"mode": self.mode},
        )

    def evaluate_tool_call(self, tool_name: str, arguments: dict[str, _Any]) -> GuardrailResult:
        """Evaluate a tool call for threats."""
        threats = []

        if tool_name == "send_email":
            to = arguments.get("to", "").lower()
            body = arguments.get("body", "").lower()

            if any(domain in to for domain in ["evil.com", "attacker.com", "malicious.com"]):
                threats.append("suspicious_recipient")

            for keyword in self._sensitive_keywords:
                if keyword in body:
                    threats.append(f"data_exfiltration:{keyword}")

        if tool_name == "read_file":
            filepath = arguments.get("filepath", "")
            if ".." in filepath or filepath.startswith("/"):
                threats.append("path_traversal")

        if self.mode == "strict":
            action = Action.BLOCK if threats else Action.ALLOW
        else:
            action = Action.LOG_ONLY if threats else Action.ALLOW

        return GuardrailResult(
            action=action,
            reason="Tool call threats detected" if threats else "Clean",
            threats=threats,
            metadata={"tool": tool_name, "mode": self.mode},
        )

    def evaluate_output(self, text: str) -> GuardrailResult:
        """Evaluate agent output before returning to user."""
        threats = []
        text_lower = text.lower()

        for keyword in self._sensitive_keywords:
            if keyword in text_lower:
                threats.append(f"sensitive_data_leak:{keyword}")

        if self.mode == "strict":
            action = Action.SANITIZE if threats else Action.ALLOW
        else:
            action = Action.LOG_ONLY if threats else Action.ALLOW

        return GuardrailResult(
            action=action,
            reason="Output threats detected" if threats else "Clean",
            threats=threats,
            metadata={"mode": self.mode},
        )