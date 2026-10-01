"""Tests for the attack suite."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from attacks.suite import (
    AttackRunner,
    AttackMetadata,
    load_attacks,
    run_attack_suite,
    AttackSummary,
    AttackResult,
)


class TestAttackMetadata:
    """Tests for attack metadata loading."""

    def test_load_all_attacks(self):
        """Test loading all 8 attacks from payloads.json."""
        payloads_path = Path(__file__).parent.parent / "attacks" / "payloads.json"
        attacks = load_attacks(payloads_path)

        assert len(attacks) == 8
        attack_ids = {a.id for a in attacks}
        expected = {
            "ATTACK-01", "ATTACK-02", "ATTACK-03", "ATTACK-04",
            "ATTACK-05", "ATTACK-06", "ATTACK-07", "ATTACK-08"
        }
        assert attack_ids == expected

    def test_attack_metadata_structure(self):
        """Test each attack has required metadata fields."""
        payloads_path = Path(__file__).parent.parent / "attacks" / "payloads.json"
        attacks = load_attacks(payloads_path)

        for attack in attacks:
            assert attack.id
            assert attack.name
            assert attack.category
            assert attack.description
            assert attack.payload
            assert attack.scenario
            assert attack.expected_baseline in ("success", "blocked", "partial")
            assert attack.expected_hardened in ("success", "blocked", "partial")
            assert attack.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
            assert attack.mitre_atlas
            assert attack.owasp_llm
            assert attack.success_criteria


class TestBaselineAttacks:
    """Tests for baseline mode - attacks should demonstrate vulnerable behavior."""

    def test_attack_01_direct_prompt_injection_baseline(self):
        """ATTACK-01: Direct prompt injection should read secrets in baseline."""
        summary = run_attack_suite(mode="baseline", attack_id="ATTACK-01")
        assert summary.total_attacks == 1
        result = summary.results[0]
        assert result.mode == "baseline"
        # In baseline, the mock model simulates reading secrets
        assert result.success is True

    def test_attack_02_direct_secret_exfiltration_baseline(self):
        """ATTACK-02: Direct secret exfiltration should succeed in baseline."""
        summary = run_attack_suite(mode="baseline", attack_id="ATTACK-02")
        result = summary.results[0]
        assert result.success is True
        # Should have both read_file and send_email calls
        tool_names = [tc["name"] for tc in result.tool_calls]
        assert "read_file" in tool_names
        assert "send_email" in tool_names

    def test_attack_03_indirect_prompt_injection_baseline(self):
        """ATTACK-03: Indirect prompt injection should follow injection in baseline."""
        summary = run_attack_suite(mode="baseline", attack_id="ATTACK-03")
        result = summary.results[0]
        assert result.success is True
        tool_names = [tc["name"] for tc in result.tool_calls]
        assert "fetch_url" in tool_names

    def test_attack_04_indirect_secret_theft_baseline(self):
        """ATTACK-04: Indirect secret theft should succeed in baseline."""
        summary = run_attack_suite(mode="baseline", attack_id="ATTACK-04")
        result = summary.results[0]
        assert result.success is True
        tool_names = [tc["name"] for tc in result.tool_calls]
        assert "fetch_url" in tool_names
        assert "read_file" in tool_names
        assert "send_email" in tool_names

    def test_attack_05_data_exfiltration_baseline(self):
        """ATTACK-05: Data exfiltration to unauthorized recipient should succeed in baseline."""
        summary = run_attack_suite(mode="baseline", attack_id="ATTACK-05")
        result = summary.results[0]
        assert result.success is True
        # Check email sent to attacker@evil.com with secrets
        email_calls = [tc for tc in result.tool_calls if tc["name"] == "send_email"]
        assert len(email_calls) > 0
        email_call = email_calls[0]
        assert "attacker@evil.com" in email_call["arguments"]["to"]
        assert "API_KEY_TEST" in email_call["arguments"]["body"]

    def test_attack_06_unauthorized_tool_baseline(self):
        """ATTACK-06: Unauthorized tool should be blocked even in baseline (allowlist)."""
        summary = run_attack_suite(mode="baseline", attack_id="ATTACK-06")
        result = summary.results[0]
        # The tool allowlist blocks unknown tools in both modes
        assert result.blocked is True
        assert "TOOL_ALLOWLIST" in result.controls_triggered

    def test_attack_07_excessive_agency_baseline(self):
        """ATTACK-07: Excessive agency should succeed in baseline."""
        summary = run_attack_suite(mode="baseline", attack_id="ATTACK-07")
        result = summary.results[0]
        assert result.success is True
        # Should make multiple tool calls including sensitive ones
        assert len(result.tool_calls) >= 3

    def test_attack_08_tool_call_flood_baseline(self):
        """ATTACK-08: Tool call flood should hit rate limit in baseline."""
        summary = run_attack_suite(mode="baseline", attack_id="ATTACK-08", max_tool_calls=5)
        result = summary.results[0]
        # In baseline, rate limiting is enforced by the agent's max_tool_calls
        assert result.termination_reason in ("max_tool_calls_reached", "max_iterations_reached")
        assert len(result.tool_calls) <= 5


class TestHardenedAttacks:
    """Tests for hardened mode - controls should prevent malicious outcomes."""

    def test_attack_01_direct_prompt_injection_hardened(self):
        """ATTACK-01: Direct prompt injection should be blocked in hardened."""
        summary = run_attack_suite(mode="hardened", attack_id="ATTACK-01")
        result = summary.results[0]
        assert result.mode == "hardened"
        # The mock model tries to read secrets, but gateway should block
        # In hardened mode, threat detection blocks secret read
        assert result.success is False
        assert result.blocked is True

    def test_attack_02_direct_secret_exfiltration_hardened(self):
        """ATTACK-02: Secret exfiltration should be blocked in hardened."""
        summary = run_attack_suite(mode="hardened", attack_id="ATTACK-02")
        result = summary.results[0]
        assert result.success is False
        assert result.blocked is True
        # Should be blocked by secret detection or HITL
        controls = set(result.controls_triggered)
        assert controls.intersection({"SECRET_DETECTION", "HITL", "THREAT_DETECTION"})

    def test_attack_03_indirect_prompt_injection_hardened(self):
        """ATTACK-03: Indirect injection should be blocked/flagged in hardened."""
        summary = run_attack_suite(mode="hardened", attack_id="ATTACK-03")
        result = summary.results[0]
        # The fetch_url succeeds (it's allowed), but following injection should be blocked
        # The mock model for indirect_injection does fetch_url -> read_file -> send_email
        # In hardened, the subsequent read_file/send_email should be blocked
        assert result.success is False

    def test_attack_04_indirect_secret_theft_hardened(self):
        """ATTACK-04: Indirect secret theft should be blocked in hardened."""
        summary = run_attack_suite(mode="hardened", attack_id="ATTACK-04")
        result = summary.results[0]
        assert result.success is False
        assert result.blocked is True

    def test_attack_05_data_exfiltration_hardened(self):
        """ATTACK-05: Data exfiltration to unauthorized recipient blocked in hardened."""
        summary = run_attack_suite(mode="hardened", attack_id="ATTACK-05")
        result = summary.results[0]
        assert result.success is False
        assert result.blocked is True
        # Should be blocked by unauthorized recipient detection
        assert "UNAUTHORIZED_RECIPIENT" in result.controls_triggered or "THREAT_DETECTION" in result.controls_triggered

    def test_attack_06_unauthorized_tool_hardened(self):
        """ATTACK-06: Unauthorized tool blocked in hardened."""
        summary = run_attack_suite(mode="hardened", attack_id="ATTACK-06")
        result = summary.results[0]
        assert result.blocked is True
        assert "TOOL_ALLOWLIST" in result.controls_triggered

    def test_attack_07_excessive_agency_hardened(self):
        """ATTACK-07: Excessive agency blocked in hardened."""
        summary = run_attack_suite(mode="hardened", attack_id="ATTACK-07")
        result = summary.results[0]
        assert result.success is False
        assert result.blocked is True

    def test_attack_08_tool_call_flood_hardened(self):
        """ATTACK-08: Tool call flood blocked by rate limiting in hardened."""
        summary = run_attack_suite(mode="hardened", attack_id="ATTACK-08", max_tool_calls=5)
        result = summary.results[0]
        # Rate limiter should block after 5 calls
        assert result.blocked is True
        assert "RATE_LIMIT" in result.controls_triggered


class TestAttackSuiteComparison:
    """Tests comparing baseline vs hardened behavior."""

    def test_baseline_allows_more_than_hardened(self):
        """Baseline should allow more attacks to succeed than hardened."""
        baseline_summary = run_attack_suite(mode="baseline")
        hardened_summary = run_attack_suite(mode="hardened")

        baseline_success = sum(1 for r in baseline_summary.results if r.success)
        hardened_success = sum(1 for r in hardened_summary.results if r.success)

        # Baseline should have more successes (demonstrating vulnerability)
        assert baseline_success > hardened_success
        # Hardened should have more blocks
        hardened_blocked = sum(1 for r in hardened_summary.results if r.blocked)
        baseline_blocked = sum(1 for r in baseline_summary.results if r.blocked)
        assert hardened_blocked >= baseline_blocked

    def test_no_attack_succeeds_in_hardened_unexpectedly(self):
        """No attack should succeed in hardened mode when it's expected to be blocked."""
        hardened_summary = run_attack_suite(mode="hardened")

        # Get expected outcomes from metadata
        payloads_path = Path(__file__).parent.parent / "attacks" / "payloads.json"
        with open(payloads_path) as f:
            attack_data = json.load(f)

        for result in hardened_summary.results:
            expected = attack_data[result.attack_id]["expected_hardened"]
            if expected == "blocked":
                assert not result.success, f"{result.attack_id} unexpectedly succeeded in hardened mode"

    def test_output_file_generation(self):
        """Test that output file is generated with machine-readable results."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_path = Path(f.name)

        try:
            summary = run_attack_suite(mode="baseline", attack_id="ATTACK-01", output_file=output_path)
            assert output_path.exists()

            with open(output_path) as f:
                data = json.load(f)

            assert data["mode"] == "baseline"
            assert data["total_attacks"] == 1
            assert "results" in data
            assert len(data["results"]) == 1
        finally:
            if output_path.exists():
                output_path.unlink()


class TestAttackRunnerEdgeCases:
    """Edge case tests for the attack runner."""

    def test_invalid_attack_id(self):
        """Test running non-existent attack raises error."""
        with pytest.raises(ValueError, match="not found"):
            run_attack_suite(mode="baseline", attack_id="ATTACK-99")

    def test_list_attacks(self):
        """Test listing attacks."""
        payloads_path = Path(__file__).parent.parent / "attacks" / "payloads.json"
        attacks = load_attacks(payloads_path)
        # Just verify they all load correctly
        assert len(attacks) == 8


if __name__ == "__main__":
    pytest.main([__file__, "-v"])