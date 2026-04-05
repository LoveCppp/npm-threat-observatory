from __future__ import annotations

from datetime import datetime, timezone

from app.models import SecurityEvent, Severity, Verdict
from app.verdicts import severity_from_rule, summarize_events


def make_event(rule: str, severity: Severity) -> SecurityEvent:
    return SecurityEvent(
        analysis_id="analysis-1",
        container_id="container-1",
        phase="install",
        rule=rule,
        priority="warning",
        severity=severity,
        source="falco",
        output=rule,
        event_time=datetime.now(timezone.utc),
        details={},
    )


def test_summarize_events_returns_clean_for_empty_events():
    verdict, risk_level, summary = summarize_events([])
    assert verdict == Verdict.CLEAN
    assert risk_level == "none"
    assert "No suspicious" in summary


def test_summarize_events_returns_malicious_for_high_severity():
    verdict, risk_level, summary = summarize_events(
        [make_event("npm sensitive credential access", Severity.HIGH)]
    )
    assert verdict == Verdict.MALICIOUS
    assert risk_level == "high"
    assert "credential" in summary


def test_severity_from_rule_detects_medium_network_rule():
    assert severity_from_rule("npm suspicious network activity", "warning") == Severity.MEDIUM
