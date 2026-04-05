from __future__ import annotations

from collections.abc import Iterable
from typing import Tuple

from app.models import SecurityEvent, Severity, Verdict


SEVERITY_ORDER = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}


def summarize_events(events: Iterable[SecurityEvent]) -> Tuple[Verdict, str, str]:
    events = list(events)
    if not events:
        return Verdict.CLEAN, "none", "No suspicious Falco event was associated with this analysis."

    highest = max(events, key=lambda item: SEVERITY_ORDER[item.severity])
    distinct_rules = sorted({event.rule for event in events})

    if highest.severity == Severity.HIGH:
        verdict = Verdict.MALICIOUS
        risk_level = "high"
    elif highest.severity == Severity.MEDIUM:
        verdict = Verdict.SUSPICIOUS
        risk_level = "medium"
    else:
        verdict = Verdict.SUSPICIOUS
        risk_level = "low"

    summary = f"{len(events)} suspicious event(s); highest severity={risk_level}; rules={', '.join(distinct_rules)}"
    return verdict, risk_level, summary


def severity_from_rule(rule: str, priority: str) -> Severity:
    text = f"{rule} {priority}".lower()
    if any(token in text for token in ["credential", "reverse shell", "download and execute", "binary"]):
        return Severity.HIGH
    if any(token in text for token in ["network", "shell", "profile", "cron", "sensitive"]):
        return Severity.MEDIUM
    return Severity.LOW
