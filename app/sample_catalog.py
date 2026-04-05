from __future__ import annotations

SAMPLE_PREFIX = "sample://"

SAMPLES = [
    {
        "id": "benign",
        "title": "Benign Baseline",
        "description": "Simple local function export with no suspicious network, process, or credential access.",
        "runtime_mode": "require",
        "package_name": "benign",
        "version": "local",
    },
    {
        "id": "malicious-postinstall",
        "title": "Malicious Postinstall",
        "description": "Lifecycle script runs curl | sh during installation to simulate install-time package poisoning.",
        "runtime_mode": "none",
        "package_name": "malicious-postinstall",
        "version": "local",
    },
    {
        "id": "malicious-runtime",
        "title": "Malicious Runtime",
        "description": "Module reaches out over the network when required to simulate runtime beaconing.",
        "runtime_mode": "require",
        "package_name": "malicious-runtime",
        "version": "local",
    },
]


def get_sample(sample_id: str) -> dict | None:
    for sample in SAMPLES:
        if sample["id"] == sample_id:
            return sample
    return None


def sample_registry_url(sample_id: str) -> str:
    return f"{SAMPLE_PREFIX}{sample_id}"


def is_sample_registry_url(value: str) -> bool:
    return value.startswith(SAMPLE_PREFIX)


def sample_id_from_registry_url(value: str) -> str | None:
    if not is_sample_registry_url(value):
        return None
    return value[len(SAMPLE_PREFIX) :]
