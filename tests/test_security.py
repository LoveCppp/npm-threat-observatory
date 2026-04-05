from __future__ import annotations

from app.security import allowed_hosts_from_urls, is_blocked_host


def test_allowed_hosts_from_urls_extracts_hostnames():
    hosts = allowed_hosts_from_urls(["http://control-api:8000", "https://registry.npmjs.org"])
    assert hosts == {"control-api", "registry.npmjs.org"}


def test_is_blocked_host_rejects_private_ip():
    assert is_blocked_host("192.168.1.10", set(), resolve_dns=False) is True


def test_is_blocked_host_allows_allowlisted_internal_service():
    assert is_blocked_host("control-api", {"control-api"}, resolve_dns=False) is False


def test_is_blocked_host_allows_public_domain():
    assert is_blocked_host("registry.npmjs.org", set(), resolve_dns=False) is False
