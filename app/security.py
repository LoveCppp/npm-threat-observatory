from __future__ import annotations

import ipaddress
import socket
from typing import Iterable, Set
from urllib.parse import urlparse


LOCAL_HOSTNAMES = {
    "localhost",
    "host.docker.internal",
    "host.containers.internal",
    "gateway.containers.internal",
}
LOCAL_SUFFIXES = (".local", ".internal", ".lan", ".home")


def allowed_hosts_from_urls(urls: Iterable[str]) -> Set[str]:
    hosts: Set[str] = set()
    for url in urls:
        host = hostname_from_url(url)
        if host:
            hosts.add(host)
    return hosts


def hostname_from_url(url: str) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    return normalize_host(parsed.hostname)


def normalize_host(host: str | None) -> str | None:
    if not host:
        return None
    return host.strip().lower().strip("[]")


def is_blocked_host(host: str | None, allowlist: Iterable[str], resolve_dns: bool = True) -> bool:
    normalized = normalize_host(host)
    if not normalized:
        return False

    allowed = {value for value in (normalize_host(item) for item in allowlist) if value}
    if normalized in allowed:
        return False
    if normalized in LOCAL_HOSTNAMES or normalized.endswith(LOCAL_SUFFIXES):
        return True
    if _ip_is_blocked(normalized):
        return True
    if not resolve_dns:
        return False

    try:
        infos = socket.getaddrinfo(normalized, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False

    addresses = {info[4][0] for info in infos if info[4] and info[4][0]}
    return any(_ip_is_blocked(address) for address in addresses)


def _ip_is_blocked(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False

    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    if ip.is_private:
        return True
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return True
    return False
