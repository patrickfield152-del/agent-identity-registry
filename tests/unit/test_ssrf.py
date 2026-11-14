"""Behavior and security tests for SSRF protection in auth/ssrf.py."""

import random
import time
from unittest.mock import patch

import pytest

from attestix.auth.ssrf import validate_url_host


BLOCKED_HOSTS = [
    "localhost", "127.0.0.1", "::1", "10.0.0.1", "192.168.1.1",
    "172.16.0.1", "169.254.169.254", "myserver.local", "api.internal",
    "metadata.google.internal", "0.0.0.0", "", "[::1]",
]


@pytest.mark.parametrize("host", BLOCKED_HOSTS)
def test_blocks_unsafe_host(host):
    assert validate_url_host(host) is not None


def test_allows_public_ip_and_dns():
    assert validate_url_host("8.8.8.8") is None
    with patch("attestix.auth.ssrf.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(2, 1, 0, "", ("93.184.216.34", 0))]
        assert validate_url_host("example.com") is None


def test_blocks_dns_rebinding():
    with patch("attestix.auth.ssrf.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(2, 1, 0, "", ("127.0.0.1", 0))]
        result = validate_url_host("evil.example.com")
        assert result is not None
        assert "private" in result.lower() or "blocked" in result.lower()


def test_proactive_host_check_budget():
    t0 = time.perf_counter()
    for _ in range(200):
        assert validate_url_host("10.1.2.3") is not None
    assert (time.perf_counter() - t0) < 0.25


def test_reactive_private_cidr_fuzz():
    rng = random.Random(1794653767)
    for _ in range(50):
        ip = f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
        assert validate_url_host(ip) is not None
        ip_192 = f"192.168.{rng.randrange(256)}.{rng.randrange(1, 255)}"
        assert validate_url_host(ip_192) is not None
