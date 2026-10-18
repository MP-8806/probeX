
import socket

import pytest

from scanner.target_validation import validate_target_url


@pytest.mark.parametrize(
    ("url", "expected_host", "expected_port"),
    [
        ("https://example.com", "example.com", 443),
        ("http://example.com/path", "example.com", 80),
        ("https://example.com:8443/test", "example.com", 8443),
        ("https://EXAMPLE.COM/", "example.com", 443),
    ],
)
def test_accepts_valid_url_syntax(url, expected_host, expected_port):
    target = validate_target_url(url, resolve_dns=False)

    assert target.hostname == expected_host
    assert target.port == expected_port
    assert target.url == url


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "ftp://example.com",
        "file:///etc/passwd",
        "https://",
        "https://user:password@example.com",
        "http://localhost",
        "http://service.local",
        "http://127.0.0.1",
        "http://10.0.0.1",
        "http://[::1]",
        "https://example.com:99999",
        "https://example.com:invalid",
        "https://example.com/path with spaces",
    ],
)
def test_rejects_invalid_or_unsafe_url_syntax(url):
    with pytest.raises(ValueError):
        validate_target_url(url, resolve_dns=False)


def _dns_result(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
    return (
        family,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        sockaddr,
    )


def test_accepts_hostname_with_public_dns_results(monkeypatch):
    monkeypatch.setattr(
        "scanner.target_validation.socket.getaddrinfo",
        lambda *args, **kwargs: [_dns_result("93.184.216.34")],
    )

    target = validate_target_url("https://example.com")

    assert target.resolved_ips == ("93.184.216.34",)


def test_rejects_hostname_resolving_to_private_ip(monkeypatch):
    monkeypatch.setattr(
        "scanner.target_validation.socket.getaddrinfo",
        lambda *args, **kwargs: [_dns_result("10.0.0.5")],
    )

    with pytest.raises(ValueError, match="non-public"):
        validate_target_url("https://example.com")


def test_rejects_hostname_with_mixed_public_and_private_ips(monkeypatch):
    monkeypatch.setattr(
        "scanner.target_validation.socket.getaddrinfo",
        lambda *args, **kwargs: [
            _dns_result("93.184.216.34"),
            _dns_result("192.168.1.10"),
        ],
    )

    with pytest.raises(ValueError, match="non-public"):
        validate_target_url("https://example.com")


def test_rejects_hostname_when_dns_fails(monkeypatch):
    def fail_dns(*args, **kwargs):
        raise socket.gaierror("simulated DNS failure")

    monkeypatch.setattr(
        "scanner.target_validation.socket.getaddrinfo",
        fail_dns,
    )

    with pytest.raises(ValueError, match="could not be resolved"):
        validate_target_url("https://example.com")
