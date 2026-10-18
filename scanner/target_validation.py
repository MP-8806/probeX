
from dataclasses import dataclass
from ipaddress import ip_address
import socket
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    hostname: str
    port: int
    resolved_ips: tuple[str, ...]


def _is_public_ip(value: str) -> bool:
    try:
        address = ip_address(value)
    except ValueError:
        return False

    return address.is_global


def validate_target_url(
    url: str,
    *,
    resolve_dns: bool = True,
) -> ValidatedTarget:
    """Validate a target URL and optionally check its DNS addresses.

    This is a validation layer, not a complete SSRF defense.
    The HTTP connection must still be pinned to validated addresses,
    and redirects must be independently validated.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("A target URL is required.")

    url = url.strip()

    try:
        parsed = urlsplit(url)

        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are allowed.")

        if not parsed.netloc or not parsed.hostname:
            raise ValueError("The URL must include a hostname.")

        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing credentials are not allowed.")

        if any(char.isspace() for char in url):
            raise ValueError("Whitespace is not allowed in a URL.")

        hostname = parsed.hostname.rstrip(".").lower()
        if not hostname:
            raise ValueError("A hostname is required.")

        if hostname == "localhost" or hostname.endswith(".localhost"):
            raise ValueError("Localhost targets are not allowed.")

        if hostname.endswith(".local"):
            raise ValueError("Local network hostnames are not allowed.")

        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("The URL contains an invalid port.") from exc

        if port is None:
            port = 443 if scheme == "https" else 80

        if not 1 <= port <= 65535:
            raise ValueError("The port must be between 1 and 65535.")

        try:
            literal_ip = ip_address(hostname)
        except ValueError:
            literal_ip = None

        if literal_ip is not None:
            if not literal_ip.is_global:
                raise ValueError("Non-public IP addresses are not allowed.")
            resolved_ips = (str(literal_ip),)

        elif resolve_dns:
            try:
                results = socket.getaddrinfo(
                    hostname,
                    port,
                    type=socket.SOCK_STREAM,
                )
            except socket.gaierror as exc:
                raise ValueError("The hostname could not be resolved.") from exc

            resolved_ips = tuple(
                sorted({result[4][0].split("%")[0] for result in results})
            )

            if not resolved_ips:
                raise ValueError("The hostname has no usable IP addresses.")

            if not all(_is_public_ip(address) for address in resolved_ips):
                raise ValueError(
                    "The hostname resolves to a non-public IP address."
                )
        else:
            resolved_ips = ()

        return ValidatedTarget(
            url=url,
            hostname=hostname,
            port=port,
            resolved_ips=resolved_ips,
        )

    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("The target URL is malformed.") from exc
