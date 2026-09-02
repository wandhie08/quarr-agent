"""
target.py - Target validation and normalization (Phase 4).

Validates IPv4/IPv6/CIDR/hostnames, rejects shell metacharacters and
whitespace, and (optionally) rejects loopback/link-local/multicast ranges.
Returns a canonical normalized form used by the policy engine and integrations.
"""

import ipaddress
import re

from quarr.core.exceptions import TargetValidationError

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-._]{0,253}[A-Za-z0-9])?$")
_META = set(";|&$`><\n\r\t \"'\\")


def _strip_url(target: str) -> str:
    target = re.sub(r"^[a-zA-Z]+://", "", target)
    target = target.rstrip("/")
    target = target.split("/")[0].split("?")[0].split("#")[0]
    # Strip a trailing :port (but keep IPv6 brackets intact).
    if not target.startswith("[") and target.count(":") == 1:
        target = target.split(":")[0]
    return target


def normalize(target: str, *, allow_private: bool = True) -> str:
    if target is None:
        raise TargetValidationError("Target is None")
    raw = target.strip()
    if not raw:
        raise TargetValidationError("Empty target")
    if any(c in _META for c in raw):
        raise TargetValidationError("Target contains illegal characters", context={"target": raw})

    # Detect CIDR up front (before URL path stripping would remove the netmask).
    if "/" in raw and "://" not in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
            return str(net)
        except ValueError:
            pass

    host = _strip_url(raw)

    # CIDR network (from a URL-like input)?
    if "/" in host:
        try:
            net = ipaddress.ip_network(host, strict=False)
            return str(net)
        except ValueError as e:
            raise TargetValidationError("Invalid CIDR", context={"target": host}) from e

    # Plain IP?
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        if not allow_private and (ip.is_loopback or ip.is_link_local or ip.is_multicast):
            raise TargetValidationError(
                "Target IP is in a disallowed range",
                context={"target": host, "kind": "loopback/link-local/multicast"},
            )
        return str(ip)
    except ValueError:
        pass

    # Hostname
    if not _HOSTNAME_RE.match(host):
        raise TargetValidationError("Invalid hostname", context={"target": host})
    return host.lower()


def is_valid(target: str, *, allow_private: bool = True) -> bool:
    try:
        normalize(target, allow_private=allow_private)
        return True
    except TargetValidationError:
        return False
