from __future__ import annotations

import ipaddress

from starlette.requests import Request


def client_ip(request: Request, trusted_proxy_cidrs: list[str]) -> str:
    direct = request.client.host if request.client is not None else "unknown"
    try:
        direct_ip = ipaddress.ip_address(direct)
    except ValueError:
        return "unknown"

    networks = [ipaddress.ip_network(value, strict=False) for value in trusted_proxy_cidrs]
    if any(direct_ip in network for network in networks):
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            candidate = forwarded.split(",", 1)[0].strip()
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                pass
    return str(direct_ip)
