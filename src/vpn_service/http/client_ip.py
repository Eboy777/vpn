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
            candidates = forwarded.split(",")
            if len(candidates) != 1:
                return str(direct_ip)
            try:
                candidate = ipaddress.ip_address(candidates[0].strip())
            except ValueError:
                return str(direct_ip)
            return str(candidate)
    return str(direct_ip)
