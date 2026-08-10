from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_public_proxy_overwrites_untrusted_forwarding_headers_and_has_safe_logs() -> None:
    config = (ROOT / "deploy/api-proxy/nginx.conf.example").read_text()

    assert "server 10.77.0.1:8000" in config
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in config
    assert "proxy_set_header X-Request-ID $request_id;" in config
    assert 'proxy_set_header Forwarded "";' in config
    assert "$proxy_add_x_forwarded_for" not in config
    assert "$request_uri" not in config
    assert "$http_authorization" not in config
    assert "$request_body" not in config
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in config
    assert "error_log /var/log/nginx/error.log crit;" in config
    assert "proxy_request_buffering off;" in config
    assert "proxy_buffering off;" in config
    assert "limit_req zone=public_api_per_ip burst=60 nodelay;" in config
    assert "limit_req zone=admin_api_per_ip burst=10 nodelay;" in config
    assert "auth_basic_user_file /etc/nginx/loki.htpasswd;" in config
    assert "location = /loki/api/v1/push" in config
    assert "location = /internal/metrics" in config
    assert "limit_conn public_connections_per_ip 30;" in config
    assert "client_header_timeout 10s;" in config
    assert "limit_except GET POST OPTIONS" in config


def test_wireguard_peer_addresses_match_backend_trust_profile() -> None:
    proxy_a = (ROOT / "deploy/api-proxy/wireguard-proxy-a.conf.example").read_text()
    proxy_b = (ROOT / "deploy/api-proxy/wireguard-proxy-b.conf.example").read_text()
    origin = (ROOT / "deploy/api-proxy/wireguard-origin.conf.example").read_text()

    assert "Address = 10.77.0.2/32" in proxy_a
    assert "Address = 10.77.0.3/32" in proxy_b
    assert "AllowedIPs = 10.77.0.2/32" in origin
    assert "AllowedIPs = 10.77.0.3/32" in origin


def test_production_compose_publishes_only_api_on_wireguard_address() -> None:
    compose = (ROOT / "deploy/control/docker-compose.production.yml").read_text()

    postgres_section, api_section = compose.split("  api:", 1)
    assert "ports:" not in postgres_section.split("  postgres:", 1)[1]
    assert '"${CONTROL_WIREGUARD_IP:?set CONTROL_WIREGUARD_IP}:8000:8000"' in api_section
    assert "reverse-proxy:" not in compose


def test_firewall_templates_limit_origin_api_to_wireguard_peers() -> None:
    origin = (ROOT / "deploy/api-proxy/nftables-origin.conf.example").read_text()
    proxy = (ROOT / "deploy/api-proxy/nftables-proxy.conf.example").read_text()

    assert (
        'iifname "wg0" ip saddr { 10.77.0.2, 10.77.0.3 } tcp dport { 8000, 3100 } accept'
    ) in origin
    assert "tcp dport { 80, 443 } accept" in proxy
    assert "tcp dport 443 tcp flags syn limit rate over 3000/second" in proxy
    assert "flush ruleset" not in origin
    assert "flush ruleset" not in proxy
