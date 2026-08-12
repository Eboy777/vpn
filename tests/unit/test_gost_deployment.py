from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GOST_CONFIG = ROOT / "deploy/gost/gost.yml.example"
NODE_FIREWALL = ROOT / "deploy/gost/nftables-node.conf.example"
GOST_SERVICE = ROOT / "deploy/gost/gost.service.example"
NODE_SYNC_SERVICE = ROOT / "deploy/gost/vpn-node-sync.service"
DEPLOYMENT_README = ROOT / "deploy/gost/README.md"


def test_gost_config_enforces_request_connection_and_bandwidth_limits() -> None:
    config = GOST_CONFIG.read_text()

    assert "limiter: vpn-bandwidth" in config
    assert "rlimiter: vpn-request-rate" in config
    assert "climiter: vpn-connections" in config
    assert '- "$$ 25MB 25MB"' in config
    assert '- "$ 1000"' in config
    assert '- "$$ 60"' in config
    assert '- "$ 5000"' in config
    assert '- "$$ 256"' in config
    assert "observer: vpn-user-traffic" in config
    assert "observer.resetTraffic: true" in config
    assert "idleTimeout: 10m" in config
    assert 'addr: "127.0.0.1:9000"' in config
    assert "probeResist" not in config


def test_gost_and_firewall_both_deny_private_destinations() -> None:
    config = GOST_CONFIG.read_text()
    firewall = NODE_FIREWALL.read_text()

    assert "bypass: vpn-deny-private" in config
    for network in (
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ):
        assert network in config
        assert network in firewall


def test_node_firewall_scopes_egress_blocks_to_unprivileged_gost_user() -> None:
    firewall = NODE_FIREWALL.read_text()

    assert "flush ruleset" not in firewall
    assert "policy drop;" in firewall
    assert 'meta skuid "gost" tcp dport { 22, 25, 465, 587, 2525 }' in firewall
    assert 'meta skuid "gost" ip daddr @blocked_ipv4' in firewall
    assert 'meta skuid "gost" ip6 daddr @blocked_ipv6' in firewall
    assert 'meta skuid "gost" ip daddr 127.0.0.1 tcp dport 9001 accept' in firewall
    assert 'meta skuid "gost" udp dport 53 accept' in firewall
    assert 'meta skuid "gost" tcp dport 53 accept' in firewall
    assert 'meta skuid "gost" tcp dport { 80, 443 } accept' in firewall
    assert 'meta skuid "gost" counter reject with icmpx type admin-prohibited' in firewall
    assert firewall.index('meta skuid "gost" ip daddr @blocked_ipv4') < firewall.index(
        'meta skuid "gost" tcp dport { 80, 443 } accept'
    )
    assert "tcp dport 443 tcp flags syn limit rate over 2000/second" in firewall
    assert "tcp dport 443 accept" in firewall


def test_gost_service_uses_dedicated_user_and_minimal_bind_capability() -> None:
    service = GOST_SERVICE.read_text()
    sync_service = NODE_SYNC_SERVICE.read_text()

    assert "User=gost" in service
    assert "Group=gost" in service
    assert "AmbientCapabilities=CAP_NET_BIND_SERVICE" in service
    assert "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" in service
    assert "NoNewPrivileges=true" in service
    assert "ProtectSystem=strict" in service
    assert "User=root" in sync_service
    assert "Group=gost" in sync_service
    assert "UMask=0027" in sync_service


def test_deployment_requires_firewall_dry_run_and_exact_ssh_sources() -> None:
    instructions = DEPLOYMENT_README.read_text()

    assert "nft --check -f /etc/nftables.conf" in instructions
    assert "exact administrator `/32` and/or `/128`" in instructions
    assert "verify a second SSH" in instructions
