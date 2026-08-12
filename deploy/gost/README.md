# GOST node deployment baseline

These templates assume Debian/Ubuntu, GOST v3, systemd and nftables. They protect the proxy
process without blocking the host's own control-plane traffic.

## Install safely

1. Keep an existing root console open. Install GOST and nftables, then create a locked service
   account: `useradd --system --home /nonexistent --shell /usr/sbin/nologin gost`. Create the
   shared directory with `install -d -o root -g gost -m 0750 /var/lib/vpn-node`.
2. Copy `gost.yml.example` to `/etc/gost/gost.yml`, install the TLS files and replace all example
   values. Keep `/var/lib/vpn-node/auth.txt` owned by root and readable by group `gost` only
   (`0640`, group `gost`). The sync-agent service runs as `root:gost`, writes auth files as `0640`
   and keeps its private state as `0600`.
3. Copy `gost.service.example`, `vpn-node-sync.service`, and `vpn-node-observer.service` to
   `/etc/systemd/system/`. Install the Python package in `/opt/vpn-node`, configure
   `/etc/vpn-node/node.env`, and start both node agents. The observer listens only on loopback;
   GOST sends it authenticated-user counters every 15 seconds.
4. Copy `nftables-node.conf.example` to `/etc/nftables.d/vpn-node.nft`. Replace the documentation
   SSH source addresses with exact administrator `/32` and/or `/128` addresses; remove an unused
   address family rather than widening it.
5. Ensure `/etc/nftables.conf` includes `/etc/nftables.d/*.nft`. Before applying anything, run
   `nft --check -f /etc/nftables.conf`. Apply it from the provider console, verify a second SSH
   login, and only then enable `nftables` and `gost` at boot.
6. Confirm the effective policy with `nft list table inet vpn_node`, then test HTTPS CONNECT,
   blocked TCP ports and blocked private destinations through authenticated GOST credentials.

## Enforced baseline

- only managed SSH and HTTPS proxy port 443 are accepted inbound;
- GOST can open internet TCP connections only to standard web ports 80 and 443; all other TCP and
  non-DNS UDP traffic is rejected, which prevents ordinary BitTorrent peer, DHT and uTP traffic;
- GOST-originated TCP connections to 22, 25, 465, 587 and 2525 are explicitly rejected;
- GOST cannot reach loopback (except its observer on 127.0.0.1:9001), RFC1918, link-local,
  carrier-grade NAT, multicast or other reserved destination ranges, including common cloud
  metadata paths; DNS on port 53 remains allowed for hostname resolution;
- GOST allows at most 5,000 concurrent connections per node and 256 per source IP;
- proxy request rate is at most 1,000/s per node and 60/s per source IP;
- one proxied connection is capped at 25 MB/s in each direction and idle CONNECT tunnels close
  after 10 minutes;
- aggregate GOST metrics are exposed only on `127.0.0.1:9000/metrics` for capacity/abuse alerts.
- authenticated per-user counters and host health are sent to the control API every 15 seconds;
  target sites and traffic contents are not included.

This is a port-based MVP restriction, not protocol inspection: a peer deliberately listening on
port 80 or 443 cannot be identified as BitTorrent by nftables alone. Tracker websites remain
accessible as normal web pages. The defaults are deliberately conservative. Change them only
after load tests on the actual VPS.
These are service/IP controls, not per-account traffic quotas. Per-user dynamic limits require an
authenticated GOST limiter plugin and are outside the MVP baseline.

Do not enable GOST `probeResist` for this browser extension: it replaces the proxy `407`
authentication challenge that `onAuthRequired` needs to supply user credentials.
