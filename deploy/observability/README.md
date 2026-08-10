# Virgo observability

The application admin panel is served by the control API at `/admin`. Grafana is a separate
technical dashboard on the same control VPS and listens on `127.0.0.1:3000` by default.

## Control VPS

1. Enable the application panel and set `ADMIN_PANEL_USERNAME`,
   `ADMIN_PANEL_PASSWORD_HASH`, `METRICS_SCRAPE_TOKEN`, `GRAFANA_ADMIN_PASSWORD`, and
   `POSTGRES_EXPORTER_DSN` in the production environment file.
2. Create `deploy/observability/secrets/metrics_token` with exactly the same secret as
   `METRICS_SCRAPE_TOKEN`. The directory is ignored by Git.
3. Start the control stack first, then start this compose file from the
   `deploy/observability` directory. The external `vpn-control_private` network must exist.
4. Open Grafana through an SSH tunnel to local port 3000. Do not expose it directly to the
   Internet.

Prometheus retains metrics for 30 days. Loki retains logs for 30 days. Grafana is provisioned
with the Virgo overview dashboard and Prometheus/Loki data sources.

## Logs from VPN nodes

1. Install Grafana Alloy on each node.
2. Copy `node.alloy.example` to `/etc/alloy/node.alloy` and
   `vpn-node-alloy.service` to `/etc/systemd/system/`.
3. Configure `NODE_NAME`, `LOKI_PUSH_URL`, `LOKI_USERNAME`, and `LOKI_PASSWORD` in
   `/etc/vpn-node/node.env`.
4. On both API proxy VPSes, create `/etc/nginx/loki.htpasswd` for that dedicated log-shipping
   user. Never reuse the admin-panel or Telegram credentials.
5. Reload Nginx and start `vpn-node-alloy.service`.

Only the Loki write endpoint is published through the API proxies. Reads remain inside the
control server. The origin firewall permits port 3100 only from the two WireGuard proxy peers.
