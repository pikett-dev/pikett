#!/usr/bin/env bash
# Installs CrowdSec with the iptables firewall bouncer on this server (Ubuntu 24.04). Run as root on the server:
#
#   sudo ./install-crowdsec.sh            SSH and the host
#   sudo ./install-crowdsec.sh --web      also the access log of Coolify's proxy (test server)
#
# The Tailscale network is whitelisted before the bouncer starts. Undo: see ../README.md, "CrowdSec", "Undo".
set -Eeuo pipefail
trap 'echo "error: step failed (line $LINENO): $BASH_COMMAND" >&2' ERR

here="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" = 0 ] || { echo "error: run as root" >&2; exit 1; }

# The local API port first: the package starts CrowdSec right away, and 8080 is Traefik's on the test server.
install -D -m 644 "$here/config.yaml.local" /etc/crowdsec/config.yaml.local

if [ ! -f /etc/apt/sources.list.d/crowdsec_crowdsec.list ]; then
  # The official package repository (docs.crowdsec.net, "Linux" install). Read the script before you run it.
  curl -fsSL https://install.crowdsec.net -o /tmp/crowdsec-repo.sh
  sh /tmp/crowdsec-repo.sh
fi
DEBIAN_FRONTEND=noninteractive apt-get install -y -q crowdsec
# cscli talks to the local API through this file; the package writes it with the default port.
sed -i 's#^url: .*#url: http://127.0.0.1:8086#' /etc/crowdsec/local_api_credentials.yaml

install -D -m 644 "$here/tailscale-whitelist.yaml" /etc/crowdsec/parsers/s02-enrich/tailscale-whitelist.yaml
cscli collections install crowdsecurity/linux crowdsecurity/sshd
if [ "${1:-}" = "--web" ]; then
  install -D -m 644 "$here/acquis-coolify-proxy.yaml" /etc/crowdsec/acquis.d/coolify-proxy.yaml
  cscli collections install crowdsecurity/traefik
fi
systemctl restart crowdsec
for _ in $(seq 1 30); do cscli lapi status >/dev/null 2>&1 && break; sleep 1; done
cscli lapi status

install -D -m 644 "$here/crowdsec-firewall-bouncer.yaml.local" \
  /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local
DEBIAN_FRONTEND=noninteractive apt-get install -y -q crowdsec-firewall-bouncer-iptables
systemctl restart crowdsec-firewall-bouncer

echo "Check: the whitelist is loaded and the bouncer is registered:"
cscli parsers list | grep -i tailscale || echo "warning: whitelist not listed"
cscli bouncers list
