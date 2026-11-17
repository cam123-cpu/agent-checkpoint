#!/usr/bin/env bash
# Set up a fresh Ubuntu 22.04/24.04 or Debian 12 server for Agent Checkpoint, behind HTTPS, with
# automatic security updates. Run as root:
#
#   sudo bash deploy/install.sh checkpoint.example.com you@example.com
#
# Point the domain's DNS at this server first (Caddy needs it to get a certificate).
# Safe to run again: each step checks what is already there.
set -euo pipefail

DOMAIN="${1:?usage: install.sh DOMAIN ADMIN_EMAIL}"
ADMIN_EMAIL="${2:?usage: install.sh DOMAIN ADMIN_EMAIL}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP=/opt/agent-checkpoint
DATA=/srv/checkpoint
CONF=/etc/agent-checkpoint
KEYS=$CONF/keys

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "domain looks wrong: $DOMAIN"; exit 1; }
export DEBIAN_FRONTEND=noninteractive

echo "== packages"
apt-get update -q
apt-get install -y -q python3 python3-venv ufw unattended-upgrades apt-listchanges \
    debian-keyring debian-archive-keyring apt-transport-https curl gnupg

echo "== automatic security updates (daily; reboots at 04:00 when an update needs it)"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
CONF
cat > /etc/apt/apt.conf.d/52agent-checkpoint-upgrades <<'CONF'
// Security updates for the system, Python and OpenSSL, plus Caddy's own repository.
Unattended-Upgrade::Origins-Pattern {
        "origin=${distro_id},archive=${distro_codename}-security";
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
        "origin=cloudsmith/caddy/stable";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
CONF
systemctl enable --now unattended-upgrades

echo "== firewall: only SSH, HTTP (redirects to HTTPS) and HTTPS"
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo "== SSH: keys only"
if [[ -d /etc/ssh/sshd_config.d ]] && ls /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys >/dev/null 2>&1; then
    cat > /etc/ssh/sshd_config.d/50-agent-checkpoint.conf <<'CONF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
CONF
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
else
    echo "   skipped: no SSH key installed yet. Add one, then run this again, so you aren't locked out."
fi

echo "== Caddy (HTTPS with automatic certificates)"
if ! command -v caddy >/dev/null; then
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -q
    apt-get install -y -q caddy
fi
sed -e "s/checkpoint.example.com/$DOMAIN/" -e "s/you@example.com/$ADMIN_EMAIL/" "$REPO_DIR/deploy/Caddyfile" > /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl reload caddy || systemctl restart caddy

echo "== the checkpoint"
id checkpoint >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin checkpoint
install -d -m 0700 -o checkpoint -g checkpoint "$DATA"
install -d -m 0755 "$CONF"
install -d -m 0700 -o checkpoint -g checkpoint "$KEYS"
python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install --quiet --upgrade pip
"$APP/venv/bin/pip" install --quiet "$REPO_DIR"
cat > "$CONF/env" <<CONF
CHECKPOINT_HOME=$DATA
AGENT_CHECKPOINT_KEYS=$KEYS
PUBLIC_ORIGIN=https://$DOMAIN
CONF
chmod 0644 "$CONF/env"
install -m 0644 "$REPO_DIR"/deploy/agent-checkpoint.service "$REPO_DIR"/deploy/agent-checkpoint-update.service \
    "$REPO_DIR"/deploy/agent-checkpoint-update.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now agent-checkpoint.service agent-checkpoint-update.timer

echo "== checks"
sudo -u checkpoint env CHECKPOINT_HOME=$DATA AGENT_CHECKPOINT_KEYS=$KEYS "$APP/venv/bin/agent-checkpoint" doctor || true
cat <<DONE

Done. Next:
  1. Create the company and its first admin (it stays in shadow mode):
       sudo -u checkpoint env CHECKPOINT_HOME=$DATA AGENT_CHECKPOINT_KEYS=$KEYS \\
         $APP/venv/bin/agent-checkpoint create-org acme --name "Acme"
       sudo -u checkpoint env CHECKPOINT_HOME=$DATA AGENT_CHECKPOINT_KEYS=$KEYS \\
         $APP/venv/bin/agent-checkpoint add-user acme $ADMIN_EMAIL --role admin
     The admin must set up two-step sign-in at first sign-in. Nothing else works until they do.
  2. From another machine, check the server from the outside:
       python3 deploy/external_check.py https://$DOMAIN
  3. Back up $DATA and $KEYS to two different places.
DONE
