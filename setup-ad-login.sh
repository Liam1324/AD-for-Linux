#!/bin/bash
# setup-ad-login.sh
# Joins this host to the lgshl.co.uk Active Directory domain and configures
# SSH login for domain users.
#
# Prerequisites (run on DC first):
#   Set-ADUser -Identity "username" -Replace @{uidNumber=XXXX; gidNumber=10001; unixHomeDirectory="/home/username@lgshl.co.uk"; loginShell="/bin/bash"}
#   Set-ADGroup -Identity "Domain Users" -Replace @{gidNumber=10001}
#
# Usage:
#   sudo bash setup-ad-login.sh
#   sudo bash setup-ad-login.sh -d lgshl.co.uk -u Administrator

set -euo pipefail

# --- Configuration ---
DOMAIN="${DOMAIN:-lgshl.co.uk}"
REALM="${REALM:-LGSHL.CO.UK}"
ADMIN_USER="${ADMIN_USER:-Administrator}"
COMPUTER_OU=""   # Optional: e.g. "OU=Servers,DC=lgshl,DC=co,DC=uk"

# --- Colours ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# --- Argument parsing ---
while getopts "d:u:o:" opt; do
  case $opt in
    d) DOMAIN="$OPTARG"; REALM="${OPTARG^^}" ;;
    u) ADMIN_USER="$OPTARG" ;;
    o) COMPUTER_OU="$OPTARG" ;;
    *) echo "Usage: $0 [-d domain] [-u admin_user] [-o computer_ou]"; exit 1 ;;
  esac
done

[[ $EUID -ne 0 ]] && error "This script must be run as root (sudo)."

# ── 1. Install packages ────────────────────────────────────────────────────────
info "Installing required packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    realmd \
    sssd \
    sssd-tools \
    sssd-ad \
    sssd-krb5 \
    samba-common-bin \
    adcli \
    oddjob \
    oddjob-mkhomedir \
    krb5-user \
    packagekit \
    libnss-sss \
    libpam-sss \
    2>/dev/null
info "Packages installed."

# ── 2. Write krb5.conf ───────────────────────────────────────────────────────
# Must be done before realm join so adcli uses supported enctypes.
info "Writing /etc/krb5.conf..."
cat > /etc/krb5.conf <<EOF
[libdefaults]
default_realm = ${REALM}
rdns = false
allow_weak_crypto = true
default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
udp_preference_limit = 0

[realms]
    ${REALM} = {
        kdc = sp-ad.${DOMAIN}
        admin_server = sp-ad.${DOMAIN}
    }

[domain_realm]
    .${DOMAIN} = ${REALM}
    ${DOMAIN} = ${REALM}
EOF
info "krb5.conf written."

# ── 3. Discover the domain ────────────────────────────────────────────────────
info "Discovering domain: $DOMAIN"
realm discover "$DOMAIN" || error "Cannot reach domain $DOMAIN. Check DNS and network."

# ── 4. Join the domain (skip if already joined) ───────────────────────────────
if realm list 2>/dev/null | grep -q "^${DOMAIN}$"; then
    warn "Already joined to $DOMAIN — skipping realm join."
else
    info "Joining domain $DOMAIN as $ADMIN_USER..."
    # realm/adcli writes its own temporary krb5.conf snippet which overrides
    # /etc/krb5.conf and causes "Message stream modified" when setting the
    # computer password. Force adcli to use our krb5.conf via KRB5_CONFIG.
    ADCLI_ARGS=(
        join --verbose
        --domain "$DOMAIN"
        --domain-realm "$REALM"
        --login-user="$ADMIN_USER"
    )
    [[ -n "$COMPUTER_OU" ]] && ADCLI_ARGS+=(--computer-ou="$COMPUTER_OU")
    KRB5_CONFIG=/etc/krb5.conf adcli "${ADCLI_ARGS[@]}"
    info "Domain join complete."
fi

# ── 4. Configure /etc/sssd/sssd.conf ─────────────────────────────────────────
info "Writing /etc/sssd/sssd.conf..."
cat > /etc/sssd/sssd.conf <<EOF
[sssd]
domains = ${DOMAIN}
config_file_version = 2
services = nss, pam

[domain/${DOMAIN}]
default_shell = /bin/bash
krb5_store_password_if_offline = True
cache_credentials = True
krb5_realm = ${REALM}
realmd_tags = manages-system joined-with-samba
id_provider = ad
fallback_homedir = /home/%u@%d
ad_domain = ${DOMAIN}
use_fully_qualified_names = True
access_provider = ad

# Use uidNumber/gidNumber attributes set on AD user objects
# instead of auto-generating UIDs from the SID hash.
ldap_id_mapping = False

# Allow SSH (system-auth) logins despite AD GPO restrictions.
ad_gpo_map_remote_interactive = +sshd
EOF
chmod 600 /etc/sssd/sssd.conf
info "sssd.conf written."

# ── 5. Enable SSH password authentication ─────────────────────────────────────
info "Enabling PasswordAuthentication in sshd_config..."
SSHD_CONF="/etc/ssh/sshd_config"
# Uncomment if commented out
sed -i 's/^#\s*PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD_CONF"
# Add if not present at all
grep -q "^PasswordAuthentication" "$SSHD_CONF" \
    || echo "PasswordAuthentication yes" >> "$SSHD_CONF"
# Ensure it's not set to no
sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' "$SSHD_CONF"
info "PasswordAuthentication enabled."

# ── 6. Enable automatic home directory creation ───────────────────────────────
info "Enabling pam_mkhomedir..."
# pam-auth-update is idempotent
pam-auth-update --enable mkhomedir
info "pam_mkhomedir enabled."

# ── 7. Clear SSSD cache and restart services ──────────────────────────────────
info "Clearing SSSD cache..."
systemctl stop sssd 2>/dev/null || true
rm -rf /var/lib/sss/db/*
rm -rf /var/lib/sss/mc/*

info "Restarting services..."
systemctl enable sssd
systemctl restart sssd
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

# Give SSSD a moment to connect to the DC
sleep 3

# ── 8. Verify ─────────────────────────────────────────────────────────────────
info "Verifying domain connectivity..."
if id "administrator@${DOMAIN}" &>/dev/null; then
    info "Domain lookup working: $(id administrator@${DOMAIN})"
else
    warn "Could not resolve administrator@${DOMAIN} — check that uidNumber/gidNumber are set in AD."
    warn "On DC:  Set-ADUser -Identity <username> -Replace @{uidNumber=<uid>; gidNumber=<gid>; unixHomeDirectory='/home/...'; loginShell='/bin/bash'}"
fi

echo ""
echo -e "${GREEN}Setup complete.${NC}"
echo "  Domain:  $DOMAIN"
echo "  SSH:     ssh username@${DOMAIN}@<this-host>"
echo ""
echo "  If users show 'no such user', ensure AD attributes are set:"
echo "    uidNumber, gidNumber, unixHomeDirectory, loginShell"
