#!/usr/bin/env bash
# =============================================================================
# Linux Security Inventory Script
# Purpose: Collect critical security-related information for Linux server hardening
# This script is READ-ONLY - it does NOT make any changes to the system
# 
# Author: Prepared for GitHub (based on requirements)
# Version: 1.0
# Compatibility: Ubuntu, Debian, RHEL, Rocky, AlmaLinux, CentOS, Fedora and most systemd-based distros
# 
# Usage:
#   sudo ./linux-security-inventory.sh
#   sudo ./linux-security-inventory.sh > security-report-$(hostname)-$(date +%Y%m%d).txt
# 
# Important: Run this script before starting any hardening process.
# It helps identify risks such as outdated packages, unnecessary services,
# weak SSH configurations, privileged users, etc.
# =============================================================================

set -u  # Treat unset variables as an error

echo "======================================================================"
echo "🔐 Linux Security Inventory Report"
echo "Hostname     : $(hostname)"
echo "Date         : $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "======================================================================"
echo ""

# Helper function for section headers
section() {
    printf "\n%s\n%s\n" "$1" "$(printf '─%.0s' {1..70})"
}

# ------------------------------------------------------------------------------
section "1. Operating System & Kernel Information"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "OS           : $PRETTY_NAME"
    echo "Version      : $VERSION"
    echo "ID           : $ID $VERSION_ID"
else
    echo "OS           : $(cat /etc/*release 2>/dev/null | head -n3)"
fi
echo "Kernel       : $(uname -r)"
echo "Architecture : $(uname -m)"
echo "Last Boot    : $(who -b)"
echo "Uptime       : $(uptime -p)"

# ------------------------------------------------------------------------------
section "2. Last System Update Information"
if command -v apt-get >/dev/null 2>&1; then
    echo "Package Manager : APT (Debian/Ubuntu)"
    echo "Last apt history: $(ls -l /var/log/apt/history.log 2>/dev/null | awk '{print $6" "$7" "$8}' || echo 'Not found')"
    echo "Upgradable packages: $(apt list --upgradable 2>/dev/null | wc -l | awk '{print $1-1}') (approximate)"
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    PKG_MGR=$(command -v dnf || command -v yum)
    echo "Package Manager : $PKG_MGR (RHEL-based)"
    echo "Last update check summary available via: $PKG_MGR history"
fi

# ------------------------------------------------------------------------------
section "3. Privileged / Non-Standard Users (UID < 1000)"
echo "Users with UID < 1000 (excluding common system accounts):"
awk -F: '$3 < 1000 && $3 != 0 && $1 !~ /^(sync|shutdown|halt|operator|games|news|mail|uucp|proxy|www-data|backup|list|irc|gnats|nobody|systemd.*|dbus|polkitd|rpc|rpcuser|ntp|sshd|dnsmasq|avahi|colord|rtkit|pulse|geoclue|saned|usbmux)$/ {print "  • " $1 " (UID=" $3 ", GID=" $4 ")"}' /etc/passwd || echo "  No unusual low-UID users found."

# ------------------------------------------------------------------------------
section "4. SSH Authorized Keys (Potential Attack Surface)"
echo "Scanning for authorized_keys files..."
find /home -type f -name "authorized_keys" -size +10c 2>/dev/null | while read -r file; do
    user=$(stat -c '%U' "$file" 2>/dev/null || echo "unknown")
    key_count=$(grep -cvE '^\s*(#|$)' "$file" 2>/dev/null || echo "0")
    echo "  • $file  →  User: $user  →  $key_count keys"
done

if [ -s /root/.ssh/authorized_keys ]; then
    echo "  ⚠️  /root/.ssh/authorized_keys exists!"
fi

# ------------------------------------------------------------------------------
section "5. Listening Ports & Running Services"
echo "Top listening ports and associated processes (ss/netstat):"
if command -v ss >/dev/null 2>&1; then
    ss -tulnp | head -n 25
elif command -v netstat >/dev/null 2>&1; then
    netstat -tulnp | head -n 25
else
    echo "  Neither ss nor netstat found."
fi

# ------------------------------------------------------------------------------
section "6. Firewall Status"
echo "Firewall detection:"
if command -v ufw >/dev/null 2>&1; then
    echo "UFW Status:"
    ufw status verbose | head -n 15
fi
if command -v firewall-cmd >/dev/null 2>&1; then
    echo "Firewalld Status: $(firewall-cmd --state 2>/dev/null || echo 'not found')"
    firewall-cmd --list-all 2>/dev/null | head -n 12
fi
echo "Basic iptables summary (if active):"
iptables -L -n -v 2>/dev/null | grep -E 'Chain|pkts' | head -n 10 || echo "  iptables not showing active rules or not installed."

# ------------------------------------------------------------------------------
section "7. Sudo / Wheel / Admin Privileges"
echo "Sudoers configuration (users/groups with elevated privileges):"
grep -E '^%wheel|^%sudo|^root|^\s*ALL' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^#' || echo "  No custom sudoers found."

# ------------------------------------------------------------------------------
section "8. Security Modules (SELinux / AppArmor)"
if command -v getenforce >/dev/null 2>&1; then
    echo "SELinux Status : $(getenforce 2>/dev/null)"
    sestatus 2>/dev/null | grep -E 'Current|Mode|Loaded' || true
fi
if command -v aa-status >/dev/null 2>&1; then
    echo "AppArmor Status:"
    aa-status --enabled && aa-status | head -n 12 || echo "  AppArmor not enabled."
else
    echo "AppArmor: Not installed or not available."
fi

# ------------------------------------------------------------------------------
section "9. Recent Logins (Last 15 entries)"
echo "Recent logins (last command):"
last -a | head -n 16 || echo "  last command not available."

echo ""
echo "======================================================================"
echo "Report completed successfully."
echo "Recommendation: Save this output and review it before applying hardening changes."
echo "Next steps usually include: SSH hardening, unnecessary service removal, firewall tightening,"
echo "package updates, disabling root login, and reviewing authorized_keys."
echo "======================================================================"

exit 0