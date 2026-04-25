# Linux Security Inventory Script

A read-only Bash script that collects essential security information from Linux servers.  
Useful as the **first step** before performing any hardening (SSH, firewall, users, etc.).

## Features
- OS & Kernel details
- Last update information
- Non-standard privileged users
- All `authorized_keys` files with key count
- Listening ports & services
- Firewall status (UFW, firewalld, iptables)
- Sudoers configuration
- SELinux / AppArmor status
- Recent logins

## Usage
```bash
sudo ./linux-security-inventory.sh > report-$$   (hostname)-   $$(date +%Y%m%d).txt