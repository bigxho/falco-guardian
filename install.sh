#!/usr/bin/env bash
# FALCO Guardian installer for Debian.
# Run as root (or through sudo) on the target machine/VM.
set -euo pipefail

echo "==> Installing system dependencies..."
apt-get update
apt-get install -y \
    clang llvm libbpf-dev \
    linux-headers-"$(uname -r)" \
    linux-tools-common linux-tools-"$(uname -r)" \
    build-essential \
    python3 python3-venv python3-pip \
    iptables

echo "==> Creating runtime directories..."
mkdir -p /run/falco-guardian
mkdir -p /var/log/falco-guardian
mkdir -p /opt/falco-guardian

echo "==> Building the eBPF/C component..."
pushd ebpf
make vmlinux
make
popd

echo "==> Setting up the Python environment..."
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

cat <<'MSG'

==> Installation completed.

Next steps:
  1. Download the GeoLite2-City.mmdb database (a free MaxMind account is required)
     and place it at /opt/falco-guardian/GeoLite2-City.mmdb
     (or set geoip.enabled: false in config/config.yaml).
  2. Review config/config.yaml (network interface, whitelist, and thresholds).
  3. Start both components (see systemd/*.service to install them as services):
       sudo ./ebpf/build/loader eth0          # C/eBPF component
       ./venv/bin/python python/main.py       # Python component

For a safe first run on a test VM, keep blocker.enabled: false so the system
only detects and logs activity without blocking network traffic.
MSG
