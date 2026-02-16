#!/bin/bash
set -e

# Syslog Viewer Uninstall Script
# Run as root: sudo ./uninstall.sh

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo ./uninstall.sh"
    exit 1
fi

echo "=== Syslog Viewer Uninstall ==="
echo

read -p "This will remove Syslog Viewer and all its configuration. Continue? [y/N] " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled."
    exit 0
fi

echo

# Stop and disable service
if systemctl is-active --quiet syslog-viewer 2>/dev/null; then
    echo "Stopping service..."
    systemctl stop syslog-viewer
fi

if systemctl is-enabled --quiet syslog-viewer 2>/dev/null; then
    echo "Disabling service..."
    systemctl disable syslog-viewer --quiet
fi

# Remove systemd service
if [ -f /etc/systemd/system/syslog-viewer.service ]; then
    echo "Removing systemd service..."
    rm /etc/systemd/system/syslog-viewer.service
    systemctl daemon-reload
fi

# Remove application files
if [ -d /opt/syslog-viewer ]; then
    echo "Removing application files..."
    rm -rf /opt/syslog-viewer
fi

# Remove configuration
if [ -d /etc/syslog-viewer ]; then
    echo "Removing configuration..."
    rm -rf /etc/syslog-viewer
fi

# Remove firewall rule if firewalld is available
if command -v firewall-cmd &> /dev/null; then
    if systemctl is-active --quiet firewalld; then
        if firewall-cmd --query-port=443/tcp --quiet 2>/dev/null; then
            echo "Removing firewalld rule..."
            firewall-cmd --remove-port=443/tcp --permanent --quiet
            firewall-cmd --reload --quiet
        fi
    fi
fi

# Remove ufw rule if applicable
if command -v ufw &> /dev/null; then
    if ufw status | grep -q "443/tcp"; then
        echo "Removing ufw rule..."
        ufw delete allow 443/tcp
    fi
fi

echo
echo "=== Uninstall Complete ==="
