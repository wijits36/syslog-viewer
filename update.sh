#!/bin/bash
set -e

# Syslog Viewer Update Script
# Run as root: sudo ./update.sh

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo ./update.sh"
    exit 1
fi

INSTALL_DIR="/opt/syslog-viewer"

echo "=== Updating Syslog Viewer ==="

# Copy application files
echo "Copying updated files..."
cp app.py "$INSTALL_DIR/"
cp syslog_parser.py "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"
cp -r templates "$INSTALL_DIR/"
cp -r static "$INSTALL_DIR/"

# Update dependencies
echo "Updating dependencies..."
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q

# Restart service
echo "Restarting service..."
systemctl restart syslog-viewer

echo "Update complete. Checking status..."
systemctl status syslog-viewer --no-pager
