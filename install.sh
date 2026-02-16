#!/bin/bash
set -e

# Syslog Viewer Installation Script
# Run as root: sudo ./install.sh

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo ./install.sh"
    exit 1
fi

INSTALL_DIR="/opt/syslog-viewer"
CONFIG_DIR="/etc/syslog-viewer"
CONFIG_FILE="$CONFIG_DIR/syslog-viewer.env"

echo "=== Syslog Viewer Installation ==="
echo

# Detect OS family
OS_ID=""
OS_ID_LIKE=""
# shellcheck source=/dev/null
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="$ID"
    OS_ID_LIKE="$ID_LIKE"
fi

# Detect correct syslog file path
if [ -f /var/log/messages ]; then
    DEFAULT_SYSLOG_FILE="/var/log/messages"
elif [ -f /var/log/syslog ]; then
    DEFAULT_SYSLOG_FILE="/var/log/syslog"
else
    DEFAULT_SYSLOG_FILE="/var/log/messages"
fi

# Ensure python3-venv is available (needed on Ubuntu/Debian)
if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" || "$OS_ID_LIKE" == *"debian"* ]]; then
    if ! python3 -c "import venv" 2>/dev/null; then
        echo "Installing python3-venv..."
        apt-get update -qq && apt-get install -y -qq python3-venv
    fi
fi

# Prompt for password if config doesn't exist
if [ ! -f "$CONFIG_FILE" ]; then
    while true; do
        read -rs -p "Set a password for the web interface: " PASSWORD
        echo
        if [ -z "$PASSWORD" ]; then
            echo "Password cannot be empty. Please try again."
            continue
        fi
        read -rs -p "Confirm password: " PASSWORD_CONFIRM
        echo
        if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
            echo "Passwords do not match. Please try again."
            continue
        fi
        break
    done
    echo
fi

# Create directories
echo "Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"

# Copy application files
echo "Copying application files..."
cp app.py "$INSTALL_DIR/"
cp syslog_parser.py "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"
cp -r templates "$INSTALL_DIR/"
cp -r static "$INSTALL_DIR/"

# Set up Python virtual environment
echo "Setting up Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q

# Generate SSL certificates if they don't exist
if [ ! -f "$INSTALL_DIR/cert.pem" ]; then
    echo "Generating self-signed SSL certificate..."
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$INSTALL_DIR/key.pem" \
        -out "$INSTALL_DIR/cert.pem" \
        -days 365 -nodes \
        -subj '/CN=syslog-viewer' 2>/dev/null
fi

# Create config file if it doesn't exist
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Creating configuration file..."
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    cat > "$CONFIG_FILE" << EOF
# Syslog Viewer Configuration

# Password for web interface login
SYSLOG_PASSWORD=$PASSWORD

# Secret key for session encryption
SECRET_KEY=$SECRET_KEY

# Path to syslog file (auto-detected: $DEFAULT_SYSLOG_FILE)
SYSLOG_FILE=$DEFAULT_SYSLOG_FILE

# Number of log lines to load on startup
INITIAL_LINES=2000

# SSL certificate paths
SSL_CERT=$INSTALL_DIR/cert.pem
SSL_KEY=$INSTALL_DIR/key.pem

# Port to listen on
PORT=443
EOF
    chmod 600 "$CONFIG_FILE"
fi

# Install systemd service
echo "Installing systemd service..."
cp syslog-viewer.service /etc/systemd/system/
systemctl daemon-reload

# Start and enable service
echo "Starting service..."
systemctl enable syslog-viewer --quiet
systemctl start syslog-viewer

# Configure firewall
if command -v firewall-cmd &> /dev/null; then
    if systemctl is-active --quiet firewalld; then
        echo "Configuring firewalld..."
        firewall-cmd --add-port=443/tcp --permanent --quiet
        firewall-cmd --reload --quiet
    fi
elif command -v ufw &> /dev/null; then
    if ufw status | grep -q "Status: active"; then
        echo "Configuring ufw..."
        ufw allow 443/tcp
    fi
else
    echo
    echo "Note: Remember to open port 443 in your firewall if needed."
fi

echo
echo "=== Installation Complete ==="
echo
echo "Service status:"
systemctl status syslog-viewer --no-pager --lines=0
echo
LOCAL_IP=$(hostname -I | awk '{print $1}')
echo "Access the web interface at: https://$LOCAL_IP"
echo
echo "Useful commands:"
echo "  View logs:      journalctl -u syslog-viewer -f"
echo "  Restart:        systemctl restart syslog-viewer"
echo "  Edit config:    nano $CONFIG_FILE"
