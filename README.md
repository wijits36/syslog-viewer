# Syslog Viewer

A simple, browser-based frontend for viewing syslog entries in real-time. Filter logs by machine, search through messages, and watch new entries stream in live.

## Features

- **Live streaming** - New log entries appear instantly via WebSocket
- **Filter by machine** - Dropdown to view logs from specific hosts
- **Search** - Filter logs by message content or process name
- **Dark theme** - Easy on the eyes for log viewing
- **Color-coded levels** - Errors (red), warnings (yellow), debug (gray)
- **Simple auth** - Password-protected access
- **HTTPS only** - Secure by default with SSL/TLS

## Requirements

- Python 3.6+
- A Linux server running rsyslog (or compatible syslog daemon)
- Read access to your syslog file (typically `/var/log/messages`)

## Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/wijits36/syslog-viewer.git
   cd syslog-viewer
   ```

2. **Run the installer:**
   ```bash
   sudo ./install.sh
   ```
   The installer will prompt you to set a password, then automatically configure and start the service.

3. **Open in browser:**
   ```
   https://your-server-ip
   ```

## Configuration

Configuration is stored in `/etc/syslog-viewer/syslog-viewer.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `SYSLOG_PASSWORD` | *(required)* | Password for web interface |
| `SECRET_KEY` | *(auto-generated)* | Flask session encryption key |
| `SYSLOG_FILE` | `/var/log/messages` | Path to syslog file |
| `INITIAL_LINES` | `2000` | Number of log lines to load on startup |
| `SSL_CERT` | `/opt/syslog-viewer/cert.pem` | Path to SSL certificate |
| `SSL_KEY` | `/opt/syslog-viewer/key.pem` | Path to SSL private key |
| `PORT` | `443` | Port to listen on |

## Firewall

Allow HTTPS traffic through your firewall:

```bash
# firewalld (RHEL/CentOS/Fedora)
sudo firewall-cmd --add-port=443/tcp --permanent
sudo firewall-cmd --reload

# ufw (Debian/Ubuntu)
sudo ufw allow 443/tcp
```

## Updating

To update an existing installation:

```bash
cd syslog-viewer
git pull
sudo ./update.sh
```

## Uninstalling

To completely remove Syslog Viewer:

```bash
cd syslog-viewer
sudo ./uninstall.sh
```

This removes the service, application files, configuration, and firewall rules.

## Using a Real SSL Certificate

The installer generates a self-signed certificate. To use a real certificate (e.g., from Let's Encrypt):

1. Obtain your certificate files
2. Update `/etc/syslog-viewer/syslog-viewer.env`:
   ```
   SSL_CERT=/path/to/fullchain.pem
   SSL_KEY=/path/to/privkey.pem
   ```
3. Restart: `sudo systemctl restart syslog-viewer`

## Troubleshooting

**"Loaded 0 log entries"**
- Check that the syslog file exists and is readable
- The service runs as root, so permissions usually aren't an issue
- Verify the path in `SYSLOG_FILE`

**Can't connect in browser**
- Check firewall rules
- Verify the service is running: `systemctl status syslog-viewer`
- Check logs: `journalctl -u syslog-viewer -f`

**WebSocket disconnects**
- Check browser console for errors
- Ensure you're using HTTPS, not HTTP

## Development

Run locally for development:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Generate test cert
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'

# Run (requires sudo for port 443, or change PORT)
export SYSLOG_PASSWORD=test
export PORT=8443
python app.py
```

## License

MIT License - see [LICENSE](LICENSE) file.
