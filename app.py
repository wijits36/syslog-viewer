#!/usr/bin/env python3
"""
Syslog Web Viewer - A browser-based frontend for viewing syslog entries.
"""

import os
import re
import secrets
import subprocess
import sys
from functools import wraps
from collections import deque
from threading import Thread
from hmac import compare_digest

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, emit

app = Flask(__name__)

# Security: require SECRET_KEY in production, generate random one for dev
if os.environ.get('SECRET_KEY'):
    app.secret_key = os.environ['SECRET_KEY']
else:
    print("WARNING: No SECRET_KEY set, generating random key (sessions won't persist across restarts)")
    app.secret_key = secrets.token_hex(32)

# Secure session cookies
app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

socketio = SocketIO(app, async_mode='threading')

# Configuration
LOG_FILE = os.environ.get('SYSLOG_FILE', '/var/log/messages')
PASSWORD = os.environ.get('SYSLOG_PASSWORD', '')
INITIAL_LINES = int(os.environ.get('INITIAL_LINES', '2000'))
SSL_CERT = os.environ.get('SSL_CERT', 'cert.pem')
SSL_KEY = os.environ.get('SSL_KEY', 'key.pem')
PORT = int(os.environ.get('PORT', '443'))

# Store recent logs and known hostnames
recent_logs = deque(maxlen=INITIAL_LINES)
known_hosts = set()

# Syslog line parser
# Format: "Jan 15 14:23:01 hostname process[pid]: message"
SYSLOG_PATTERN = re.compile(
    r'^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.*)$'
)


def parse_syslog_line(line):
    """Parse a syslog line into its components."""
    match = SYSLOG_PATTERN.match(line.strip())
    if match:
        timestamp, hostname, process, message = match.groups()
        return {
            'timestamp': timestamp,
            'hostname': hostname,
            'process': process,
            'message': message,
            'raw': line.strip(),
            'level': detect_level(message)
        }
    return {
        'timestamp': '',
        'hostname': 'unknown',
        'process': '',
        'message': line.strip(),
        'raw': line.strip(),
        'level': 'info'
    }


def detect_level(message):
    """Detect log level from message content."""
    msg_lower = message.lower()
    if any(w in msg_lower for w in ['error', 'fail', 'fatal', 'crit']):
        return 'error'
    if any(w in msg_lower for w in ['warn', 'warning']):
        return 'warn'
    if any(w in msg_lower for w in ['debug']):
        return 'debug'
    return 'info'


def login_required(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    error = None
    if request.method == 'POST':
        submitted = request.form.get('password', '')
        # Use constant-time comparison to prevent timing attacks
        if compare_digest(submitted, PASSWORD):
            session['authenticated'] = True
            return redirect(url_for('index'))
        error = 'Invalid password'
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    """Log out the user."""
    session.pop('authenticated', None)
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    """Main log viewer page."""
    return render_template('index.html')


@app.route('/api/logs')
@login_required
def get_logs():
    """API endpoint to get recent logs."""
    return jsonify({
        'logs': list(recent_logs),
        'hosts': sorted(known_hosts)
    })


@app.route('/api/hosts')
@login_required
def get_hosts():
    """API endpoint to get known hostnames."""
    return jsonify({'hosts': sorted(known_hosts)})


def load_initial_logs():
    """Load the last N lines from the log file."""
    global recent_logs, known_hosts

    # Check if file exists and is readable
    if not os.path.exists(LOG_FILE):
        print(f"ERROR: Log file does not exist: {LOG_FILE}")
        return
    if not os.access(LOG_FILE, os.R_OK):
        print(f"ERROR: No read permission for: {LOG_FILE}")
        print(f"  Try running with sudo, or add your user to the 'adm' group:")
        print(f"    sudo usermod -aG adm $USER")
        return

    try:
        result = subprocess.run(
            ['tail', '-n', str(INITIAL_LINES), LOG_FILE],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"ERROR: tail command failed: {result.stderr.strip()}")
            return
        for line in result.stdout.splitlines():
            if line.strip():
                parsed = parse_syslog_line(line)
                recent_logs.append(parsed)
                if parsed['hostname'] != 'unknown':
                    known_hosts.add(parsed['hostname'])
    except Exception as e:
        print(f"Error loading initial logs: {e}")


def tail_log_file():
    """Background task to tail the log file and broadcast new entries."""
    if not os.path.exists(LOG_FILE) or not os.access(LOG_FILE, os.R_OK):
        print("ERROR: Cannot tail log file (see errors above)")
        return

    try:
        process = subprocess.Popen(
            ['tail', '-F', LOG_FILE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        for line in iter(process.stdout.readline, ''):
            if line.strip():
                parsed = parse_syslog_line(line)
                recent_logs.append(parsed)
                if parsed['hostname'] != 'unknown':
                    known_hosts.add(parsed['hostname'])
                socketio.emit('log_entry', parsed)
    except Exception as e:
        print(f"Error tailing log file: {e}")


@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    if not session.get('authenticated'):
        return False
    emit('connected', {'status': 'ok'})


if __name__ == '__main__':
    print("Syslog Viewer starting...")

    # Validate required configuration
    if not PASSWORD:
        print("ERROR: SYSLOG_PASSWORD environment variable is required")
        sys.exit(1)

    # Check for SSL certificates
    ssl_context = None
    if os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
        ssl_context = (SSL_CERT, SSL_KEY)
        print(f"SSL enabled with {SSL_CERT}")
    else:
        print(f"ERROR: SSL certificates not found ({SSL_CERT}, {SSL_KEY})")
        print(f"  Generate certs with:")
        print(f"  openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=syslog-viewer'")
        sys.exit(1)

    print(f"Log file: {LOG_FILE}")
    print(f"Loading initial logs...")

    load_initial_logs()
    print(f"Loaded {len(recent_logs)} log entries from {len(known_hosts)} hosts")

    # Start the log tailing thread
    socketio.start_background_task(tail_log_file)

    # Run the server
    print(f"Listening on https://0.0.0.0:{PORT}")
    socketio.run(app, host='0.0.0.0', port=PORT, debug=False, ssl_context=ssl_context, allow_unsafe_werkzeug=True)
