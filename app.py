#!/usr/bin/env python3
"""
Syslog Web Viewer - A browser-based frontend for viewing syslog entries.
"""

import os
import secrets
import subprocess
import sys
from functools import wraps
from collections import deque
from hmac import compare_digest

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, current_app
from flask_socketio import SocketIO, emit

from syslog_parser import parse_syslog_line


def detect_syslog_path():
    """Detect the correct syslog file path for the current OS."""
    env_path = os.environ.get('SYSLOG_FILE')
    if env_path:
        return env_path
    # RHEL/CentOS/AlmaLinux/Fedora use /var/log/messages
    if os.path.exists('/var/log/messages'):
        return '/var/log/messages'
    # Debian/Ubuntu use /var/log/syslog
    if os.path.exists('/var/log/syslog'):
        return '/var/log/syslog'
    return '/var/log/messages'


def create_app(config=None):
    """Application factory for creating Flask app instances."""
    app = Flask(__name__)

    # Secret key
    if config and config.get('SECRET_KEY'):
        app.secret_key = config['SECRET_KEY']
    elif os.environ.get('SECRET_KEY'):
        app.secret_key = os.environ['SECRET_KEY']
    else:
        print("WARNING: No SECRET_KEY set, generating random key (sessions won't persist across restarts)")
        app.secret_key = secrets.token_hex(32)

    # Configuration from environment, overridable by config dict
    app.config['SYSLOG_FILE'] = detect_syslog_path()
    app.config['SYSLOG_PASSWORD'] = os.environ.get('SYSLOG_PASSWORD', '')
    app.config['INITIAL_LINES'] = int(os.environ.get('INITIAL_LINES', '2000'))
    app.config['SSL_CERT'] = os.environ.get('SSL_CERT', 'cert.pem')
    app.config['SSL_KEY'] = os.environ.get('SSL_KEY', 'key.pem')
    app.config['PORT'] = int(os.environ.get('PORT', '443'))

    # Apply config overrides
    if config:
        app.config.update(config)

    # Session cookie security
    if app.config.get('TESTING'):
        app.config['SESSION_COOKIE_SECURE'] = False
    else:
        app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    # Per-app state
    app.recent_logs = deque(maxlen=app.config['INITIAL_LINES'])
    app.known_hosts = set()

    # SocketIO
    socketio = SocketIO(app, async_mode='threading')
    app.socketio = socketio

    # --- Routes ---

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
            password = current_app.config['SYSLOG_PASSWORD']
            if compare_digest(submitted, password):
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
            'logs': list(current_app.recent_logs),
            'hosts': sorted(current_app.known_hosts)
        })

    @app.route('/api/hosts')
    @login_required
    def get_hosts():
        """API endpoint to get known hostnames."""
        return jsonify({'hosts': sorted(current_app.known_hosts)})

    @socketio.on('connect')
    def handle_connect():
        """Handle client connection."""
        if not session.get('authenticated'):
            return False
        emit('connected', {'status': 'ok'})

    return app, socketio


def load_initial_logs(app):
    """Load the last N lines from the log file."""
    log_file = app.config['SYSLOG_FILE']
    initial_lines = app.config['INITIAL_LINES']

    if not os.path.exists(log_file):
        print(f"ERROR: Log file does not exist: {log_file}")
        return
    if not os.access(log_file, os.R_OK):
        print(f"ERROR: No read permission for: {log_file}")
        print(f"  Try running with sudo, or add your user to the 'adm' group:")
        print(f"    sudo usermod -aG adm $USER")
        return

    try:
        result = subprocess.run(
            ['tail', '-n', str(initial_lines), log_file],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"ERROR: tail command failed: {result.stderr.strip()}")
            return
        for line in result.stdout.splitlines():
            if line.strip():
                parsed = parse_syslog_line(line)
                app.recent_logs.append(parsed)
                if parsed['hostname'] != 'unknown':
                    app.known_hosts.add(parsed['hostname'])
    except Exception as e:
        print(f"Error loading initial logs: {e}")


def tail_log_file(app, socketio):
    """Background task to tail the log file and broadcast new entries."""
    log_file = app.config['SYSLOG_FILE']

    if not os.path.exists(log_file) or not os.access(log_file, os.R_OK):
        print("ERROR: Cannot tail log file (see errors above)")
        return

    try:
        process = subprocess.Popen(
            ['tail', '-F', log_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        for line in iter(process.stdout.readline, ''):
            if line.strip():
                parsed = parse_syslog_line(line)
                app.recent_logs.append(parsed)
                if parsed['hostname'] != 'unknown':
                    app.known_hosts.add(parsed['hostname'])
                socketio.emit('log_entry', parsed)
    except Exception as e:
        print(f"Error tailing log file: {e}")


if __name__ == '__main__':
    app, socketio = create_app()

    print("Syslog Viewer starting...")

    # Validate required configuration
    if not app.config['SYSLOG_PASSWORD']:
        print("ERROR: SYSLOG_PASSWORD environment variable is required")
        sys.exit(1)

    # Check for SSL certificates
    ssl_cert = app.config['SSL_CERT']
    ssl_key = app.config['SSL_KEY']
    ssl_context = None
    if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        ssl_context = (ssl_cert, ssl_key)
        print(f"SSL enabled with {ssl_cert}")
    else:
        print(f"ERROR: SSL certificates not found ({ssl_cert}, {ssl_key})")
        print(f"  Generate certs with:")
        print(f"  openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=syslog-viewer'")
        sys.exit(1)

    log_file = app.config['SYSLOG_FILE']
    port = app.config['PORT']

    print(f"Log file: {log_file}")
    print(f"Loading initial logs...")

    load_initial_logs(app)
    print(f"Loaded {len(app.recent_logs)} log entries from {len(app.known_hosts)} hosts")

    # Start the log tailing thread
    socketio.start_background_task(tail_log_file, app, socketio)

    # Run the server
    print(f"Listening on https://0.0.0.0:{port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=False, ssl_context=ssl_context, allow_unsafe_werkzeug=True)
