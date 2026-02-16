import os
import shutil
import subprocess
import threading
import time

import pytest

# Add project root to path so we can import app
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import create_app, load_initial_logs


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


@pytest.fixture
def sample_log_file(tmp_path):
    """Copy the fixture log file to a temp location and return its path."""
    src = os.path.join(FIXTURES_DIR, 'sample_messages.log')
    dest = tmp_path / 'messages.log'
    shutil.copy2(src, dest)
    return str(dest)


@pytest.fixture
def app(sample_log_file):
    """Create a test Flask app with TESTING mode."""
    app, socketio = create_app(config={
        'TESTING': True,
        'SYSLOG_FILE': sample_log_file,
        'SYSLOG_PASSWORD': 'testpassword',
        'INITIAL_LINES': 100,
        'SECRET_KEY': 'test-secret-key',
    })
    load_initial_logs(app)
    return app


@pytest.fixture
def socketio(app):
    """Return the SocketIO instance."""
    return app.socketio


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def authenticated_client(client):
    """A test client that is already logged in."""
    with client.session_transaction() as sess:
        sess['authenticated'] = True
    return client
