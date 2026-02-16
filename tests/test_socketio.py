"""Tests for WebSocket (SocketIO) functionality."""

from flask_socketio import SocketIOTestClient


class TestSocketIOConnection:
    """Tests for SocketIO connect/disconnect."""

    def test_authenticated_connect(self, app, socketio):
        """Authenticated client connects and receives 'connected' event."""
        flask_client = app.test_client()
        with flask_client.session_transaction() as sess:
            sess['authenticated'] = True

        sio_client = socketio.test_client(app, flask_test_client=flask_client)
        assert sio_client.is_connected()

        received = sio_client.get_received()
        event_names = [r['name'] for r in received]
        assert 'connected' in event_names

        connected_data = next(r for r in received if r['name'] == 'connected')
        assert connected_data['args'][0] == {'status': 'ok'}

        sio_client.disconnect()

    def test_unauthenticated_connect_rejected(self, app, socketio):
        """Unauthenticated client is rejected."""
        flask_client = app.test_client()
        sio_client = socketio.test_client(app, flask_test_client=flask_client)
        assert not sio_client.is_connected()


class TestLoadInitialLogs:
    """Tests for load_initial_logs populating app state."""

    def test_populates_recent_logs(self, app):
        """After load_initial_logs, recent_logs has entries."""
        assert len(app.recent_logs) == 20

    def test_populates_known_hosts(self, app):
        """After load_initial_logs, known_hosts has hostnames."""
        assert 'webserver01' in app.known_hosts
        assert 'dbserver02' in app.known_hosts
        assert 'mailserver' in app.known_hosts
        assert 'loadbalancer' in app.known_hosts
