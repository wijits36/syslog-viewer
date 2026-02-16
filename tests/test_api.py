"""Tests for API endpoints and route responses."""

import json


class TestIndexRoute:
    """Tests for the main page."""

    def test_index_returns_html(self, authenticated_client):
        response = authenticated_client.get('/')
        assert response.status_code == 200
        assert b'Syslog Viewer' in response.data


class TestLogsAPI:
    """Tests for GET /api/logs."""

    def test_returns_json(self, authenticated_client):
        response = authenticated_client.get('/api/logs')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'logs' in data
        assert 'hosts' in data
        assert isinstance(data['logs'], list)
        assert isinstance(data['hosts'], list)

    def test_entries_have_expected_fields(self, authenticated_client):
        response = authenticated_client.get('/api/logs')
        data = json.loads(response.data)
        assert len(data['logs']) > 0
        entry = data['logs'][0]
        assert 'timestamp' in entry
        assert 'hostname' in entry
        assert 'process' in entry
        assert 'message' in entry
        assert 'raw' in entry
        assert 'level' in entry

    def test_loaded_from_fixture(self, authenticated_client):
        response = authenticated_client.get('/api/logs')
        data = json.loads(response.data)
        # Fixture has 20 lines
        assert len(data['logs']) == 20

    def test_hosts_include_fixture_hosts(self, authenticated_client):
        response = authenticated_client.get('/api/logs')
        data = json.loads(response.data)
        hosts = data['hosts']
        assert 'webserver01' in hosts
        assert 'dbserver02' in hosts
        assert 'mailserver' in hosts
        assert 'loadbalancer' in hosts


class TestHostsAPI:
    """Tests for GET /api/hosts."""

    def test_returns_json(self, authenticated_client):
        response = authenticated_client.get('/api/hosts')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'hosts' in data
        assert isinstance(data['hosts'], list)

    def test_returns_known_hosts(self, authenticated_client):
        response = authenticated_client.get('/api/hosts')
        data = json.loads(response.data)
        assert 'webserver01' in data['hosts']
        assert 'dbserver02' in data['hosts']
        assert 'mailserver' in data['hosts']
        assert 'loadbalancer' in data['hosts']

    def test_hosts_sorted(self, authenticated_client):
        response = authenticated_client.get('/api/hosts')
        data = json.loads(response.data)
        assert data['hosts'] == sorted(data['hosts'])
