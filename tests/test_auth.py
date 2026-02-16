"""Tests for authentication (login, logout, session handling)."""


class TestLogin:
    """Tests for the login page and authentication flow."""

    def test_login_page_renders(self, client):
        response = client.get('/login')
        assert response.status_code == 200
        assert b'password' in response.data.lower()

    def test_login_correct_password(self, client):
        response = client.post('/login', data={'password': 'testpassword'}, follow_redirects=False)
        assert response.status_code == 302
        assert response.location.endswith('/')

    def test_login_wrong_password(self, client):
        response = client.post('/login', data={'password': 'wrong'}, follow_redirects=True)
        assert response.status_code == 200
        assert b'Invalid password' in response.data

    def test_login_empty_password(self, client):
        response = client.post('/login', data={'password': ''}, follow_redirects=True)
        assert response.status_code == 200
        assert b'Invalid password' in response.data

    def test_login_sets_session(self, client):
        client.post('/login', data={'password': 'testpassword'})
        with client.session_transaction() as sess:
            assert sess.get('authenticated') is True


class TestLogout:
    """Tests for logout."""

    def test_logout_clears_session(self, authenticated_client):
        authenticated_client.get('/logout')
        with authenticated_client.session_transaction() as sess:
            assert 'authenticated' not in sess

    def test_logout_redirects_to_login(self, authenticated_client):
        response = authenticated_client.get('/logout', follow_redirects=False)
        assert response.status_code == 302
        assert '/login' in response.location


class TestLoginRequired:
    """Tests that protected routes require authentication."""

    def test_index_requires_auth(self, client):
        response = client.get('/', follow_redirects=False)
        assert response.status_code == 302
        assert '/login' in response.location

    def test_api_logs_requires_auth(self, client):
        response = client.get('/api/logs', follow_redirects=False)
        assert response.status_code == 302
        assert '/login' in response.location

    def test_api_hosts_requires_auth(self, client):
        response = client.get('/api/hosts', follow_redirects=False)
        assert response.status_code == 302
        assert '/login' in response.location
