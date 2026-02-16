"""End-to-end Selenium browser tests.

These tests start a real Flask-SocketIO server and drive a headless browser.
Run with: pytest tests/test_e2e.py -v
Skip with: pytest -m "not e2e"
"""

import os
import shutil
import subprocess
import threading
import time
import sys

import pytest
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import create_app, load_initial_logs

pytestmark = pytest.mark.e2e

TEST_PASSWORD = 'e2e-test-password'
TEST_PORT = 8443


@pytest.fixture(scope='session')
def session_log_file(tmp_path_factory):
    """Session-scoped copy of the fixture log file."""
    src = os.path.join(os.path.dirname(__file__), 'fixtures', 'sample_messages.log')
    dest = tmp_path_factory.mktemp('logs') / 'messages.log'
    shutil.copy2(src, dest)
    return str(dest)


@pytest.fixture(scope='session')
def ssl_certs(tmp_path_factory):
    """Generate self-signed SSL certs for testing."""
    cert_dir = tmp_path_factory.mktemp('certs')
    cert_path = str(cert_dir / 'cert.pem')
    key_path = str(cert_dir / 'key.pem')
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
        '-keyout', key_path, '-out', cert_path,
        '-days', '1', '-nodes', '-subj', '/CN=localhost'
    ], check=True, capture_output=True)
    return cert_path, key_path


@pytest.fixture(scope='session')
def live_server(session_log_file, ssl_certs):
    """Start a real Flask-SocketIO server for E2E tests."""
    cert_path, key_path = ssl_certs
    app, socketio = create_app(config={
        'SYSLOG_FILE': session_log_file,
        'SYSLOG_PASSWORD': TEST_PASSWORD,
        'INITIAL_LINES': 100,
        'SECRET_KEY': 'e2e-secret-key',
        'SSL_CERT': cert_path,
        'SSL_KEY': key_path,
        'PORT': TEST_PORT,
        'SESSION_COOKIE_SECURE': True,
    })
    load_initial_logs(app)

    # Start tail in background for live streaming tests
    socketio.start_background_task(
        target=_tail_log_file, app=app, socketio=socketio
    )

    thread = threading.Thread(
        target=socketio.run,
        kwargs={
            'app': app,
            'host': '127.0.0.1',
            'port': TEST_PORT,
            'ssl_context': (cert_path, key_path),
            'allow_unsafe_werkzeug': True,
            'log_output': False,
        },
        daemon=True,
    )
    thread.start()
    time.sleep(2)  # Wait for server startup

    yield f'https://127.0.0.1:{TEST_PORT}'


def _tail_log_file(app, socketio):
    """Tail the log file for live streaming."""
    from app import tail_log_file
    tail_log_file(app, socketio)


@pytest.fixture
def browser():
    """Headless Chrome browser."""
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--ignore-certificate-errors')
    driver = webdriver.Chrome(options=options)
    driver.implicitly_wait(10)
    yield driver
    driver.quit()


@pytest.fixture
def logged_in_browser(browser, live_server):
    """Browser that is already logged in."""
    browser.get(f'{live_server}/login')
    password_input = browser.find_element(By.ID, 'password')
    password_input.send_keys(TEST_PASSWORD)
    browser.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
    WebDriverWait(browser, 10).until(
        EC.presence_of_element_located((By.ID, 'log-container'))
    )
    return browser


class TestLoginPage:
    """Tests for the login page in the browser."""

    def test_login_page_loads(self, browser, live_server):
        browser.get(f'{live_server}/login')
        assert 'Login' in browser.title
        password_input = browser.find_element(By.ID, 'password')
        assert password_input.is_displayed()

    def test_login_correct_password(self, browser, live_server):
        browser.get(f'{live_server}/login')
        password_input = browser.find_element(By.ID, 'password')
        password_input.send_keys(TEST_PASSWORD)
        browser.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
        WebDriverWait(browser, 10).until(
            EC.presence_of_element_located((By.ID, 'log-container'))
        )
        assert 'Syslog Viewer' in browser.page_source

    def test_login_wrong_password(self, browser, live_server):
        browser.get(f'{live_server}/login')
        password_input = browser.find_element(By.ID, 'password')
        password_input.send_keys('wrongpassword')
        browser.find_element(By.CSS_SELECTOR, 'button[type="submit"]').click()
        WebDriverWait(browser, 5).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, '.error'))
        )
        error = browser.find_element(By.CSS_SELECTOR, '.error')
        assert 'Invalid password' in error.text


class TestMainUI:
    """Tests for the main log viewer UI."""

    def test_log_entries_displayed(self, logged_in_browser, live_server):
        WebDriverWait(logged_in_browser, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, '.log-entry'))
        )
        entries = logged_in_browser.find_elements(By.CSS_SELECTOR, '.log-entry')
        assert len(entries) > 0

    def test_host_filter_populated(self, logged_in_browser, live_server):
        host_filter = logged_in_browser.find_element(By.ID, 'host-filter')
        options = host_filter.find_elements(By.TAG_NAME, 'option')
        option_texts = [o.text for o in options]
        # "All machines" plus at least some hosts
        assert len(options) >= 2
        assert 'All machines' in option_texts

    def test_search_filters_entries(self, logged_in_browser, live_server):
        # Wait for entries to load
        WebDriverWait(logged_in_browser, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, '.log-entry'))
        )
        total_before = len(logged_in_browser.find_elements(By.CSS_SELECTOR, '.log-entry'))

        search_input = logged_in_browser.find_element(By.ID, 'search')
        search_input.send_keys('ERROR')
        time.sleep(0.5)  # Wait for filter to apply

        visible = [
            e for e in logged_in_browser.find_elements(By.CSS_SELECTOR, '.log-entry')
            if e.is_displayed()
        ]
        assert len(visible) < total_before
        assert len(visible) > 0

    def test_sort_toggle(self, logged_in_browser, live_server):
        sort_btn = logged_in_browser.find_element(By.ID, 'sort-toggle')
        assert sort_btn.text == 'Newest first'
        sort_btn.click()
        assert sort_btn.text == 'Oldest first'
        sort_btn.click()
        assert sort_btn.text == 'Newest first'

    def test_websocket_connected(self, logged_in_browser, live_server):
        WebDriverWait(logged_in_browser, 10).until(
            EC.text_to_be_present_in_element(
                (By.ID, 'status'), 'Connected'
            )
        )
        status = logged_in_browser.find_element(By.ID, 'status')
        assert 'Connected' in status.text

    def test_logout(self, logged_in_browser, live_server):
        logout_link = logged_in_browser.find_element(By.CSS_SELECTOR, '.logout-btn')
        logout_link.click()
        WebDriverWait(logged_in_browser, 10).until(
            EC.presence_of_element_located((By.ID, 'password'))
        )
        assert 'Login' in logged_in_browser.title


class TestLiveStreaming:
    """Test the real-time log streaming pipeline."""

    def test_new_log_entry_appears(self, logged_in_browser, live_server, session_log_file):
        """Append a line to the log file and verify it appears in the browser."""
        WebDriverWait(logged_in_browser, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, '.log-entry'))
        )
        initial_count = len(logged_in_browser.find_elements(By.CSS_SELECTOR, '.log-entry'))

        # Append a new syslog line to the file
        unique_marker = 'SELENIUM_LIVE_TEST_12345'
        new_line = f'Feb 16 12:00:00 testhost selenium[999]: {unique_marker}\n'
        with open(session_log_file, 'a') as f:
            f.write(new_line)

        # Wait for the new entry to appear
        WebDriverWait(logged_in_browser, 15).until(
            lambda driver: unique_marker in driver.page_source
        )
