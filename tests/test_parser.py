"""Unit tests for syslog line parsing and level detection."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from syslog_parser import parse_syslog_line, detect_level


class TestParseSyslogLine:
    """Tests for parse_syslog_line()."""

    def test_standard_line_with_pid(self):
        line = 'Jan 15 14:23:01 webserver01 sshd[12345]: Accepted publickey for root'
        result = parse_syslog_line(line)
        assert result['timestamp'] == 'Jan 15 14:23:01'
        assert result['hostname'] == 'webserver01'
        assert result['process'] == 'sshd'
        assert result['message'] == 'Accepted publickey for root'
        assert result['level'] == 'info'

    def test_line_without_pid(self):
        line = 'Jan 15 14:23:01 webserver01 kernel: Out of memory: Kill process 123'
        result = parse_syslog_line(line)
        assert result['hostname'] == 'webserver01'
        assert result['process'] == 'kernel'
        assert result['message'] == 'Out of memory: Kill process 123'

    def test_unparseable_line(self):
        line = 'this is not a syslog line'
        result = parse_syslog_line(line)
        assert result['hostname'] == 'unknown'
        assert result['timestamp'] == ''
        assert result['process'] == ''
        assert result['message'] == 'this is not a syslog line'
        assert result['level'] == 'info'

    def test_empty_line(self):
        result = parse_syslog_line('')
        assert result['hostname'] == 'unknown'
        assert result['message'] == ''

    def test_single_digit_day_with_space(self):
        line = 'Feb  3 09:15:22 myhost sshd[111]: test message'
        result = parse_syslog_line(line)
        assert result['timestamp'] == 'Feb  3 09:15:22'
        assert result['hostname'] == 'myhost'

    def test_process_with_slash(self):
        line = 'Jan 15 08:05:00 mailserver postfix/smtpd[2345]: connect from unknown'
        result = parse_syslog_line(line)
        assert result['process'] == 'postfix/smtpd'
        assert result['hostname'] == 'mailserver'

    def test_raw_field_preserved(self):
        line = 'Jan 15 08:00:01 host CRON[1234]: (root) CMD (/usr/bin/backup.sh)'
        result = parse_syslog_line(line)
        assert result['raw'] == line.strip()

    def test_line_with_trailing_whitespace(self):
        line = 'Jan 15 08:00:01 host sshd[1]: test message   \n'
        result = parse_syslog_line(line)
        assert result['message'] == 'test message'
        assert result['raw'] == 'Jan 15 08:00:01 host sshd[1]: test message'

    def test_level_assigned_from_message(self):
        line = 'Jan 15 08:04:33 host nginx[7890]: error: upstream timed out'
        result = parse_syslog_line(line)
        assert result['level'] == 'error'

    def test_hostname_with_domain(self):
        line = 'Jan 15 14:23:01 server.example.com sshd[1234]: Accepted publickey'
        result = parse_syslog_line(line)
        assert result['hostname'] == 'server.example.com'
        assert result['process'] == 'sshd'

    def test_process_with_hyphen(self):
        line = 'Jan 15 14:23:01 server systemd-logind[456]: New session'
        result = parse_syslog_line(line)
        assert result['process'] == 'systemd-logind'

    def test_empty_message(self):
        line = 'Jan 15 14:23:01 server process[1]: '
        result = parse_syslog_line(line)
        assert result['message'] == ''

    def test_message_with_colons(self):
        line = 'Jan 15 14:23:01 server app[1]: key: value: data'
        result = parse_syslog_line(line)
        assert result['message'] == 'key: value: data'

    def test_message_with_brackets(self):
        line = 'Jan 15 14:23:01 server app[1]: User [admin] logged in'
        result = parse_syslog_line(line)
        assert result['message'] == 'User [admin] logged in'

    def test_numeric_hostname(self):
        line = 'Jan 15 14:23:01 192.168.1.1 syslog[1]: message'
        result = parse_syslog_line(line)
        assert result['hostname'] == '192.168.1.1'

    def test_unicode_in_message(self):
        line = 'Jan 15 14:23:01 server app[1]: User José logged in from München'
        result = parse_syslog_line(line)
        assert 'José' in result['message']
        assert 'München' in result['message']

    def test_very_long_message(self):
        long_msg = 'x' * 10000
        line = f'Jan 15 14:23:01 server app[1]: {long_msg}'
        result = parse_syslog_line(line)
        assert result['message'] == long_msg
        assert result['hostname'] == 'server'


class TestDetectLevel:
    """Tests for detect_level()."""

    def test_error_keyword(self):
        assert detect_level('ERROR: something broke') == 'error'

    def test_fail_keyword(self):
        assert detect_level('Failed password for invalid user') == 'error'

    def test_fatal_keyword(self):
        assert detect_level('fatal: unable to connect') == 'error'

    def test_crit_keyword(self):
        assert detect_level('CRITICAL: disk full') == 'error'

    def test_warn_keyword(self):
        assert detect_level('WARNING: disk space low') == 'warn'

    def test_warning_keyword(self):
        assert detect_level('warning: mounting unchecked fs') == 'warn'

    def test_debug_keyword(self):
        assert detect_level('DEBUG: Buffer pool hit ratio 999') == 'debug'

    def test_info_default(self):
        assert detect_level('Accepted publickey for root') == 'info'

    def test_case_insensitive(self):
        assert detect_level('Error: something') == 'error'
        assert detect_level('WARNING: something') == 'warn'
        assert detect_level('Debug: tracing') == 'debug'

    def test_keyword_in_context(self):
        assert detect_level('authentication failure for user admin') == 'error'

    def test_no_false_positive(self):
        assert detect_level('information about the system') == 'info'

    def test_empty_string(self):
        assert detect_level('') == 'info'
