"""Syslog parsing utilities."""

import re

# Syslog line parser
# Format: "Jan 15 14:23:01 hostname process[pid]: message"
SYSLOG_PATTERN = re.compile(
    r'^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.*)$'
)


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
