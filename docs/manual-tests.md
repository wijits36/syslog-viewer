# Syslog Viewer - Manual Test Plan

## Prerequisites
- Fresh Linux VM or server with rsyslog
- Browser (Chrome/Firefox/Safari)
- Terminal access to server

---

## 1. Installation Tests

| Test | Steps | Expected Result |
|------|-------|-----------------|
| Fresh install | Run `sudo ./install.sh` | Prompts for password, completes without errors |
| Password validation | Enter empty password | Rejected, prompts again |
| Password confirmation | Enter mismatched passwords | Rejected, prompts again |
| Service auto-start | Check `systemctl status syslog-viewer` | Active (running) |
| Boot persistence | Run `systemctl is-enabled syslog-viewer` | "enabled" |
| Firewall configured | Run `firewall-cmd --list-ports` | 443/tcp listed (if firewalld present) |

## 2. Update & Uninstall Tests

| Test | Steps | Expected Result |
|------|-------|-----------------|
| Update preserves config | Run `sudo ./update.sh`, check password still works | Login succeeds with original password |
| Uninstall prompts | Run `sudo ./uninstall.sh` | Asks for confirmation |
| Uninstall removes files | Confirm uninstall, check `/opt/syslog-viewer` | Directory doesn't exist |
| Uninstall removes config | Check `/etc/syslog-viewer` | Directory doesn't exist |
| Uninstall stops service | Run `systemctl status syslog-viewer` | "not found" or inactive |

---

## 3. Authentication Tests

| Test | Steps | Expected Result |
|------|-------|-----------------|
| Login page loads | Navigate to `https://server-ip` | Login form displayed |
| Correct password | Enter correct password, submit | Redirected to log viewer |
| Wrong password | Enter wrong password, submit | "Invalid password" error shown |
| Direct URL blocked | Navigate to `https://server-ip/` without login | Redirected to login |
| API blocked | Navigate to `https://server-ip/api/logs` without login | Redirected to login |
| Session persists | Login, refresh page | Still logged in |
| Logout works | Click Logout button | Redirected to login, can't access viewer |

---

## 4. Log Display Tests

| Test | Steps | Expected Result |
|------|-------|-----------------|
| Initial load | Login and view page | Logs displayed, count shown in footer |
| Newest first default | Check first visible log | Most recent timestamp at top |
| Sort toggle | Click "Newest first" button | Button shows "Oldest first", order reverses |
| Sort toggle back | Click "Oldest first" button | Button shows "Newest first", order reverses |
| Real-time updates | Run `logger "test message"` on server | New log appears without refresh |
| Auto-scroll on | With auto-scroll checked, generate new log | View scrolls to show new entry |
| Auto-scroll off | Uncheck auto-scroll, scroll up, generate new log | View stays in place |

---

## 5. Filtering Tests

| Test | Steps | Expected Result |
|------|-------|-----------------|
| Machine dropdown populated | Check Machine dropdown | Contains hostnames from logs |
| Filter by machine | Select specific machine | Only logs from that machine shown |
| All machines | Select "All machines" | All logs shown again |
| Search by message | Type keyword in Search box | Only matching logs shown |
| Search by process | Type process name in Search box | Logs from that process shown |
| Combined filters | Select machine AND enter search term | Only logs matching both criteria |
| Clear search | Delete search text | All logs (for selected machine) shown |
| Entry count updates | Apply filter | Footer shows "(X shown)" |

---

## 6. UI/UX Tests

| Test | Steps | Expected Result |
|------|-------|-----------------|
| Sticky header | Scroll down through logs | Header stays fixed at top |
| Error highlighting | Find log with "error" or "fail" | Row has red/pink background |
| Warning highlighting | Find log with "warning" | Row has yellow/orange tint |
| Connection status | Check status indicator | Shows "Connected" (green) |
| Disconnect handling | Stop syslog-viewer service | Status changes to "Disconnected" (red) |
| Responsive layout | Resize browser to narrow width | Controls wrap, still usable |

---

## 7. Edge Cases

| Test | Steps | Expected Result |
|------|-------|-----------------|
| Long message | Generate log with 1000+ char message | Displays without breaking layout |
| Unicode characters | Generate log with emojis/accents | Characters display correctly |
| Special characters | Generate log with `<script>` or HTML | Escaped, not executed |
| Multiple tabs | Open viewer in two browser tabs | Both work independently |
| Rapid logs | Generate many logs quickly (`for i in {1..100}; do logger "test $i"; done`) | All appear, no crashes |

---

## 8. Security Tests

| Test | Steps | Expected Result |
|------|-------|-----------------|
| HTTPS enforced | Try `http://server-ip` | Connection refused or redirect to HTTPS |
| Certificate warning | Access site first time | Browser shows self-signed cert warning |
| Session isolation | Login in Chrome, try Firefox | Firefox requires separate login |
| No password in URL | Check browser URL bar after login | Password not visible |

---

## Sign-off

| Tester | Date | Version | Pass/Fail | Notes |
|--------|------|---------|-----------|-------|
| | | | | |
