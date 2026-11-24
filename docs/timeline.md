# Attack timeline (UTC)

[Back to the README](../README.md)

The hunt window is 2026-10-23, 04:00 to 16:00 UTC. All times are UTC and come from the event time column (`OriginalTime`), not ingestion time.

| Visit | Time | What the telemetry shows |
|---|---|---|
| 1 | 04:32:44 | Nmap scripting engine scan begins from the internal host |
| 1 | 04:34:31 | Web shell `health-check.php` created as a root-owned file through an SSH session with sudo, then handed to the web server account |
| 1 | 04:34:34 to 04:34:50 | First commands through the shell; an implant is downloaded from a local port and started |
| 1 | 04:35:20 to 04:35:54 | Discovery and security-tool checks, database settings and `/etc/shadow` read, the user table dumped and archived with `tar` |
| 1 | 04:36:21 | Shell timestamp copied from `wp-login.php` (timestomping); implant moved to `/dev/shm/.cache-helper` |
| 1 | 04:36:45 | `auditctl -D`, `systemctl stop sysmon`, shell history cleared |
| 1 | 04:36:59 | Config file and dump passed through base64, then deleted |
| 1 | 04:37:19 | Cron job every 5 minutes, cookie backdoor written into `version.php`, ransom note written |
| 2 | 12:18:05 to 12:19:47 | Upload exploit attempts against PHP session handling (Apache error log, clock-corrected) |
| 2 | 12:21 to 12:26 | More discovery, an SSH key search, a new implant copy, then attempts to stop Sysmon, auditd and the Splunk forwarder |
| Gap | 12:27 to 13:43 | Every source silent: the host restarts |
| Responder | 13:49 to 13:52 | A responder removes the shell, the note and the crontab |
| 3 | 13:52 to 15:07 | Second scan burst, upload exploit attempts, the shell re-created, data staged again, the note rewritten, and the attacker reads the logs for its own activity |

## Visit windows

| Visit | Window |
|---|---|
| 1 | 04:32 to 04:40 |
| 2 | 12:18 to 12:26 |
| 3 | 13:52 to 15:07 |

## Notes on the times

- **Apache error log clock.** The error log clock is 4 hours behind. Its times are corrected by +4 hours before they are placed on this timeline. That is how the visit 2 upload exploit warnings land at 12:18:05 to 12:19:47.
- **The silence: 77 minutes and 70 minutes.** The two numbers measure different sources.
  - Sysmon and auditd have no events in any one-minute bin from 12:27 to 13:43 inclusive. That is 77 minutes.
  - The Apache access log has none from 12:30 to 13:39. That is 70 minutes, and it matches the 14 empty 5-minute bins that [Rule 4](../detections/rule4_host_silent.kql) finds.
- **Why it was a restart.** Audit serial numbers and process IDs reset when logging returned. That points to a reboot, not a stopped forwarder.
- **What the cleanup left.** The responder at 13:49 to 13:52 removed the shell, the note and the crontab. The first cleanup did not name the cookie backdoor in `wp-includes/version.php`.
