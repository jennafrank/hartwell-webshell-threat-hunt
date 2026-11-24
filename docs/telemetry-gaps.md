# Telemetry gaps

[Back to the README](../README.md)

Six gaps I found in the telemetry during this hunt. Each one limited what I could see or prove.

| Gap | Why it matters |
|---|---|
| Sysmon starts recording at 05:24 | The first visit is visible in auditd only |
| Response bodies are not logged | Data leaving the server can be sized but not read |
| Commands hidden in a custom HTTP header | The access log does not record headers, so they never appear in it |
| Error log clock is 4 hours behind | Cross-table correlation silently misaligns |
| Network events have no destination | The implant's 215 connections cannot be tied to a destination |
| No alert on loss of collection | The endpoint sensors were silent for 77 minutes and the web log for 70, and nothing alerted |

## Why each one matters

### 1. Sysmon starts recording at 05:24

The first visit ran from 04:32 to 04:40, before Sysmon was recording. The web shell, the implant, the credential reads, the cron job and the core-file backdoor all happened in that window. An analyst who hunted in Sysmon alone would have started the story at the second visit and missed where the persistence was planted. Auditd had all of it.

### 2. Response bodies are not logged

The attacker archived and base64-encoded the config file and the user table, and the HTTP response sizes fit that output being sent back. Without the response bodies, I can show the size of each response but not its content. This gap is the reason data theft is rated "very likely, not proven" and not stated as fact.

### 3. Commands hidden in a custom HTTP header

The commands sent to the shell traveled in a custom HTTP header. The Apache access log does not record headers, so those commands never appear in it. A web log alone cannot say what the shell was told to do; the commands have to be seen on the host, in auditd.

### 4. Error log clock is 4 hours behind

The Apache error log is 4 hours behind every other source. A join on time across tables does not fail when this happens. It just returns the wrong rows, or none. The visit 2 upload exploit warnings only line up at 12:18:05 to 12:19:47 after a +4 hour correction.

### 5. Network events have no destination

The implant made 215 connections, but the network events carry no destination. I cannot tie those connections to a destination, which also means I cannot show where any data went.

### 6. No alert on loss of collection

The endpoint sensors (Sysmon and auditd) were silent for 77 minutes, from 12:27 to 13:43. The web log was silent for 70, from 12:30 to 13:39. Nothing alerted. A host that stops reporting is a blind spot, whatever the cause, and [Rule 4](../detections/rule4_host_silent.kql) was written to close it.
