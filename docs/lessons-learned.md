# Lessons learned

[Back to the README](../README.md)

Five things this hunt taught me, including two places where I got it wrong first.

### 1. Check which column holds event time

In this data, `TimeGenerated` is the time Sentinel ingested a record, not the time the event happened. A query scoped on `TimeGenerated` looks at the wrong slice of the day. I scoped every query on `OriginalTime` instead. The Apache error log was a second trap: its clock is 4 hours behind every other source. Before I trust a timestamp, I check which clock wrote it.

### 2. When every source goes quiet at once, check the counters on either side of the gap

Visit 2 ended with attempts to stop Sysmon, auditd and the Splunk forwarder, and then every source went silent. My first explanation was the forwarder stop. It fit the story, so I believed it. Then I compared the audit serial numbers and process IDs on either side of the gap, and both had reset. Those counters reset only on a reboot. The 77-minute silence was a host restart. I now check the counters before I name a cause.

### 3. Build detections from the findings, then run them

My first rule watched for files written by the web server account. In this hunt, both shells were written by root. The first one came through an SSH session with sudo. That first rule would have caught neither of them. Rule 1 keys on any account, and I only know it works because I ran it over the hunt window: 6 rows, both shells and the `version.php` backdoor among them. A rule I have not run is a guess.

### 4. Know when each sensor starts recording

Sysmon started recording at 05:24. The first visit was over by 04:40. Sysmon missed all of it: the shell, the implant, the cron job and the backdoor. Auditd had every step. If I had hunted in Sysmon alone, I would have started the story in the wrong place and missed where the persistence was planted. Now I check each sensor's first event before I trust its silence.

### 5. Say "probable" when the evidence stops short

I can show the attacker archived and base64-encoded the config file and the user table. I can show HTTP response sizes that fit that output being sent back. I cannot show the data leaving, because response bodies are not logged and network events have no destination. So the finding is "very likely, not proven." Saying more than the evidence supports would make the report easier to read and less true.
