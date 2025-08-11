# Phase 4 – Threat Detection & Incident Response

Phase 4 turns your lab into a mini security operations centre (SOC).  You will design and tune detection rules, practise threat hunting, and respond to incidents using the tooling you set up in earlier phases.  This phase also introduces a structured incident‑response process with runbooks derived from our new cheat sheet.

## 1. Building Detection Content

* **Sigma rules.**  Learn the Sigma rule format for writing platform‑independent detections.  Create rules to detect suspicious PowerShell usage, lateral movement (e.g., `PsExec`), and privilege escalation.  Convert them to Elastic or Splunk queries using `sigmac` and test them in Kibana.
* **Suricata rules.**  Develop custom IDS signatures in `local.rules` to alert on unusual DNS queries, port scans, or HTTP headers.  Test them by generating traffic from your Kali VM and verify they appear in the ELK dashboards.
* **YARA rules.**  Write YARA signatures to detect malicious binaries or scripts.  Run YARA scans on your Windows and Linux VMs and forward any matches to The Hive for investigation.
* **Cheat sheet integration.**  Use a JSON and `jq` quick‑start cheat sheet to build scripts that parse Suricata EVE logs and Wazuh alerts.  Include these scripts in your `/scripts/` directory for reuse.

## 2. Threat Hunting & Monitoring

* **Kibana dashboards.**  Create custom dashboards and visualisations in Kibana for Windows Event Logs (Sysmon), Linux audit logs, Suricata alerts, and Wazuh events.  Use saved searches to hunt for anomalous patterns (rare processes, unusual network destinations).
* **Wazuh correlation.**  Enable and customise Wazuh rulesets to detect brute force attempts, privilege misuse, and malware.  Configure Wazuh to send high‑severity alerts to a webhook endpoint for automated case creation.
* **Scheduled hunts.**  Write Python scripts that query Elasticsearch for specific IOC patterns (e.g., MD5 hashes from MISP feeds) and alert when matches are found.  Schedule these hunts via Cron or Jenkins.

## 3. Incident Response Runbooks

* **Cheat‑sheet driven triage.**  Create a Markdown file (`phase4/incident‑response‑cheatsheet.md`) summarising the commands and procedures from the uploaded Incident Response Cheat Sheet.  The runbook should guide you through initial triage steps: checking user accounts, reviewing logs (`lastlog`, `auth.log`, `history`), examining running processes (`top`, `ps aux`), inspecting services and scheduled tasks, and gathering network information.  For Windows hosts, include equivalent PowerShell commands.  This runbook helps ensure consistent evidence collection during an incident.
* **Case management with The Hive.**  Deploy The Hive and Cortex (if not already running) on your Docker host.  Create case templates with tasks such as triage, containment, eradication, and recovery.  Configure a webhook or script to automatically create a case when Wazuh sends a high‑severity alert.
* **Eradication and recovery.**  Practise isolating a compromised host (e.g., using pfSense firewall rules), removing malicious files or processes, and restoring services from backups or golden images.  Document each step and link it back to the detection that triggered the response.

## 4. Forensics and Analysis

* **Memory and disk forensics.**  Use tools like Volatility, FTK Imager, or Autopsy (if resources permit) to capture and analyse memory and disk images.  Refer to memory forensics and SIFT cheat sheets for guidance.  Analyse suspicious artefacts and correlate them with your logs.
* **Threat intelligence enrichment.**  Use your VirusTotal and AbuseIPDB API keys to enrich indicators (hashes, IPs, domains).  Automate this with Python scripts and attach the results to The Hive cases.

## 5. Documentation and Improvement

After each exercise, update the runbooks in `/docs/phase4/` with what worked well and what didn’t.  Keep a timeline of events for each simulated incident.  At the end of Phase 4 you should be comfortable writing your own detection rules, performing structured hunts, and following a repeatable incident‑response process.
