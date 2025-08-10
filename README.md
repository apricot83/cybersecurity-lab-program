# cybersecurity-lab-program

This repository documents and provides hands‑on labs for a comprehensive “zero to hero” cyber‑security learning program.  The program is designed as an experiential self‑study path inspired by SANS‑style training: you will build and maintain a full‑stack home lab, learn by doing projects, integrate AI/ML ideas, and produce resume‑ready artifacts.

## Overview

The goal is to take a complete beginner from foundational concepts through advanced topics such as DevSecOps, threat detection, incident response, offensive security, cloud security and zero‑trust architectures.  Rather than relying on third‑party training platforms, you will build your own network, instrumentation and automation.  Projects include pfSense‑driven networks, host‑intrusion detection with Wazuh, network detection with Suricata, threat‑intelligence sharing with MISP, case management with The Hive/Cortex, automated IaC pipelines (Terraform, Ansible) scanned by Checkov, and data‑driven dashboards with ELK.  Python is used throughout for scripting, automation, enrichment and machine‑learning prototypes.

## Phase 1 – Home Lab and Scripting Fundamentals

* Create all required accounts (GitHub, Slack, Jira, AWS/Azure free tiers, VirusTotal, AbuseIPDB, Tenable Nessus, Jenkins, HashiCorp Cloud) and generate API keys stored in `.env` files (never committed).
* Install host tools on your workstation: Homebrew, Python 3.12 + pipx/poetry, quality/security linters (ruff, mypy, pytest, bandit, pip‑audit, pre‑commit), VS Code with extensions, Wireshark, virtualization (VirtualBox or VMware), Docker and Colima (or Docker Desktop).
* Design a virtual network: Host‑only (management), NAT (internet) and internal segments.  Use pfSense as a router/firewall to connect them and enforce policies.
* Provision VMs: Ubuntu servers for Docker stacks and CI/CD, a Suricata sensor, a Wazuh manager (or Wazuh container), a Windows workstation (with Sysmon) and a Kali Linux attacker.  Use Ansible to harden and configure them.
* Deploy core services: an ELK stack (Elasticsearch/Logstash/Kibana) via docker‑compose, Suricata on a sensor VM with custom rules, Wazuh manager with agents, MISP (malware information sharing) and The Hive/Cortex via Docker.  Wire Suricata and Wazuh events into ELK and configure case creation in The Hive via Python webhooks.
* Learn networking fundamentals (OSI, IP/TCP/UDP, routing, DNS), basic Linux and Windows administration, and introductory scripting (Python, Bash, PowerShell).  Write scripts to automate scanning and log analysis.

## Phase 2 – Network & Web Security

* Study firewalls, VPNs and IDS/IPS concepts.  Tune your pfSense rules and Suricata signatures.  Capture traffic with Wireshark and build dashboards in Kibana.
* Explore vulnerability scanning with Nmap, OpenVAS/Greenbone and Tenable Nessus.  Analyse reports and remediate in your lab.
* Install and secure sample web applications (e.g., OWASP Juice Shop or DVWA) on a separate VM.  Perform reconnaissance and attacks from Kali and mitigate them through secure coding and configuration.
* Practice TLS, certificates and encryption with OpenSSL and GnuPG.

## Phase 3 – Secure Coding, DevSecOps & Automation

* Learn secure coding practices: input validation, authentication/authorization, cryptography and error handling.  Build a simple REST API in Python and secure it.
* Set up continuous integration/continuous deployment (CI/CD) using Jenkins or GitHub Actions.  Use Terraform to define cloud lab resources, Ansible to configure hosts, and integrate security scanning tools: Checkov for IaC, Bandit for Python, Trivy for containers, Ruff/Mypy/PyTest for code quality.
* Containerize services with Docker and orchestrate them with Kubernetes (optional: Minikube/Kind).  Scan images and containers for vulnerabilities.
* Incorporate pre‑commit hooks to enforce coding standards and run security checks automatically.

## Phase 4 – Threat Detection & Incident Response

* Ingest logs into ELK: Sysmon and Winlogbeat from Windows, Filebeat/Auditbeat from Linux, Suricata EVE JSON and Wazuh alerts.  Build detection dashboards and alerts.
* Write and tune detection rules: Sigma for SIEM, Suricata custom rules for network events, YARA rules for file analysis, and Python heuristics.  Use MITRE ATT&CK to map techniques.
* Integrate Wazuh alerts with MISP and automatically enrich indicators.  Use Python scripts to call VirusTotal and AbuseIPDB and append data to The Hive cases.
* Develop incident response playbooks.  Use The Hive to manage cases, collaborate with team members, and run automated analyzers via Cortex.  Document each investigation thoroughly.

## Phase 5 – Offensive Security & Vulnerability Management

* Study penetration testing methodologies and frameworks (Nmap, Metasploit, Burp, sqlmap).  Conduct red‑team exercises against your lab environment and then harden systems based on findings.
* Perform password auditing and credential hunting using John the Ripper and Hashcat.  Explore honeypots and deception technologies.
* Build a vulnerability management process: schedule periodic scans with Nessus/OpenVAS, triage findings based on CVSS and business impact, and track remediation using Jira.
* Explore adversary emulation and detection engineering frameworks.

## Phase 6 – Advanced Topics and Specialisation

* Deep dive into cloud security (AWS, Azure, GCP) and zero‑trust architectures.  Build micro‑services in the cloud and apply least‑privilege IAM policies.
* Experiment with AI/ML in cyber security: anomaly detection on network traffic, malware classification using feature extraction and simple models.  Study adversarial ML and model robustness.
* Explore digital forensics and malware analysis tools (Volatility, Autopsy, FTK).  Study incident response for industrial control systems (ICS) and IoT.
* Prepare for certifications (e.g., Security+, GCIH, GPEN, OSCP, or cloud‑native security certs).  Engage with the community through CTFs and open‑source projects.

## Contributing & Structure

All labs are documented in the `/docs` directory and grouped by phase.  Infrastructure code lives under `/iac` and `/ansible`; pipelines under `/jenkins`; detection rules under `/detections`; ELK and Wazuh configurations under `/elk` and `/wazuh`.  Each Markdown lab page follows a structure: goal → prerequisites → steps → evidence → result.  Use Git branches and pull requests for changes; pre‑commit hooks ensure code quality.

---

This README reflects the latest program design, emphasising self‑hosted tools (Wazuh, MISP, The Hive), automation with Terraform/Ansible, and Python‑driven detection engineering.  See `phase1/home‑lab‑setup.md` for detailed setup instructions.
