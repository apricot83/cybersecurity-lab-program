# Phase 2 – Network & Web Security

Phase 2 builds on your home‑lab foundation by focusing on network defence and web application security.  You will learn how attacks occur on networks and applications, practise vulnerability scanning and hardening, and tune your detection stack to catch malicious activity.

## 1. Network Security Essentials

* **Understand firewalls and VPNs.**  Study how stateful firewalls filter packets and how VPNs provide secure remote access.  Configure pfSense to implement basic firewall rules and a site‑to‑site VPN.
* **Intrusion detection and prevention.**  Review how IDS/IPS systems like Suricata monitor network traffic.  Tune your Suricata installation by enabling Emerging Threats rulesets and writing custom rules.  Use a **TCP/IP and tcpdump** cheat sheet to refresh packet‑analysis basics.
* **Packet analysis exercises.**  Using Wireshark and `tcpdump`, capture traffic between your VMs.  Identify protocols and handshake processes.  Write a short report on any unusual packets, referencing cheat sheets as needed.

## 2. Web Application Fundamentals

* **HTTP basics.**  Review HTTP verbs, status codes, cookies and sessions.  Learn about TLS and how to configure HTTPS on a test web server.
* **OWASP Top 10.**  Read through the OWASP Cheat Sheet Series on injection prevention, cross‑site scripting (XSS) prevention and authentication best practices.  Deploy a deliberately vulnerable web application such as **OWASP Juice Shop** or **DVWA** in your lab and explore these vulnerabilities.
* **Web proxies and scanners.**  Install **OWASP ZAP** and learn how to intercept and modify HTTP requests.  Use its automated scanner to discover issues in your test application and practise fixing them.

## 3. Vulnerability Scanners

* **Network scanning with Nmap.**  Perform host discovery and port scanning across your internal network.  Use an **Nmap cheat sheet** for command reference.  Document open services and attempt version detection.
* **OpenVAS/Greenbone.**  Install OpenVAS on your Docker host or another VM.  Run an authenticated scan against a test VM and review the findings.  Prioritise vulnerabilities based on CVSS scores.
* **Nessus Essentials.**  Use your Tenable licence to scan your lab network.  Compare results with OpenVAS and discuss any discrepancies.  Export reports and save them under `/docs/scans/`.

## 4. Web Application Hardening

* **Secure configuration.**  Learn how to disable directory listings, enforce TLS, implement HTTP security headers (CSP, HSTS) and limit file uploads.  Apply these settings to your test app and verify they mitigate the issues identified earlier.
* **Authentication and session management.**  Implement multi‑factor authentication on your application (e.g., using Authy or Google Authenticator) and enforce secure session cookies.  Test session fixation and session expiration behaviours.
* **Automated security testing in CI/CD.**  Add ZAP and `bandit` scans to your CI pipeline.  Fail the build on high‑severity findings and notify Slack/Jira.  Use Checkov to scan Dockerfiles and Kubernetes manifests.

## 5. Documentation and Reflection

For each exercise, create a lab note in `/docs/phase2/` that includes:

1. **Goal.**  What you are testing or configuring.
2. **Procedure.**  Steps taken, commands used, and tools involved.
3. **Evidence.**  Screenshots or logs demonstrating the activity (e.g., ZAP alerts, Nmap output).
4. **Lessons learned.**  How the vulnerability was exploited or mitigated and any cheat sheets consulted.

By the end of Phase 2 you will have hands‑on experience in network packet analysis, intrusion detection tuning, vulnerability scanning, and web application security.  These skills build a solid foundation for secure coding and DevSecOps in the next phase.
