# cybersecurity-lab-program

This repository contains documentation and hands‑on labs for a “zero to hero” cyber‑security learning program with AI/ML and engineering focus.  The program is designed as a year‑long self‑study path inspired by SANS‑style training.  It emphasises building a home lab, learning by doing, and producing resume‑ready projects.

## Overview

The goal of this program is to take a complete beginner from foundational concepts through advanced topics such as DevSecOps, threat detection, incident response, offensive security, cloud and zero‑trust architectures.  Along the way you will build projects (network analyzers, automated vulnerability pipelines, detection dashboards, etc.) that you can showcase during interviews.

## Phase 1 – Foundations and Scripting

* Build your home lab with VirtualBox/VMware and create Windows and Linux VMs.
* Learn networking fundamentals (OSI model, protocols) and operating system basics.
* Write simple Python, Bash and PowerShell scripts to enumerate processes, scan ports and parse logs.

## Phase 2 – Network and Web Security

* Study firewall, VPN and IDS/IPS concepts.
* Deploy Snort or OSSEC in your lab and generate benign/malicious traffic to understand signature‑based detection.
* Set up vulnerable web applications (OWASP Juice Shop, DVWA) and scan them with Zed Attack Proxy (ZAP); fix at least one vulnerability.

## Phase 3 – Secure Coding, DevSecOps & Automation

* Learn secure coding practices and implement authentication, authorization and input validation.
* Build a CI/CD pipeline using Jenkins or GitLab CI and integrate SAST/DAST tools.
* Containerize your applications with Docker and deploy them on Kubernetes; scan images with Trivy.
* Automate infrastructure with Ansible or Terraform.

## Phase 4 – Threat Detection & Incident Response

* Deploy a SIEM (Elastic Stack or Splunk) and forward logs from your VMs.
* Write Sigma, KQL or SPL detection rules to catch MITRE ATT&CK techniques.
* Simulate incidents with Metasploit; perform forensics with Wireshark and open‑source tools; document your incident‑response actions.

## Phase 5 – Offensive Security & Vulnerability Management

* Learn penetration‑testing methodology and use tools like Metasploit, Nmap and OpenVAS.
* Create an automated vulnerability management pipeline that runs scans and prioritizes findings.
* Conduct red vs blue exercises by exploiting vulnerabilities and then remediating them.

## Phase 6 – Advanced Topics & Specialisation

* Deepen your knowledge in cloud security, zero‑trust architectures and infrastructure‑as‑code.
* Explore AI/ML security by building a simple anomaly detection model for network traffic.
* Study malware analysis, reverse engineering and IoT/OT security if these interest you.
* Prepare for certifications (Security+, GIAC, GPEN, GCIH) and soft‑skills development.

## Using this repository

* Each phase will have its own directory (e.g., `phase1/`, `phase2/`) containing lab instructions, scripts, and notes.
* `report.md` (to be added) will include a detailed report on the skills, tools and technologies for key cyber‑security roles.
* Issues and pull requests can be used to track tasks, ask questions and submit improvements.

## License

This project is licensed under the MIT License – see the LICENSE file for details.
