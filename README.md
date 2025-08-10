# cybersecurity-lab-program

This repository contains the code, infrastructure definitions, documentation, and labs for a comprehensive “zero‑to‑hero” cyber‑security learning program.  The program is designed to be hands‑on and project‑driven: you build a full‑stack home lab, learn by doing, integrate AI/ML ideas where appropriate, and leave with a portfolio of technical artifacts.  It follows a phased approach inspired by SANS‑style training and is intended for newcomers who want to become proficient security engineers, detection engineers, or DevSecOps practitioners.

## Overview

The program takes you from foundational concepts through advanced topics such as network defence, DevSecOps, threat detection, incident response, offensive security, cloud security and zero‑trust architectures.  Unlike many courses that rely on third‑party training platforms, you will build your own network, servers, detection stack, and automation pipeline.  Key projects include:

- **PfSense‑driven networks** with separate management, internal and internet segments.
- **Host‑intrusion detection** using Wazuh and Sysmon.
- **Network detection** with Suricata sensors and custom rules.
- **Threat‑intelligence sharing** through MISP and enrichment with VirusTotal/AbuseIPDB.
- **Case management** with The Hive and Cortex to triage and track incidents.
- **Infrastructure‑as‑code pipelines** using Terraform and Ansible, scanned by Checkov and integrated into Jenkins or GitHub Actions.
- **Data‑driven dashboards** built on the ELK Stack (Elasticsearch, Logstash, Kibana).
- **Python scripting** throughout—for automating scans, parsing logs, enriching alerts, integrating APIs, and prototyping basic ML models.

The repository is structured into phases.  Each phase includes a high‑level description here in the README and detailed step‑by‑step instructions under the corresponding folder in `phase1/`, `phase2/`, etc.

## Phase 1a – Home Lab Setup

Phase 1a is about building a safe and realistic environment where you can practise.  You will create the accounts, tools, networks and virtual machines that form the foundation for later phases.

  - **Create essential accounts**: Set up free accounts on key services and enable multi‑factor authentication wherever possible.  Detailed sign‑up instructions and best practices are documented in `phase1/home‑lab‑setup.md`.  Use the official sign‑up pages below:

    - [GitHub](https://github.com/signup) — host your code, documentation and CI pipelines.
    - [Slack](https://slack.com/get-started#/signup) — receive alerts from your pipelines and monitoring tools, and collaborate with teammates.
    - [Jira](https://www.atlassian.com/software/jira/free) — or another ticketing system to track tasks and incident‑response actions.
    - [AWS Free Tier](https://aws.amazon.com/free) & [Azure Free Account](https://azure.microsoft.com/en-us/free/) — provision cloud resources (VPCs, subnets, virtual machines) for later experiments.
    - [VirusTotal](https://www.virustotal.com/gui/join-us) & [AbuseIPDB](https://www.abuseipdb.com/register) — look up file and IP reputation when investigating alerts.
    - [HashiCorp Terraform Cloud](https://app.terraform.io/signup) or [Vault](https://developer.hashicorp.com/vault) — securely store your Terraform state and secrets.
    - [Tenable Nessus Essentials](https://www.tenable.com/products/nessus/nessus-essentials) — perform vulnerability scans of your internal network.
    - [Jenkins](https://www.jenkins.io/download/) — install on your CI server to run pipelines; you can also use GitHub Actions if you prefer.
    - Generate API keys where required and store them in a local `.env` file rather than committing them to GitHub.

  - **Install host tools**: Use Homebrew (macOS) or your Linux/Windows package manager to install Python 3.12 and set up `pipx` and `poetry` for managing Python packages.  Add Git and **Visual Studio Code** as your primary IDE; install extensions for Python, YAML, Terraform, Ansible and Docker, and use the Remote‑SSH extension to edit files inside your VMs.  Install security linters such as `ruff`, `mypy`, `pytest`, `bandit`, `pip‑audit`, and enable `pre‑commit` hooks to run these tools automatically.  Finally, install Wireshark for packet analysis, virtualization software (VirtualBox or VMware) and a container runtime (Docker Desktop or Docker/Colima).

- **Design the virtual network**: Create three virtual networks in VirtualBox/VMware—a host‑only management network, a NAT or DMZ network for internet access, and an internal network for servers and workstations.  Deploy a **pfSense** firewall/router with interfaces on each network.  Configure pfSense to allow management traffic from your host, route internal traffic, and perform NAT for external access.

- **Provision virtual machines**: Deploy several VMs in your lab:
  - **Ubuntu Docker host** – runs Docker and Docker Compose for services like the ELK stack, Wazuh (if containerised), MISP and The Hive.
  - **CI/CD and IaC server** – runs Jenkins (or GitLab CI) and installs Terraform and Ansible for automation.  This VM holds your pipeline definitions and runs Checkov, Bandit and other scans on your code.
  - **Suricata sensor** – runs Suricata either as a dedicated VM or container to monitor network traffic.  Configure its `HOME_NET` to match your internal network and enable JSON logging.
  - **Wazuh manager** – collects logs from Linux and Windows agents, monitors file integrity and command execution, and exposes alerts via API.  You can deploy Wazuh in a container or on its own VM.
  - **Windows workstation** – a Windows 10/11 VM with Sysmon to generate detailed endpoint logs.  Install Winlogbeat to ship logs to the ELK stack and register the host as a Wazuh agent.
  - **Kali Linux attacker** – a Kali VM used for reconnaissance and testing.  Keep the toolkit focused (Nmap, Metasploit, YARA, Burp) to practise both attacking and defending against realistic threats.

- **Deploy core services**: Use Docker Compose on your Ubuntu host to run the ELK stack (Elasticsearch, Logstash, Kibana).  Deploy Suricata sensors, Wazuh, MISP and The Hive/Cortex, either as containers or on their own VMs.  Configure Suricata to send JSON logs to Logstash, register Wazuh agents, and connect MISP and The Hive via API so that high‑priority alerts can be converted into cases.

- **Document as you go**: Create a `/docs` directory and record every step you take—network diagrams, VM specifications, firewall rules, installation commands, troubleshooting notes and screenshots.  This documentation will be invaluable for future phases and job interviews.

## Phase 1b – Scripting and Python Fundamentals

In Phase 1b you learn the core concepts and scripting skills that underpin everything else in the program.  The focus is on mastering Python as your primary automation tool while getting comfortable with Bash and PowerShell.

- **Learn networking and OS basics**: Understand the OSI model, IP addressing, ports and protocols (TCP/UDP), DNS and routing.  Practise Linux command‑line skills (file permissions, processes, networking tools like `netstat`, `ss` and `tcpdump`) and Windows administration (PowerShell basics, Event Viewer, Sysmon configuration).

- **Practise scripting in Python**: Install a Python virtual environment using `pipx` or `poetry` and practise writing scripts that automate common tasks.  Start with simple programs that scan IP ranges using `socket` or `python‑nmap`, parse log files, or interact with the pfSense API.  Use libraries such as `requests` to call external services like VirusTotal and AbuseIPDB.

- **Bash and PowerShell fundamentals**: Learn to write shell scripts that collect system information, enumerate running processes, monitor open ports or parse logs.  On Windows, write PowerShell scripts to fetch event logs and detect anomalies.  Use these scripts in conjunction with Cron or Task Scheduler to automate routine tasks.

- **Security linters and tests**: Run `ruff`, `mypy` and `pytest` on your Python code to enforce style and type safety.  Use `bandit` to scan for insecure coding patterns and `pip‑audit` to check dependencies for known vulnerabilities.  Configure `pre‑commit` to run these checks before each Git commit.

- **Build enrichment and detection scripts**: Write Python programs to process Suricata EVE logs or Wazuh alerts, enrich them with threat‑intelligence lookups, and post high‑severity findings into The Hive.  Experiment with simple machine‑learning techniques (e.g., isolation forests or clustering) to spot anomalous network traffic or system behaviour.

- **Version control and collaboration**: Use Git branches and meaningful commit messages to manage your scripts.  Collaborate via pull requests and code reviews if you work with others.  Set up Slack or Jira integrations so your pipeline can notify you of linting errors, failed tests or security violations.

By the end of Phase 1b you will have a solid grasp of the tools and scripting languages needed for cyber‑security work, with Python skills that underpin automation and analysis across the rest of the program.

## Phase 2 – Network & Web Security

Phase 2 focuses on network defence, web application security and vulnerability assessment.  You will tune your Suricata rules, build dashboards in Kibana, perform vulnerability scans with Nmap, OpenVAS and Nessus, and practise web application hacking on deliberately vulnerable systems.  You’ll learn about OWASP Top 10 vulnerabilities, TLS configuration, network segmentation and firewall hardening.  Detailed instructions live in the `phase2/` folder.

## Phase 3 – Secure Coding, DevSecOps & Automation

Phase 3 introduces secure development practices and embeds security into the software‑delivery pipeline.  You’ll implement CI/CD workflows with Jenkins or GitHub Actions, write Dockerfiles and Kubernetes manifests, integrate static and dynamic code scanners (SonarQube, ZAP), and use Terraform and Ansible to manage infrastructure as code.  The `phase3/` folder contains the labs.

## Phase 4 – Threat Detection & Incident Response

In Phase 4 you build and tune detection content, practise threat hunting and develop incident‑response workflows.  You’ll use the ELK stack and Wazuh to create Sigma and YARA rules, write threat‑hunting queries, automate alert triage via The Hive, and perform forensic analysis using tools like Volatility and Autopsy.  See `phase4/` for details.

## Phase 5 – Offensive Security & Vulnerability Management

Phase 5 teaches ethical hacking and vulnerability management.  You’ll learn the penetration‑testing methodology, use Metasploit and Burp Suite, practise password cracking with John the Ripper, and integrate Nessus/Qualys scans into your CI pipeline.  You’ll also learn how to prioritize vulnerabilities and develop remediation plans.  Labs reside in `phase5/`.

## Phase 6 – Advanced Topics & Specialization

The final phase explores advanced domains such as cloud‑security architectures, zero‑trust implementation, AI/ML security, malware analysis, industrial control systems and IoT.  You’ll deploy workloads in AWS or Azure, implement least‑privilege roles, experiment with adversarial machine‑learning models and analyse malicious code using Ghidra or IDA Free.  Choose the specializations that interest you most.

---

For detailed lab instructions, sample code, and runbooks, see the subdirectories under each phase.  Contributions and improvements are welcome—please open issues or pull requests if you have suggestions or find any problems.
