# Phase 1 – Home Lab Setup

This document provides detailed instructions for building your own full-stack cybersecurity home lab. Instead of relying on external platforms, you will create an entire environment from scratch – including accounts, infrastructure, and tools – so that you can safely practice detection engineering, DevSecOps, incident response, and offensive testing.

## Objectives
- Build a virtualized lab network with isolated segments for management, internal, and internet-connected zones.
- Provision multiple virtual machines: a pfSense firewall/router, Linux servers for Docker and CI/CD, an IDS sensor, a Windows workstation, and a Kali Linux attacker box.
- Create and configure accounts for collaboration (GitHub, Slack, Jira), cloud labs (AWS, Azure), threat intelligence (VirusTotal, AbuseIPDB), and tooling (HashiCorp Terraform Cloud, Nessus Essentials, Jenkins, VS Code).
- Install core host tools such as Python 3.12, Git, poetry, pre-commit, ruff, mypy, pytest, bandit, pip-audit, VS Code, Wireshark and virtualization software.
- Deploy open-source detection technologies including Suricata for network monitoring【591465785898967†L97-L101】, YARA for file content analysis【591465785898967†L104-L105】, Elastic Stack and Wazuh as a SIEM【591465785898967†L109-L112】, and integrate them with your lab.
- Use infrastructure-as-code (Terraform and Ansible) and CI/CD pipelines (Jenkins or GitHub Actions) to automate provisioning and security scanning. Leverage Checkov to scan Terraform, Dockerfiles, Kubernetes manifests and other IaC for misconfigurations【111891855746703†L29-L50】【111891855746703†L90-L97】.
- Learn DevSecOps principles by building pipelines that enforce security controls early in the development lifecycle【756675528211391†L2-L9】【756675528211391†L62-L90】.
- Document every step and commit your work into this GitHub repository.

## Accounts to Create

Create the following free-tier or community accounts before you start. Use unique passwords and enable multi-factor authentication.

| Service | Purpose |
| --- | --- |
| **GitHub** | Host your code, lab notes, Terraform modules and pipelines |
| **Slack** | Receive CI/CD notifications and collaborate during incident simulations |
| **Jira (Atlassian)** | Track tasks, create incident tickets and manage agile sprints |
| **AWS Free Tier** | Build cloud infrastructure with Terraform; explore AWS services |
| **Azure Free Tier** | Alternative cloud environment for hybrid scenarios |
| **HashiCorp Terraform Cloud** | Store remote state and run automated plans; integrate with Checkov |
| **VirusTotal (VT)** | Enrich indicators of compromise and scan suspicious files |
| **AbuseIPDB** | Check IP reputation to filter malicious traffic |
| **Tenable Nessus Essentials** | Perform authenticated and unauthenticated vulnerability scans |
| **Jenkins** | Self-hosted CI/CD platform; will run your pipelines |
| **VS Code Account** | Synchronize settings and use extensions (Python, Terraform, Ansible) |
| **Docker Hub** | Pull and store container images; optional private registry |

> Keep API keys (VirusTotal, AbuseIPDB, Slack webhooks, etc.) in a `.env` file that is ignored by Git. Use GitHub Secrets or Jenkins credentials store to inject them into pipelines.

## Host Setup (macOS/Linux)

Perform these steps on your host machine (a Mac with virtualization support or a Linux PC) to prepare for the lab.

1. **Install Homebrew (macOS)**:  
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. **Install core command-line and development tools**:  
   ```bash
   brew install python@3.12 pyenv pipx git jq wget gnupg
   brew install --cask visual-studio-code wireshark virtualbox      # or VMware Workstation Player
   brew install docker colima                                       # or Docker Desktop
   ```

3. **Install Python tooling with pipx** (works on Linux with pipx as well):  
   ```bash
   pipx ensurepath
   pipx install poetry pre-commit pip-audit bandit ruff mypy pytest checkov
   ```

4. **Configure VS Code**: install extensions for Python, Terraform, Ansible, Docker, YAML, and GitLens. Enable autosave and configure Prettier/Black.

5. **Virtualization software**: use VirtualBox (free) or VMware Workstation Player. Enable virtualization in BIOS/EFI and allocate at least 16 GB RAM and 200 GB storage to your lab.

6. **Networking**: create three networks in VirtualBox:
   - `Host-only` (e.g., `vboxnet0`) for management – your host and VMs can communicate.
   - `NAT` network to provide internet access.
   - `Internal` network (`intnet`) with no external connectivity – used for isolated servers.

## Building the Lab Network

1. **pfSense firewall/router**:  
   - Download the pfSense ISO and create a VM with three NICs: `NAT` (WAN), `Host-only` (management), and `Internal` (LAN).  
   - Assign IP addresses (e.g., `192.168.56.1/24` on management; `10.10.0.1/24` on internal).  
   - Configure DHCP on internal, NAT rules, and firewall policies to restrict east–west traffic.

2. **Ubuntu Docker host (`ubuntu-docker`)**:  
   - Install Ubuntu Server LTS. Add two NICs: `Host-only` and `Internal`.  
   - Install Docker and Docker Compose. This VM will run the Elastic Stack (Elasticsearch, Logstash, Kibana) and optional Wazuh server via Docker Compose.  
   - Deploy an ELK stack using a `docker-compose.yml` file and verify Kibana is reachable.

3. **Ubuntu CI server (`ubuntu-ci`)**:  
   - Install Ubuntu Server. Add two NICs: `Host-only` and `Internal`.  
   - Install Jenkins, Terraform, Ansible, and necessary plugins.  
   - Set up Jenkins credentials for GitHub, AWS and Azure.  
   - Write a Jenkinsfile that runs `ruff`, `bandit`, `pip-audit`, `checkov` and `terraform plan`. Use Slack notifications and Jira ticket creation on failures.

4. **Suricata sensor (`suricata-sensor`)**:  
   - Install Ubuntu Server. Add one NIC on `Internal` (or two for inline deployment).  
   - Install Suricata and enable EVE JSON output; configure `HOME_NET` to your internal subnet.  
   - Forward EVE logs to Logstash or parse them in Kibana to build detection dashboards.  
   - Suricata uses detection rules to interrogate network traffic【591465785898967†L97-L101】; create a `local.rules` file for your own signatures.

5. **Wazuh manager (`wazuh-manager`)** (optional if not using Docker):  
   - Install Wazuh on a dedicated VM or container. Wazuh is an open‑source security monitoring platform for intrusion detection and log analysis【591465785898967†L109-L112】.  
   - Enroll agents on all VMs and your Windows workstation to collect logs and monitor file integrity.

6. **Windows 10/11 lab workstation (`win-lab`)**:  
   - Install Windows 10/11. Add two NICs: `Host-only` and `Internal`.  
   - Install Sysmon and configure a recommended Sysmon configuration to capture detailed events.  
   - Install Winlogbeat to forward Windows event logs to Elastic.  
   - Practice detection by executing benign and malicious behaviours and correlating them with Suricata and ELK.

7. **Kali Linux (`kali`)**:  
   - Install Kali Linux. Add a NIC on the `Internal` network.  
   - This VM will host offensive tools such as Nmap, Metasploit, John the Ripper, sqlmap and YARA; YARA rules help identify and classify malware samples【591465785898967†L104-L105】.

## Detection Engineering Tools

- **Network detection**: Suricata provides signature and anomaly-based detection of network traffic【591465785898967†L97-L101】. You will write and tune custom rules (`suricata/rules/local.rules`).
- **File content detection**: YARA lets you create signatures for files; integrate YARA scans on your Kali and Docker hosts【591465785898967†L104-L105】.
- **SIEM**: Elastic Stack (ELK) offers search, logging and analytics; Wazuh adds host intrusion detection, file integrity monitoring and rule-based alerting【591465785898967†L109-L112】.
- **Threat intelligence integration**: Use VirusTotal and AbuseIPDB APIs to enrich alerts with IP/domain reputation.

## Automation, IaC and DevSecOps

- Install Terraform and Ansible on your CI server. Use Terraform to define VPCs, EC2 instances, security groups and other resources in AWS or Azure. An example is given in the Prisma Cloud DevSecOps workshop, which demonstrates automating IaC security scanning with checkov and integrating with GitHub, VS Code and AWS【756675528211391†L2-L9】.
- Use Checkov to statically scan Terraform, Kubernetes, Helm, Dockerfile and other IaC configurations for misconfigurations and policy violations【111891855746703†L29-L50】. Checkov has over 1000 built‑in policies covering AWS, Azure and GCP, and can scan pipelines such as GitHub Actions and Jenkins【111891855746703†L90-L97】.
- Integrate scanning into your pipelines to “shift security left” — i.e., perform security checks early in the development lifecycle【756675528211391†L62-L90】. Pre-commit hooks can run bandit, pip-audit and checkov before code is committed.

## Documentation and Version Control

- Document each lab step, including commands run, configurations applied and screenshots, in Markdown files under the `docs/` directory of this repository.
- Use Git branches and pull requests to manage changes. Apply branch protection rules and require passing checkov and bandit scans before merges.
- Use Jira to track tasks and Slack to receive notifications from Jenkins or GitHub Actions.

## Next Steps

After completing this lab setup:

1. Commit your `.env.example` template and ensure sensitive keys are kept out of version control.
2. Start building detection rules (Sigma, Suricata and YARA) and store them in a `detections/` directory.
3. Expand your lab with cloud resources using Terraform and scan them with Checkov.
4. Explore adversary emulation tools such as Atomic Red Team and Caldera to generate realistic attack patterns and test your detections【591465785898967†L118-L129】.

## Additional Tools and Integrations

### Wazuh and Elastic SIEM
- **Wazuh** acts as a host intrusion detection and file integrity monitoring platform. Deploy a Wazuh manager (or use the Wazuh container) and install agents on Linux and Windows hosts to collect logs, detect anomalies, and monitor compliance. Ingest Wazuh alerts into the Elastic Stack so they appear alongside your Suricata network events.

### MISP – Malware Information Sharing Platform
- Deploy **MISP** on your Docker host or a separate VM to gather and share indicators of compromise (IOCs). MISP centralizes threat intelligence from open‑source feeds and your own lab findings. Configure MISP to synchronize with public communities and export feeds for Suricata and Elastic.
- Integrate MISP with Wazuh and Suricata by converting IOCs into detection rules. Connect MISP to The Hive to automatically enrich cases with context from threat feeds【261375728248962†L254-L270】.

### The Hive and Cortex Case Management
- Run **The Hive** and **Cortex** in Docker using the combined image. The Hive provides an incident‑response and case‑management platform that lets analysts track incidents, assign tasks, collaborate and standardize documentation【261375728248962†L254-L270】. Cortex offers analyzers to enrich observables with data from VirusTotal, AbuseIPDB, Shodan, DomainTools and other services【921292551552632†L50-L63】.
- Create case templates for common alerts (e.g., port scan, suspicious binary, brute‑force login) and automate case creation from Wazuh or Suricata alerts via The Hive’s REST API【921292551552632†L50-L63】.
- Connect The Hive to MISP to pull threat‑intelligence into cases, and to Slack or Jira for notifications and ticketing【261375728248962†L254-L270】.

### Importance of Python
- **Python** is central to this program. Use it to automate log parsing, build enrichment scripts that query VirusTotal or MISP, develop scripts to generate Sigma/YARA/Suricata rules from threat feeds, and prototype anomaly‑detection models. Python’s rich ecosystem lets you tie together your SIEM, SOAR and case‑management workflows, making it a critical skill for modern detection engineering.
