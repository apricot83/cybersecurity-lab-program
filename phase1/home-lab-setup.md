# Phase 1 – Home Lab and Scripting Fundamentals

Phase 1 lays the foundation for your cybersecurity journey by helping you build a complete home‑lab environment from the ground up.  Instead of relying on pre‑built training platforms, you will create and manage your own network, servers, and tools.  This approach gives you full control, teaches you how these systems really work, and prepares you for real‑world security work.

## What You Will Achieve

* **Understand the big picture.**  You’ll design a small network with separate segments for management, internal systems, and internet‑facing services.  A pfSense firewall or router sits at the centre, controlling traffic between these zones and the outside world.

* **Build multiple virtual machines.**  You’ll deploy several VMs on your host computer: an Ubuntu server for Docker containers and CI/CD tools, a separate Ubuntu server or sensor for Suricata, a Wazuh manager for host‑based intrusion detection and file integrity monitoring, a Windows workstation with Sysmon for endpoint logging, and a Kali Linux attacker box.  Each VM has a specific role in the lab so you can learn both attack and defence.

* **Create the accounts you need.**  Set up free accounts on GitHub (for version control), Slack (for alerts and collaboration), Jira or another ticketing tool (for task and incident tracking), AWS and Azure free tiers (for later cloud experiments), VirusTotal and AbuseIPDB (for threat‑intelligence lookups), HashiCorp services such as Terraform Cloud (for infrastructure‑as‑code), Tenable Nessus (for vulnerability scanning) and Jenkins (for continuous integration).  If a service requires an API key, store it in an `.env` file on your local machine and add it to your GitHub repository’s secrets rather than committing it directly.

* **Install essential tools on your host.**  Use Homebrew on macOS or package managers on Linux/Windows to install Python 3.12, Git, Docker/Colima or Docker Desktop, VirtualBox or VMware, Wireshark, and Visual Studio Code.  For Python development, set up `pipx` and `poetry` so you can manage scripts cleanly.  Linting and security tools such as `ruff`, `mypy`, `pytest`, `bandit`, and `pip-audit` will help keep your code safe and maintainable.  Enable `pre-commit` hooks in your repository so these checks run automatically before each commit.

* **Deploy core security services.**  You’ll run the ELK Stack (Elasticsearch, Logstash, Kibana) via Docker Compose to collect and visualise logs.  Suricata will provide network‑based intrusion detection; you will tune its rules and export alerts in JSON format.  Wazuh will collect host logs from Linux and Windows systems, monitor file integrity, and perform configuration audits.  YARA rules will allow you to detect suspicious files or binaries.  Later, you can integrate MISP (Malware Information Sharing Platform) for threat‑intelligence sharing and The Hive/Cortex for case management and automated analysis.

* **Automate with infrastructure as code.**  Use Terraform to define cloud resources such as VPCs or subnets, and use Ansible to configure your VMs and install packages.  To ensure you’re following best practices, scan your infrastructure code with Checkov and other static analysis tools as part of your CI/CD pipeline (for example, using Jenkins or GitHub Actions).  These pipelines should also run Python linters, security scanners, and tests before deploying any changes.

* **Lay the groundwork for threat detection and incident response.**  Collect logs from your Windows and Linux machines using Winlogbeat or Filebeat, send Suricata and Wazuh events into ELK, and build dashboards in Kibana so you can spot unusual activity.  Write simple Python scripts to parse logs, enrich indicators with VirusTotal or AbuseIPDB, and generate alerts.  By the end of Phase 1 you will have a functioning SOC‑style environment ready for deeper detection‑engineering work in later phases.

## 1. Accounts and Prerequisites

Before you start building, create the accounts listed below.  They’re mostly free and will support various parts of your lab:

| Service        | Purpose                                   |
|---------------|--------------------------------------------|
| **GitHub**    | Store your code, documentation, and CI pipelines.  Use private repositories for sensitive material. |
| **Slack**     | Receive alerts from your pipelines and monitoring tools; collaborate with others if you work as a team. |
| **Jira** or another ticketing system | Track tasks and incident response actions. |
| **AWS/Azure** | Provision cloud resources (VPCs, subnets, virtual machines) when you expand beyond your local lab.  Free tiers are sufficient. |
| **VirusTotal & AbuseIPDB** | Look up file and IP reputation when investigating alerts. |
| **HashiCorp (Terraform Cloud or Vault)** | Optional: store your Terraform state and secrets securely. |
| **Tenable Nessus** | Perform vulnerability scans of your internal network.  Use the Nessus Essentials or trial license. |
| **Jenkins**   | Host your CI/CD pipelines.  You can also use GitHub Actions if you prefer. |

## 2. Preparing Your Host Machine

1. **Install a package manager.**  On macOS, run the Homebrew installation script from the official site.  On Linux, ensure `apt`, `dnf`, or your distribution’s package manager is up to date.  On Windows, install Chocolatey or Winget to manage packages.

2. **Set up development tools.**  Install Python 3.12 and set up `pipx` and `poetry` so you can install command‑line tools and manage project dependencies.  Install Git, a good text editor (VS Code), and Wireshark.  Use your package manager to install Docker/Colima (or Docker Desktop) and VirtualBox or VMware for virtualization.

3. **Configure security tooling.**  Use `pipx` to install Python linters and security checkers such as `ruff`, `mypy`, `pytest`, `bandit`, `pip-audit`, and `pre-commit`.  Run `pre-commit install` inside your repository so these tools check your code automatically when you commit changes.

4. **Prepare your workspace.**  Create a directory structure similar to the one in your GitHub repository (`/docs`, `/ansible`, `/iac/terraform`, `/jenkins`, `/suricata`, `/detections`, `/wazuh`, `/scripts`).  Place your `.env` file with API keys in a safe location outside version control.

## 3. Designing the Virtual Network

Use VirtualBox or VMware to create three virtual networks:

* **Management network (host‑only).**  This network lets your host operating system communicate with the virtual machines without exposing them to the internet.  Assign it a range such as `192.168.56.0/24`.

* **Internal network.**  This network connects your servers and workstations together (for example, `10.10.0.0/24`).  It has no direct internet access; traffic flows through your pfSense router.

* **NAT or DMZ network.**  Use this network to provide controlled internet access for updates and package downloads.  pfSense will handle NAT between this network and the outside world.

Deploy a pfSense virtual machine with three network interfaces attached to these networks.  Configure basic firewall rules so that management traffic is allowed only from your host, internal traffic is routed appropriately, and any internet‑bound traffic is inspected.

## 4. Building and Configuring Virtual Machines

* **Ubuntu Docker Host.**  Install a minimal Ubuntu Server on your first VM.  This host will run Docker and Docker Compose, hosting the ELK stack, Wazuh (if you choose the containerised version), and other services such as MISP and The Hive.  Install Docker using the official convenience script or your package manager and add your user to the `docker` group.  Test your setup by running `docker run hello-world`.

* **CI/CD and IaC Server.**  Use another Ubuntu VM for Jenkins (or simply run Jenkins in a container on the Docker host) and install Terraform and Ansible.  This machine will hold your pipeline definitions (`Jenkinsfile`) and run Checkov, Bandit, and other scans on your code.

* **Suricata Sensor.**  Create a dedicated VM or container to run Suricata.  Install the latest stable version from the official OISF PPA on Ubuntu, or use the Docker image.  Configure its `HOME_NET` to your internal network range and enable JSON logging (EVE format).  If you want to simulate inline monitoring, you can add two network interfaces and bridge them.

* **Wazuh Manager.**  Install Wazuh either on a standalone VM or as part of a Docker stack.  Follow the documentation to install the manager and register agents.  You will install agents on your Ubuntu and Windows hosts later to collect system logs and monitor file integrity.

* **Windows Workstation.**  Create a Windows 10 or Windows 11 VM to act as a user endpoint.  Install Sysmon with a reputable configuration (such as the ones provided by SwiftOnSecurity or Olaf Hartong) to generate detailed event logs.  Install Winlogbeat to forward logs to your ELK stack and the Wazuh agent for host‑based monitoring.

* **Kali Linux.**  Deploy a Kali VM to act as your attacker machine.  Keep its toolset lean: Nmap, Metasploit, YARA, and a few web testing tools.  You will use this system to scan your network and test your detection rules.  Always document your attack steps and the corresponding alerts generated in your SIEM.

## 5. Deploying Security Monitoring and Detection

1. **ELK Stack.**  Use a `docker-compose.yml` file to run Elasticsearch, Logstash, and Kibana.  Disable X‑Pack security features for simplicity in the lab.  Expose Kibana on port 5601 and Elasticsearch on port 9200.  Build dashboards to visualise Suricata, Wazuh, Sysmon, and other logs.

2. **Suricata.**  Enable community rules (Emerging Threats) and create your own rules in a `local.rules` file.  For example, you might write a rule to alert on ICMP traffic between hosts or suspicious HTTP headers.  Ensure JSON output is enabled and configure Filebeat or Logstash to ingest `eve.json` into Elasticsearch.

3. **Wazuh.**  Register your Linux and Windows machines as agents.  Enable file integrity monitoring to detect changes in important directories, and enable command‑execution monitoring.  Use the Wazuh API to query alerts or forward them to Slack or Jira when high‑severity events occur.  If you plan to integrate Wazuh with The Hive, configure a webhook to convert critical alerts into cases.

4. **YARA.**  Write simple YARA rules to detect suspicious files (for example, files with packed characteristics or known malicious strings).  Run YARA scans on your Kali VM or as part of an automated script and send matches to your SIEM.

5. **Threat Intelligence and Case Management.**  Install MISP on your Docker host to share and consume Indicators of Compromise (IOCs).  Deploy The Hive and Cortex (via their official Docker images) and integrate them with MISP for automated enrichment.  When Suricata or Wazuh generate a high‑priority alert, a small Python script can create a case in The Hive, pull in MISP data, and assign tasks to you for investigation.

## 6. Infrastructure as Code and Continuous Integration

* **Terraform Projects.**  In your `/iac/terraform` folder, create small Terraform modules, such as a VPC with public and private subnets, or a simple EC2 instance in AWS.  Initialise and plan these modules locally first, then run `terraform apply` from Jenkins or GitHub Actions once you’re confident.  Save your Terraform state securely in Terraform Cloud or an S3 bucket with versioning enabled.

* **Ansible Playbooks.**  Use the `/ansible` directory to store your inventory and playbooks.  Write roles to install packages (Docker, Suricata, Wazuh) and to configure services.  Running `ansible-playbook` ensures that your VMs can be rebuilt consistently.

* **CI/CD Pipelines.**  Create a `Jenkinsfile` or GitHub Actions workflow that runs on every push.  It should execute linting (`ruff`, `mypy`), security scanning (`bandit`, `pip-audit`), infrastructure scanning (`checkov`), and unit tests (`pytest`).  Upon success, it can run `terraform plan`.  Configure Slack or Jira notifications so you’re alerted to failures or policy violations.

## 7. Documentation and Version Control

Treat your lab like a professional project.  Keep detailed notes in Markdown files under the `/docs` directory.  For each experiment, record the goal, the steps you took, any code you wrote, screenshots of the outcome, and what you learned.  Use meaningful commit messages and branch names (for example, `feature/suricata-setup`).  Protect the `main` branch by requiring reviews or checks before merges.

## 8. Moving Forward

By the end of Phase 1 you’ll have a working home lab with firewalls, servers, sensors, a SIEM, and a CI/CD pipeline.  You’ll also have developed solid scripting habits, set up version control and collaboration tools, and started collecting logs and alerts.  In Phase 2 you’ll focus on network and web security, exploring web vulnerabilities, inspecting traffic with Suricata and Wireshark, and improving your detection rules.  Keep iterating on your lab – upgrade your services, add new detection content, and document everything so you can demonstrate your skills during interviews.