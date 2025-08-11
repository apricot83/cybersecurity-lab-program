# Phase 3 – Secure Coding, DevSecOps & Automation

In Phase 3 you integrate security into software development and infrastructure delivery.  You will learn secure coding practices, build CI/CD pipelines that include security gates, and automate infrastructure with code.  This phase reflects the demand for DevSecOps skills and prepares you to deploy reliable services securely.

## 1. Secure Coding Principles

* **Input validation and output encoding.**  Always validate and sanitise user input on both client and server.  Use parameterised queries to prevent SQL injection and encode output to prevent XSS.  Refer to the OWASP injection and output encoding cheat sheets.
* **Authentication and authorization.**  Implement strong password storage (bcrypt/Argon2), multi‑factor authentication, and least‑privilege access control.  Study the OWASP Access Control and Session Management cheat sheets.
* **Cryptography basics.**  Use industry‑standard libraries for encryption, hashing and digital signatures.  Understand the difference between symmetric and asymmetric encryption.  Avoid writing your own crypto routines.

## 2. Continuous Integration and Continuous Deployment

* **Build a CI/CD pipeline.**  Use Jenkins or GitHub Actions to automate building, testing and deploying code.  Create a `Jenkinsfile` with stages for linting (`ruff`), unit testing (`pytest`), static code analysis (`bandit`), dependency scanning (`pip‑audit`), and infrastructure‑as‑code scanning (`checkov`).
* **Security gates.**  Configure the pipeline to fail when high‑severity issues are detected.  Post results to Slack or create Jira tickets for remediation.  Include dynamic testing with OWASP ZAP for web services and Trivy for container images.
* **IaC scanning.**  Use Checkov to evaluate Terraform and Ansible files against best practices and compliance baselines.  The tool supports multiple cloud providers and includes built‑in policies.  Include Checkov in your pre‑commit hooks and CI runs.

## 3. Containerisation and Orchestration

* **Docker fundamentals.**  Write Dockerfiles that follow least‑privilege principles (non‑root user, minimal base image).  Use multi‑stage builds to reduce image size.  Scan images with Trivy and adopt the CIS Docker benchmark.
* **Kubernetes basics.**  Learn about pods, deployments, services and ingress.  Deploy a simple application using Minikube or Kind.  Apply network policies to limit traffic between pods and enable role‑based access control (RBAC).
* **Container security cheat sheets.**  Consult OWASP’s Docker and Kubernetes security cheat sheets for guidance on secure configuration.

## 4. Infrastructure as Code & Automation

* **Terraform modules.**  Create reusable modules for network and compute resources on AWS or Azure.  Apply infrastructure‑as‑code security best practices to avoid common misconfigurations.  Store state securely in Terraform Cloud or an encrypted S3 bucket.
* **Ansible playbooks.**  Write playbooks for installing and configuring Suricata, Wazuh, ELK, and other services.  Use roles to structure your configuration.  Include `ansible‑lint` in your CI pipeline.
* **Secrets management.**  Use Vault or AWS Secrets Manager to store credentials.  Inject secrets into your playbooks and Terraform modules securely rather than hard‑coding them.

## 5. Secure Development Labs

1. **Refactor your vulnerable web app.**  Take the application you attacked in Phase 2 and fix the issues.  Add input validation, parameterised queries and security headers.  Write unit tests to verify the fixes and integrate them into your pipeline.
2. **Build and deploy a microservice.**  Write a small API using Flask or Node.js, containerise it with Docker, and deploy it to Kubernetes.  Include SAST, DAST and container scanning in the CI/CD pipeline.
3. **Automate infrastructure deployment.**  Use Terraform to create a VPC and an EC2 instance; provision Suricata using Ansible.  Run Checkov to ensure compliance before provisioning.  Capture `terraform plan` and `apply` outputs in `/docs/phase3/iac/`.

## 6. Documentation and Lessons Learned

Record your experiments in `/docs/phase3/`.  Include code snippets, pipeline logs, and screenshots of your CI jobs.  Reflect on how integrating security into development changes the way you code and deploy applications.  By completing Phase 3 you will be ready to build and secure scalable services with confidence.
