# Incident Response Triage Cheat Sheet

This document summarises common triage commands for Linux and Windows systems.  Use it as a quick reference when investigating an alert or suspected compromise.  Many of these commands are drawn from the incident‑response cheat sheet you uploaded and adapted for our lab environment.

## 1. Linux Triage

| Category | Purpose | Commands |
|---|---|---|
| **User accounts** | Identify suspicious users, SUID/SGID binaries and recent logins. | `cat /etc/passwd` – list all user accounts;<br>`passwd -S <user>` – show password status for a user;<br>`grep :0: /etc/passwd` – list UID 0 (root) accounts;<br>`find / -nouser -print` – find files owned by nonexistent users;<br>`lastlog` – view last login times for all users. |
| **Groups & privileges** | Inspect group membership and sudo privileges. | `cat /etc/group` – view group definitions;<br>`cat /etc/sudoers` – view sudoers configuration (use `visudo` to edit safely);<br>`id <user>` – show a user’s groups and privileges. |
| **Log files** | Review authentication and command history logs. | `tail /var/log/auth.log` – view recent authentication events;<br>`history | less` – review shell command history;<br>`journalctl` – query systemd logs for specific services. |
| **Processes** | Identify running processes and resource usage. | `top` or `htop` – interactive process viewer;<br>`ps aux` – list all processes with owners;<br>`lsof -p <pid>` – list files opened by a process;<br>`ss -tulpan` – show listening ports and associated processes. |
| **Services & cron jobs** | Examine system and network services. | `service --status-all` – list service statuses;<br>`systemctl list-units --type=service` – list active services;<br>`cat /etc/crontab` and `ls /etc/cron.*` – review scheduled tasks. |
| **File system & disk** | Look for large or recently modified files and mounts. | `find / -type f -size +100M` – find files larger than 100 MB;<br>`ls -lh /var/www/html` – inspect web‑server directories;<br>`cat /proc/mounts` – list mounted file systems. |
| **Memory & system state** | Check uptime and memory usage. | `uptime` – show system uptime and load averages;<br>`free -h` – display memory usage;<br>`cat /proc/meminfo` – detailed memory info. |
| **Network** | Review network configuration and connections. | `ip addr` or `ifconfig` – display interfaces and IP addresses;<br>`ss -tulwn` – list listening ports;<br>`arp -a` – view ARP table;<br>`iptables -L -n -v` – show firewall rules. |

## 2. Windows Triage

| Category | Purpose | Commands |
|---|---|---|
| **User accounts** | View local users and group memberships. | `net user` – list local accounts;<br>`net user <username>` – view account details;<br>`net localgroup administrators` – list local administrators. |
| **Processes & services** | Identify running processes and services. | `tasklist /v` – detailed process list;<br>`Get-Process` – PowerShell process listing;<br>`Get-Service` – PowerShell service status;<br>`sc query` – query service state. |
| **Log files** | Review event logs and command history. | **PowerShell:** `Get-WinEvent -LogName Security -MaxEvents 50` – view recent security events;<br>`wevtutil qe System /f:text /c:50` – query system log;<br>`type C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` – view PowerShell history. |
| **Scheduled tasks** | Check scheduled tasks and startup programs. | `schtasks /query /fo LIST /v` – list scheduled tasks with details;<br>`Get-ScheduledTask` – PowerShell equivalent;<br>`wmic startup list full` – list startup programs. |
| **Network** | Examine network configuration and connections. | `ipconfig /all` – display IP configuration;<br>`netstat -ano` – list active connections and listening ports with PIDs;<br>`arp -a` – view ARP table;<br>`route print` – display routing table. |
| **System information** | Gather host details. | `systeminfo` – OS version, installed patches, BIOS info;<br>`wmic os get caption,version,buildnumber` – quick OS check. |

## 3. Usage Guidelines

1. **Do not make changes on the system during triage** unless necessary to prevent further damage.  Collect data first.
2. **Automate repetitive collection.**  Use Bash or PowerShell scripts to run these commands and save output to timestamped files (e.g., `/tmp/incident_<hostname>_<timestamp>.txt`).
3. **Centralise evidence.**  Copy logs and command outputs to your ELK stack or The Hive case for correlation and analysis.  Use secure transfer (e.g., SCP over your management network).
4. **Document everything.**  Record the time you ran each command, the results, and any anomalies.  Update your incident report in Jira or The Hive.

This cheat sheet provides a starting point for triage.  Adapt it to your environment by adding or removing commands, and always follow your organisation’s incident‑response policy.
