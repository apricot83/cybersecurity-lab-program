# Phase 1 – Lab Setup

This document provides step-by‑step instructions for setting up your home lab for **Phase 1 – Foundations & Scripting** of the cybersecurity learning program.  The goal is to create a safe, isolated environment where you can experiment with networking, operating systems and scripting without affecting your main machine.

## Objectives

- Build a virtualization environment using open‑source or free virtualization software (VirtualBox, VMware Workstation Player or Hyper‑V).
- Deploy at least two virtual machines: a Linux system (Kali or Ubuntu) and a Windows system.
- Configure network segmentation (host‑only or NAT) to allow communication between VMs while isolating them from your home network.
- Install common security tools (Wireshark, Nmap, etc.) and update the systems.
- Create accounts on online learning platforms (e.g., TryHackMe, HackTheBox, OverTheWire, CyberRange) for later exercises.
- Document each step and any issues you encounter so you can reference them during interviews.

## Prerequisites

- **Hardware**: Ideally 16 GB of RAM and at least 256 GB of storage, as recommended for home labs【682014248771950†L161-L190】.
- **Internet connection**: To download virtual machine images and access training platforms.
- **GitHub account**: You are already using this to host the repository.

## Steps

1. **Choose virtualization software**

   - Install [VirtualBox](https://www.virtualbox.org/), **VMware Workstation Player**, or enable **Hyper‑V** if you are on Windows 10/11 Pro.  All three are suitable for running multiple VMs.

2. **Download operating system images**

   - **Kali Linux** ISO (contains many penetration testing tools) or **Ubuntu Server/Desktop** for general Linux use.
   - **Windows 10/11** evaluation ISO from Microsoft (for educational purposes).

3. **Create virtual machines**

   - Configure a **host‑only** or **NAT** network adapter so that VMs can communicate with each other but are isolated from your main network.  You may also set up a separate VLAN if your router supports it, as suggested for safe experimentation【682014248771950†L161-L190】.
   - Assign at least 2 GB RAM to the Linux VM and 4 GB RAM to the Windows VM, adjusting based on your hardware.
   - Install the OSes, create standard user accounts, and enable automatic updates.

4. **Install security tools**

   - On **Linux**: update the package list (`sudo apt update && sudo apt upgrade`), then install tools like **Wireshark**, **Nmap**, **tcpdump**, and **OpenSSH server**.
   - On **Windows**: install **Wireshark**, and enable Windows Subsystem for Linux (WSL) if you want to practise Linux commands.  Install **PowerShell** 7 for more advanced scripting.

5. **Initial networking project**

   - Use **Wireshark** to capture traffic between the Linux and Windows VMs.  Try pinging each VM from the other and observe the ICMP packets.  Document the source/destination addresses and the protocol details.
   - Use **Nmap** to scan the ports of the other VM (`nmap -sV <target_IP>`).  Note what services are running and whether they have default configurations.

6. **Create accounts on training platforms**

   - **TryHackMe** – sign up at [tryhackme.com](https://tryhackme.com/) to access beginner‑friendly rooms and guided labs.
   - **HackTheBox** – create a free account at [hackthebox.com](https://hackthebox.com/).  Start with the "Starting Point" series.
   - **OverTheWire** – access via [overthewire.org](https://overthewire.org/) for wargames such as Bandit (no account required, but you can track progress).  
   - **CyberRange platforms** (optional) like **Root Me**, **CyberDefenders**, or vendor‑specific ranges.  Use your personal email to register; do **not** share personal credentials in this repository.

7. **Document your work**

   - Keep a lab journal in this repository.  You can create markdown files (e.g., `phase1/lab-notes.md`) to record setup procedures, commands, and observations.
   - Commit your notes frequently.  Use concise commit messages summarizing what you did.

## Next Steps

After completing your lab setup, proceed to the **Foundations and Scripting** exercises outlined in the program README.  Begin learning Linux and Windows command‑line basics, then move on to scripting with Python and PowerShell.  Use your lab environment to practise these skills and continue documenting everything you do.
