# 🟢 HackTheBox: Easy Tier Writeups

This directory serves as a collection of writeups for **Easy-difficulty** machines on HackTheBox. These machines are chosen to build and reinforce foundational penetration testing skills, focusing on thorough enumeration and understanding common service vulnerabilities.

---

## 🛠️ Typical Methodology

For most machines in this category, I follow a standard workflow:

1. **Service Enumeration:** Identifying running services and version detection via `nmap`.
2. **Web Analysis:** Checking for common CMS vulnerabilities (like XWiki), directory brute-forcing, and source code review.
3. **Exploitation:** Leveraging public CVEs or misconfigured services to gain initial access.
4. **Privilege Escalation:** Performing local enumeration to find SUID binaries, cron jobs, or PATH hijacking opportunities.

---

## 📑 Machine Index

| Machine Name | OS | Main Vulnerability | Difficulty (User/Root) | Link |
| :--- | :--- | :--- | :--- | :--- |
| **Editor** | Linux | CVE-2025-24893 (RCE) | 🟢 / 🟢 | [Walkthrough](./Editor/README.md) |
| **Expressway** | Linux | IKE Agressive mode/ Custom SUID Binary | 🟢 / 🟢 | [Walkthrough](./Expressway/README.md) |
| **MonitorsFour** | Linux | CVE-2025-24367(RCE)/ Exposed Docker Remote API (Unauthenticated) | 🟢 / 🟢 | [Walkthrough](./MonitorsFour/README.md) |
| **Facts** | Linux | Information Disclosure + Misconfiguration | 🟢 / 🟢 | [Walkthrough](./Facts/README.md) |
| **WingData** | Linux | Web Application Vulnerability (Auth/Injection) | 🟢 / 🟢 | [Walkthrough](./Wingdata/README.md) |

---

## 📚 Common Tools Used

* **Scanning:** `nmap`, `rustscan`.
* **Web:** `gobuster`, `feroxbuster`, `burpsuite`.
* **PrivEsc:** `linpeas.sh`, `pspy`, `ndsudo`.

---

[⬅️ Back to Main Portfolio](../README.md)