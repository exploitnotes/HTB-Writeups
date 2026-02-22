# 🟡 HackTheBox: Medium Tier Writeups

This directory serves as a collection of writeups for **Medium-difficulty** machines on HackTheBox. These machines are chosen to build and reinforce foundational penetration testing skills, focusing on thorough enumeration and understanding common service vulnerabilities.

---

## 🛠️ Typical Methodology

For most machines in this category, I follow a standard workflow:

1. **Service Enumeration:** Identifying running services and version detection via `nmap`.
2. **Web Analysis:** Checking for common CMS vulnerabilities , directory brute-forcing, and source code review.
3. **Exploitation:** Leveraging public CVEs or misconfigured services to gain initial access.
4. **Privilege Escalation:** Performing local enumeration to find SUID binaries, cron jobs, or PATH hijacking opportunities.

---

## 📑 Machine Index

| Machine Name | OS | Main Vulnerability | Difficulty (User/Root) | Link |
| :--- | :--- | :--- | :--- | :--- |
| **Pterodactyl** | Linux | CVE-2025-6018/16019 (RCE) |  🟡/ 🟡 | [Walkthrough](./pterodactyl/README.md) |
| **Interpreter**| Linux | CVE-2023-43208 (Mirth Connect RCE) + Eval Injection (PrivEsc) | 🟡 / 🟡 | [Walkthrough](./interpreter/README.md) |

---

## 📚 Common Tools Used

* **Scanning:** `nmap`, `rustscan`.
* **Web:** `gobuster`, `feroxbuster`, `burpsuite`.
* **PrivEsc:** `linpeas.sh`, `pspy`, `ndsudo`.

---

[⬅️ Back to Main Portfolio](../README.md)