# 🔴 HackTheBox: Hard Tier Writeups

This directory contains writeups for **Hard-difficulty** machines on Hack The Box.  
These machines focus on **advanced attack chains**, deeper enumeration, and complex privilege escalation techniques, often involving **Active Directory exploitation, service abuse, and multi‑stage compromise paths**.

---

## Typical Methodology

Hard machines usually require chaining multiple vulnerabilities together. My workflow generally includes:

1. **Deep Enumeration:** Comprehensive service discovery using `nmap`, `rustscan`, and manual probing.
2. **Internal Reconnaissance:** Enumerating internal services, credentials, and domain information after initial access.
3. **Credential Attacks:** Techniques such as **Kerberoasting**, password spraying, or abusing service accounts.
4. **Lateral Movement:** Pivoting through the network using tunneling tools or compromised credentials.
5. **Privilege Escalation:** Exploiting **Active Directory misconfigurations**, delegation abuse, or privilege mismanagement to obtain Domain Admin or root access.

---

## Machine Index

| Machine Name | OS | Main Vulnerability | Difficulty (User/Root) | Link |
| :--- | :--- | :--- | :--- | :--- |
| **Pirate** | Windows | gMSA Enumeration, Kerberoasting, AD Privilege Escalation | 🔴 / 🔴 | [Walkthrough](./Pirate/README.md) |
| **Snapped** | Linux | CVE-2026-27944, Credential Cracking, CVE-2026-3888 snapd LPE | 🔴 / 🔴 | [Walkthrough](./Snapped/README.md) |
| **Fries** | Mar 2026 | Enumeration, Credential Abuse, Container Pivoting, Active Directory Exploitation, AD CS Attacks | 🔴 / 🔴 | [Walkthrough](./Fries/README.md) |
| **DarkZero** | Apr 2026 | MSSQL Abuse, Linked Server Pivoting, Privilege Escalation, Kerberos Abuse (DC01$ TGT), DCSync, Pass-the-Hash | 🔴 / 🔴 | [Walkthrough](./DarkZero/README.md) |
---

## Common Tools Used

* **Scanning:** `nmap`, `rustscan`
* **Active Directory:** `bloodhound`, `impacket`, `crackmapexec`
* **Credential Attacks:** `hashcat`, `john`
* **Pivoting:** `chisel`, `ssh tunneling`
* **Enumeration:** `linpeas`, `winpeas`, `pspy`

---

[ Back to Main Portfolio](../README.md)