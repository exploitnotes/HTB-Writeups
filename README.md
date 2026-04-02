# HackTheBox Writeups

This repository is a technical journal of my Hack The Box penetration testing journey, documenting methodologies, tools, and concepts explored.  

---

## Repository Structure

The repository is organized to make navigation easier:

* **[Easy](./Easy/)** – Entry-level machines focusing on fundamental concepts.  
* **[Medium](./Medium/)** – Intermediate machines requiring multi-step exploitation.  
* **[Hard](./Hard/)** – Advanced machines with complex exploitation and deep enumeration.  
* **[Fortress](./Fortress/)** – Conceptual notes from Fortress machines (policy-safe, no full writeups).

---

## Completed Machines – Conceptual Notes

### 🟢 Easy
| Machine | Date | Focus | Notes |
| :--- | :--- | :--- | :--- |
| **Editor** | Jan 2026 | RCE, PATH Hijacking | [Walkthrough](./Easy/README.md) |
| **Expressway** | Jan 2026 | IKE Aggressive Mode, Custom SUID | [Walkthrough](./Easy/README.md) |
| **MonitorsFour** | Jan 2026 | RCE (CVE-2025-24367), Docker Remote API | [Walkthrough](./Easy/README.md) |
| **Facts** | Feb 2026 | Information Disclosure, Misconfiguration | [Walkthrough](./Easy/README.md) |
| **WingData** | Feb 2026 | Web App Vulnerabilities (Auth/Injection) | [Walkthrough](./Easy/README.md) |
| **CCTV** | Mar 2026 | Internal Recon, API Abuse | [Walkthrough](./Easy/README.md) |
| **Kobold** | Mar 2026 | JSON Injection, RCE (CVE-2026-23744), Docker Privilege Escalation, Container Escape | [Walkthrough](./Easy/README.md) |

### 🟡 Medium
| Machine | Date | Focus | Notes |
| :--- | :--- | :--- | :--- |
| **Pterodactyl** | Feb 2026 | RCE, PrivEsc (CVE-2025-6019/6018) | [Walkthrough](./Medium/README.md) |
| **AirTouch** | Feb 2026 | Credential Exposure, Network Pivot | [Walkthrough](./Medium/README.md) |
| **Interpreter** | Feb 2026 | RCE, Eval Injection | [Walkthrough](./Medium/README.md) |
| **VariaType** | Feb 2026 | LFI → FontTools → Command Injection → Sudo Path Traversal | [Walkthrough](./Medium/README.md) |
| **Principal** | Mar 2026 | JWT Auth Bypass, SSH CA Forgery | [Walkthrough](./Medium/README.md) |
| **DevArea** | Mar 2026 | FTP Enumeration → JAR Analysis → SSRF (Port 8888) → Credential Leak → Hoverfly RCE (CVE-2025-54123) → SSH Key Injection → World-Writable `/usr/bin/bash` → SUID rootbash via `dd` + `sudo` → Root | [Walkthrough](./Medium/README.md) |

### 🔴 Hard
| Machine | Date | Focus | Notes |
| :--- | :--- | :--- | :--- |
| **Pirate** | Feb 2026 | gMSA Enumeration, Kerberoasting, AD PrivEsc | [Walkthrough](./Hard/README.md) |
| **Snapped** | Mar 2026 | CVE-2026-27944, Credential Cracking, CVE-2026-3888 snapd LPE | [Walkthrough](./Hard/README.md) |
| **Fries** | Mar 2026 | Enumeration, Credential Abuse, Container Pivoting, Active Directory Exploitation, AD CS Attacks | [Walkthrough](./Hard/README.md) |
| **DarkZero** | Apr 2026 | MSSQL Abuse, Linked Server Pivoting, Privilege Escalation, Kerberos Abuse (DC01$ TGT), DCSync, Pass-the-Hash | [Walkthrough](./Hard/README.md) |

### 🏰 Fortress (Conceptual Notes Only)
| Machine | Date | Focus | Notes |
| :--- | :--- | :--- | :--- |
| **Akerva** | Mar 2026 | SNMP Enumeration, Backup Fuzzing, Flask, LFI, PrivEsc, Cipher Decoding | [Walkthrough](./Fortress/Akerva/notes.md) |
| **Faraday** | Mar 2026 | API Fuzzing, Auth Bypass, Hash Cracking, SSH Foothold, Linux Privilege Escalation, Rootkit Detection | [Walkthrough](./Fortress/README.md) |
| **Synacktiv** | Mar 2026 | VHost Fuzzing, Symfony Exploitation, Signed URL Abuse, Java Deserialization (RMI), Network Pivoting, Squid Proxy, APK Analysis, Privilege Escalation (PwnKit) | [Walkthrough](./Fortress/README.md) |
| **Context** | Mar 2026 | Web Enumeration, SQL Injection (MSSQL), Credential Reuse, Outlook Access, Linked Server Exploitation, Data Extraction, Reverse Shell, Binary Analysis | [Walkthrough](./Fortress/README.md) |

---

## Tools Frequently Used

* **Recon:** Nmap, Gobuster, Rustscan  
* **Web Testing:** Burp Suite, ffuf, SQLmap  
* **Exploitation:** Metasploit, Custom PoCs  
* **Privilege Escalation:** LinPEAS, pspy  

---