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
| Editor | Jan 2026 | RCE, PATH Hijacking | [Notes](./Easy/README.md) |
| Expressway | Jan 2026 | IKE Aggressive Mode, Custom SUID | [Notes](./Easy/README.md) |
| MonitorsFour | Jan 2026 | RCE (CVE-2025-24367), Docker Remote API | [Notes](./Easy/README.md) |
| Facts | Feb 2026 | Information Disclosure, Misconfiguration | [Notes](./Easy/README.md) |
| WingData | Feb 2026 | Web App Vulnerabilities (Auth/Injection) | [Notes](./Easy/README.md) |
| CCTV | Mar 2026 | Internal Recon, API Abuse | [Notes](./Easy/README.md) |

### 🟡 Medium
| Machine | Date | Focus | Notes |
| :--- | :--- | :--- | :--- |
| Pterodactyl | Feb 2026 | RCE, PrivEsc (CVE-2025-6019/6018) | [Notes](./Medium/README.md) |
| AirTouch | Feb 2026 | Credential Exposure, Network Pivot | [Notes](./Medium/README.md) |
| Interpreter | Feb 2026 | RCE, Eval Injection | [Notes](./Medium/README.md) |
| Principal | Linux | JWT Auth Bypass, SSH CA Forgery | [Notes](./Medium/README.md) |
| VariaType | Linux | LFI → FontTools → Command Injection → Sudo Path Traversal | [Notes](./Medium/README.md) |

### 🔴 Hard
| Machine | Date | Focus | Notes |
| :--- | :--- | :--- | :--- |
| Pirate | Feb 2026 | gMSA Enumeration, Kerberoasting, AD PrivEsc | [Notes](./Hard/README.md) |
| **Snapped** | March 2026 | CVE-2026-27944, Credential Cracking, CVE-2026-3888 snapd LPE | [Walkthrough](./Hard/README.md) |

### 🏰 Fortress (Conceptual Notes Only)
| Machine | Date | Focus | Notes |
| :--- | :--- | :--- | :--- |
| Akerva | Mar 2026 | SNMP Enumeration, Backup Fuzzing, Flask, LFI, PrivEsc, Cipher Decoding | [Notes](./Fortress/Akerva/notes.md) |
| Other Fortress Machines | TBD | Various Concepts | [Notes](./Fortress/README.md) |

---

## Tools Frequently Used

* **Recon:** Nmap, Gobuster, Rustscan  
* **Web Testing:** Burp Suite, ffuf, SQLmap  
* **Exploitation:** Metasploit, Custom PoCs  
* **Privilege Escalation:** LinPEAS, pspy  

---