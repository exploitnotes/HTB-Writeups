## Fortress – Conceptual Notes

![alt text](images/pwned.png)

---

### **Topics Learned:**

* HTTPS service enumeration
* Source code analysis for sensitive data leakage
* SQL Injection (MSSQL-based exploitation)
* Outlook Web Access (OWA) abuse
* Credential pivoting across multiple services
* MSSQL linked server exploitation (`openquery`)
* .NET deserialization vulnerabilities
* Reverse shell generation and execution
* Windows remote management (Evil-WinRM)
* Binary decompilation and analysis

---

### **Key Learning Points:**

* Misconfigured web applications can expose credentials directly in source code
* SQL Injection in MSSQL can be extended using advanced queries and chaining
* Access to internal email systems can reveal critical files and credentials
* Serialized objects (ViewState/cookies) can lead to remote code execution
* Linked MSSQL servers enable lateral movement within internal networks
* Large data dumps require efficient searching to extract meaningful information
* Base64 encoded database entries may hide executable payloads or DLLs
* Credential reuse across services significantly weakens security posture
* Decompiling binaries is an effective way to uncover hidden secrets and flags

---

### **Skills Strengthened:**

* Web enumeration and manual testing
* SQL Injection (advanced MSSQL techniques)
* Credential discovery and reuse strategies
* MSSQL exploitation using Impacket tools
* Deserialization attack execution (ysoserial)
* Reverse shell handling and troubleshooting
* Windows post-exploitation via Evil-WinRM
* Data extraction from large outputs
* Basic reverse engineering and binary analysis
