---
title: Defaced
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

- [Defaced](https://blueteamlabs.online/home/investigation/defaced-593f17897e) -- BTLO investigation
- Goal is reconstructing the full attack chain from scan to defacement to database exfil
- Techniques in scope: T1595.002 (vulnerability scanning), T1059.004 (Unix shell), T1070.004 (file deletion)
- Skills covered: Kibana Discover querying, spotting scanner user-agents, tracing RFI to webshell, correlating FIM alerts with web logs, timeline building

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

Every question has three parts. Extract them before you touch Kibana.

  - What kind of thing is the answer? (an IP, a filename, a timestamp, a tool name, a string)
  - Which field holds that kind of thing?
  - What do I already know that narrows it? (a known IP, a known time window, a prior answer)

**Notable Scanners:** 
  - Nikto, Acunetix, Nessus, OpenVAS, sqlmap
  - WPScan, Nuclei, ZAP, Burp, dirb/dirbuster
  - gobuster, WhatWeb, Arachni, w3af, Skipfish
  - Nmap NSE, masscan
 
---
 
## Investigation Submission
 
### As an analyst, you need to submit details to the CTI team. What is the signature left by the threat actor that compromised the website? (2 points)

<p align="center">
<img src=screenshots/defaced-apash.png width="700">
</p>
To begin our investigation, I opened up Kibana, and the JPG files to get an overview of all the evidence we have. The After.JPG is a message left by the threat actors...

**Answer: Team Apash Kirikiri 2.0**
 
---
 
### The attacker deleted some files. What are they? (Alphabetical order based on filename) (2 points)

 <p align="center">
<img src=screenshots/defaced-deleted.png width="700">
</p>
In the Investigation Files folder that we found the After.JPG we also have a FIM1 and FIM2.JPG. In FIM2.JPG we can observe the tab events provides use with file actions perfomed by the attacker. 

**Answer: access_log, error_log**
 
---
 
### What is the scanner used by the attacker to identify the vulnerability? (3 points)

<p align="center">
<img src=screenshots/defaced-nikto.png width="700">
</p>

I started this investigation by filtering out the obvious, the malicious client IP and resposnse: 404 which could lead us to the scanner answer we are lookin for. What i did find was really interesting scrolling thru the lines just to get a view of things I noted that are hundreds if not thousands of GET requests for the same exact timesteamp, meaning no human fingers could do that, big red flag! Nikto=http://cirt.net/rfiinc.txt

Lets filter by some of the most popular and common web scanners: "Burp Suite" or "ZAP" or "nikto" or "nuclei"

We find our answer in Nikto, which matches our original perception of hundreds of scans of different file names and commands...
 
**Answer: Nikto**

---
 
### Which PHP page is vulnerable to Remote File Inclusion (RFI)? (2 points)

 <p align="center">
<img src=screenshots/defaced-nikto.png width="700">
</p>

From our previous find we know that Nikto tested for RFI on cirt.net and all the results were 404, a successful RFI is code 200 and **not** cirt.net. Thats the clue we are working with. Work with what you have, is a huge key takeway here or in this case what you dont have! Now we only have 12 hits to log thur and we can easily spot webshell.php coming from getimagesonly.php
Filter: request: *=http* and not request: *cirt.net*

**Answer: getimagesonly.php**
 
---
 
### What is the IP address of the remote attacker? (3 points)

  <p align="center">
<img src=screenshots/defaced-ip.png width="700">
</p>

**Answer: 91.192.103.35**
 
---
 
### What is the name of the PHP shell? (2 points)

 <p align="center">
<img src=screenshots/defaced-backdoor.png width="700">
</p>

Timeline: Feb 18, 2021 11:41:34:000 webshell.php
Timeline: Feb 18, 2021 11:41:52:000 backdoor.jpg.php

**Answer: backdoor.jpg.php**
 
---
 
### The attacker downloaded the PHP shell from a file-hosting website. What is the name of the website? (2 points)

<p align="center">
<img src=screenshots/defaced-mediafire.png width="700">
</p>
 
**Answer: mediafire.com**
 
---
 
### What time was the first command executed through the PHP shell? (3 points)

Timeline: Feb 18, 2021 11:41:34:000 webshell.php
 
**Answer:**
 
---
 
### Which config file does the attacker attempt to read using the command 'cat'? (2 points)
 
**Answer:**
 
*Notes:*
 
---
 
### At what time was the database dumped by the attacker? (2 points)
 
**Answer:**
 
*Notes:*
 
---
 
### The attacker exfiltrated the database records. What is the database name? (Just the name, without any extension) (2 points)
 
**Answer:**
 
*Notes:*
 
---
 
## Closing Notes
 
- Clean end-to-end intrusion story: recon scan, RFI, webshell drop, hands-on-keyboard commands, dump, anti-forensics
- The question order roughly matches the attack order, so the timeline builds itself if you work sequentially
- FIM alerts and web logs answer different halves of the same question, and neither is enough alone
- Good rep for pivoting in Kibana Discover instead of grepping flat files
