---
title: Defaced
module: 
path: 
platform: Blue Team Labs Online
tags: [ELK, Security Operations, Web Attack, Log Analysis, T1070.004, T1595.002, T1059.004]
status: 
date: 
date_completed: 
---
*Write-up by [Miyu7x](https://github.com/Miyu7x) | TryHackMe: [Miyu7](https://tryhackme.com/p/Miyu7) | BTLO: [Miyu7x](https://blueteamlabs.online/public/user/Miyu7x)*

<p align="center">
<img src=screenshots/INTRO_FILENAME width="1500">
</p>

## Introduction

- [Defaced](https://blueteamlabs.online/home/investigation/defaced-593f17897e) -- BTLO investigation, Easy, 25 points, Security Operations, Retired
- Log analysis in ELK/Kibana against a compromised pharmaceutical website
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

## Investigation Submission

### As an analyst, you need to submit details to the CTI team. What is the signature left by the threat actor that compromised the website? (2 points)

**Answer:**

*Notes:*

---

### The attacker deleted some files. What are they? (Alphabetical order based on filename) (2 points)

**Answer:**

*Notes:*

---

### What is the scanner used by the attacker to identify the vulnerability? (3 points)

**Answer:**

*Notes:*

---

### Which PHP page is vulnerable to Remote File Inclusion (RFI)? (2 points)

**Answer:**

*Notes:*

---

### What is the IP address of the remote attacker? (3 points)

**Answer:**

*Notes:*

---

### What is the name of the PHP shell? (2 points)

**Answer:**

*Notes:*

---

### The attacker downloaded the PHP shell from a file-hosting website. What is the name of the website? (2 points)

**Answer:**

*Notes:*

---

### What time was the first command executed through the PHP shell? (3 points)

**Answer:**

*Notes:*

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
