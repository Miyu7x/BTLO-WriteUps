---
title: Phishy v1
module: 
path: 
platform: Blue Team Labs Online
tags: [phishing, phishing-kit, threat-intel, osint, T1566, T1598]
status: 
date: 
date_completed: 
---
*Write-up by [Miyu7x](https://github.com/Miyu7x) | TryHackMe: [Miyu7](https://tryhackme.com/p/Miyu7) | BTLO: [Miyu7x](https://blueteamlabs.online/public/user/Miyu7x)*

<p align="center">
<img src=screenshots/phishy.png width="1500">
</p>

---

## Introduction

- BTLO investigation lab built around a single artifact: one phishing URL
- Focus is phishing kit analysis plus threat intel, not log review
- Work runs from the landing page, into the kit source, out to operator attribution
- Tools: Web Browser, Text Editor, Linux CLI
- MITRE ATT&CK: T1566 (Phishing), T1598 (Phishing for Information)
- Infrastructure in this lab is live and malicious -- no credentials entered at any point, interaction limited to reading source and pulling the kit

---

## Scenario

- A phishing link arrives in the inbox
- The operator picked the wrong target
- Starting from that one link, identify the site, the kit behind it, and the person running it

---

## Investigation Submission

### 1. The HTML page used on securedocument.net is a decoy. Where was this webpage mirrored from, and what tool was used? (Use the first part of the tool name only)



**Answer:**

---

### 2. What is the full URL of the background image which is on the phishing landing page?



**Answer:**

---

### 3. What is the name of the php page which will process the stolen credentials?



**Answer:**

---

### 4. What is the SHA256 of the phishing kit in ZIP format? (Provide the last 6 characters)



**Answer:**

---

### 5. What email address is setup to receive the phishing credential logs?



**Answer:**

---

### 6. What is the function called to produce the PHP variable which appears in the index1.html URL?



**Answer:**

---

### 7. What is the domain of the website which should appear once credentials are entered?



**Answer:**

---

### 8. There is an error in this phishing kit. What variable name is wrong causing the phishing site to break? (Enter any of 4 potential answers)



**Answer:**

---

## Closing Notes

- Phishing kits carry their own attribution: the exfil address, the mirroring tool's signature, and the redirect target all sit in the source
- Reading a kit end to end beats answering questions one at a time -- the credential handler, the config, and the redirect explain each other
- A broken variable in a live kit is a reminder that operators ship bugs too, and those bugs are a fingerprint
