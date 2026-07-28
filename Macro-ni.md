---
title: Macro-ni
module: Digital Forensics
path: Investigations
platform: Blue Team Labs Online
tags: [malware-analysis, maldoc, vba-macro, powershell, obfuscation, cyberchef, oletools, phishing]
status: 
date: 
date_completed: 
---
*Write-up by [Miyu7x](https://github.com/Miyu7x) | TryHackMe: [Miyu7](https://tryhackme.com/p/Miyu7) | BTLO: [Miyu7x](https://blueteamlabs.online/public/user/Miyu7x)*

<p align="center">
<img src=screenshots/macro-ni.png width="1500">
</p>

---

## Introduction

Macro-ni is a Very Easy, 15-point investigation on Blue Team Labs Online built around a malicious Word document rather than host artifacts. There are no logs and no disk image here — the evidence is the file itself, and the work is peeling back layers of obfuscation one at a time. The chain runs from a VBA macro to an embedded PowerShell command, through two layers of encryption and an embedded archive, down to an XOR-obfuscated byte array holding a C2 address. CyberChef is the tagged toolkit, with oletools for pulling the macro out of the document. Each answer is the input to the next question, so the order of the submission is also the order of the analysis.

---

## Scenario

A phishing email cleared the mail filter with a Word document attached. The IR team detonated it in a sandbox, watched it do something on launch, and suspects shellcode or a downloader is buried inside. The task is to decode the document layer by layer and identify what it was reaching out to.

| Field | Value |
| --- | --- |
| Points | 15 |
| Difficulty | Very Easy |
| OS | Linux |
| Tooling | CyberChef |
| Solves | 376 |

---

## Investigation Submission

### Identify the Encryption in the Extracted PowerShell

---

The extracted powershell command contains what type of encryption? (3 points)

**Answer:**

---

### Identify the Archive Type in the Second Layer

---

After decrypting first layer of encryption. We get another layer of encryption. If decrypted, what type of archive file data will it be? (3 points)

**Answer:**

---

### Locate the Byte Array Holding the Third Layer

---

Upon saving the archive and extracting the content. We see third layer of encryption present. What byte array variable is having that data? (3 points)

**Answer:**

---

### Recover the XOR Key

---

The same byte array is getting XORed by a decimal value. What is it? (3 points)

**Answer:**

---

### Decode the Final Layer and Extract the C2

---

Can you decrypt this layer of obfuscation and find the C2 IP? (3 points)

**Answer:**

---

## Closing Notes

Macro-ni is a clean introduction to layered maldoc analysis, and the value is in the discipline rather than the difficulty: every layer's output is the next layer's input, so saving each intermediate artifact to disk before moving on is the difference between a smooth run and starting over. The chain here — macro drops PowerShell, PowerShell decrypts to an archive, archive yields a script, script XORs a byte array to hide its C2 — is a realistic pattern, and the same approach of identifying an encoding by its artifacts (crypto class names in code, magic bytes at the head of a blob, a lone integer beside a byte array) transfers directly to phishing triage work where the sample is all you have.

---
