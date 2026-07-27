---
title: Curiosity
module: Digital Forensics
path: Investigations
platform: Blue Team Labs Online
tags: [dfir, windows, usn-journal, $J, zimmerman-tools, file-system-forensics, insider-threat]
status: 
date: 
date_completed: 
---
*Write-up by [Miyu7x](https://github.com/Miyu7x) | TryHackMe: [Miyu7](https://tryhackme.com/p/Miyu7) | BTLO: [Miyu7x](https://blueteamlabs.online/public/user/Miyu7x)*

<p align="center">
<img src=screenshots/curiosity.png width="1500">
</p>

---

## Introduction

Curiosity is a Very Easy, 15-point Windows digital forensics investigation on Blue Team Labs Online, built around reading `$J` records — the USN journal — to reconstruct what a user did to files on a workstation. The lab covers creation, modification, rename, and deletion events, and the goal is to turn those raw journal entries into a timeline of user behavior. The Zimmerman tools are the intended toolkit. Login for the box is `btlo` with a blank password. The investigation is retired, so it still counts toward achievements but no longer awards leaderboard points.

---

## Scenario

NAE Systems is building a new product, and threat intel reporting shows sensitive product data from that project has leaked and is being sold on the dark web. The IR team opens an internal investigation and tracks suspicious outbound traffic back to an employee workstation. The early read is that the employee may have opened the material out of simple curiosity — the job here is to determine whether it went further than that: whether the file was actually possessed, staged, archived, transferred, or exfiltrated. The task is to establish possession, gather the forensic evidence backing that conclusion, and flag any other suspicious host activity that points to unauthorized access, staging, execution, transfer, or exfiltration.

| Field | Value |
| --- | --- |
| Points | 15 |
| Difficulty | Very Easy |
| OS | Windows |
| Tooling | Zimmerman tools |
| Credentials | User: `btlo` / Password: (blank) |

---

## Investigation Submission

### Inventory the Invoices

---

How many unique company invoices are present in the user's workstation during the acquisition? (1 points)

**Answer:**

---

### Inventory Company-Owned .docx Files

---

How many unique company files ending in .docx extension are present in the user’s workstation that were owned by the company? (1 points)

**Answer:**

---

### Identify the Home Automation Project

---

The company was working on an unreleased home automation project, and it believed it had been stolen. What was the name of this product? (2 points)

**Answer:**

---

### Track the Renames

---

Following Q3, the user renamed the files into their respective versions. What are the new file names? (2 points)

**Answer:**

---

### Pull the Entry Numbers for the Renamed Files

---

Following Q4, what are the entry numbers of the files after being renamed? (1 points)

**Answer:**

---

### Timestamp the First Version Written to Disk

---

When was the first version of the home automation product downloaded and written to disk, as per the $J record? (2 points)

**Answer:**

---

### Find the Archive Used for Staging

---

The source code from the suspect workstation was archived. What was the name of the file believed to contain these files? (2 points)

**Answer:**

---

### Timestamp the Archive Creation

---

Following Q7, when was the archive file created? (1 points)

**Answer:**

---

### Identify the Anti-Forensics Browser

---

The user downloaded a browser to cover its tracks. What browser was downloaded? What version? (1 points)

**Answer:**

---

### Timestamp and Entry Number for the Browser Installer

---

Following Q9, when was the browser installer first observed being written to disk, and what entry number corresponds to that file? (2 points)

**Answer:**

---

### Case Notes

---

## Closing Notes

Curiosity is a tight introduction to USN journal analysis: everything in the investigation is recoverable from `$J` alone, which makes it a good exercise in reading `MFT` entry numbers, reason flags, and timestamps rather than leaning on file contents. The investigation arc — possession, rename to versioned filenames, archive for staging, then a privacy-focused browser installed to move the data out — maps cleanly onto an insider-threat timeline, and the same reasoning applies to real exfiltration cases where the files themselves are long gone but the journal still remembers them.

---
