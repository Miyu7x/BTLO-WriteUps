---
title: Curiosity
module: Digital Forensics
path: Investigations
platform: Blue Team Labs Online
tags: [dfir, windows, usn-journal, $J, zimmerman-tools, file-system-forensics, insider-threat]
status: completed
date: 2026-07-27
date_completed: 2026-07-27
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

The first step in our investigation is to make the journal logs `$J` into a readable CSV file.

Command: `.\MFTECmd.exe -f 'C:\Users\BTLOTest\Desktop\Artefacts\$Extend\$J' --csv C:\output --csvf journal.csv`

<p align="center">
<img src=screenshots/curiosity-readablefile.png width="700">
</p>

Timeline Explorer can be hard to read, especially journal logs, since it does not read as a single event. One file is "logged" on multiple lines even though it's one action, and if you're used to reading other logs this can be extremely confusing.

The important thing to understand is that the Update Reasons field is **cumulative, not sequential**. Each row is a running total of everything that has happened to that file so far — not a separate event. Read bottom to top: the first row is the file being created, and the final row ending in `Close` is the write completing.

**Example:** Name: invoice-jan.pdf (Count: 19) Entry Number: 105177 Parent Sequence Number: 8

UpdateReasons
FileCreate
FileCreate|SecurityChange
DataExtend|FileCreate|SecurityChange
DataOverwrite|DataExtend|FileCreate|SecurityChange
DataOverwrite|DataExtend|FileCreate|SecurityChange|StreamChange
DataOverwrite|DataExtend|NamedDataExtend|FileCreate|SecurityChange|StreamChange
DataOverwrite|DataExtend|NamedDataOverwrite|NamedDataExtend|FileCreate|SecurityChange|StreamChange
DataOverwrite|DataExtend|NamedDataOverwrite|NamedDataExtend|FileCreate|SecurityChange|BasicInfoChange|StreamChange|
DataOverwrite|DataExtend|NamedDataOverwrite|NamedDataExtend|FileCreate|SecurityChange|BasicInfoChange|StreamChange|Close

To eliminate all these "doubles" we group by name. Eliminate the files that appear twice with the same name, only count them once.

<p align="center">
<img src=screenshots/curiosity-invoice.png width="700">
</p>

**Answer: 4**

---

### Inventory Company-Owned .docx Files

---

How many unique company files ending in .docx extension are present in the user’s workstation that were owned by the company? (1 points)

The first step is to filter by the extension `.docx`, then group by name again. This gives us some interesting information; we spot **nae-reports** and some peculiar actions, as we see `$I` metadata for `$R` files, which indicates somebody deleted company files.

Name: $R3M0T8D.docx, 2026-04-14 14:19:08, Update Reasons: RenameNewName, Entry Number: 146943
Name: $RQH54V7.docx, 2026-04-14 13:59:04, Update Reasons: RenameNewName, Entry Number: 137067

<p align="center">
<img src=screenshots/curiosity-naereport.png width="700">
</p>

**Answer: 7**

---

### Identify the Home Automation Project

---

The company was working on an unreleased home automation project, and it believed it had been stolen. What was the name of this product? (2 points)

As we worked our investigation we noted some deleted `$R` docx files. I wanted to check out exactly what had been deleted, so I filtered by `$R`. We observed all the docx files earlier and none of those seemed suspicious, so I went down the list looking at the deleted files.

<p align="center">
<img src=screenshots/curiosity-recycle.png width="700">
</p>

I picked the first zip file on the list, Name: $R45QQU3.zip, Entry Number: 30497. Clear the search for `$R` so we can filter by Entry Number 30497 to see all related events for that deleted file.

<p align="center">
<img src=screenshots/curiosity-homepilot.png width="700">
</p>

Jackpot: we find a file named homepilot-main.zip, and even better evidence that it's a product — there is a homepilot-v1.zip. It has the word "home" in it and there is an upgraded version as well, which could indicate a project in the works.

**Answer: homepilot**

---

### Track the Renames

---

Following Q3, the user renamed the files into their respective versions. What are the new file names? (2 points)

Now that we found the name of the file we can filter for homepilot and see what actions took place. Right away we spot homepilot-v1.zip and homepilot-v2.zip — but what if the attacker had named it something else? It's good practice to follow the trail, so for investigative purposes we can filter by entry number 30497, sequence 16, because homepilot shows us `RenameOldName`, and now we can find what comes directly after that, which is homepilot-v1.zip.

<p align="center">
<img src=screenshots/curiosity-home2.png width="700">
</p>

**Answer: homepilot-v1, homepilot-v2**

---

### Pull the Entry Numbers for the Renamed Files

---

Following Q4, what are the entry numbers of the files after being renamed? (1 points)

I'll take a different approach here — did I mention how annoying Timeline Explorer is to read, lol. After much trial trying to understand why homepilot-v1 has various earlier timestamps, which proves the file name had already changed but does not mean it's the sequence number they are looking for. This can be incredibly frustrating, but what I've concluded is that the more filters we can attach, the better. I sorted by the homepilot- name and queried `FileCreate`, and going up the timeline we see homepilot-main.zip, and the next ones are homepilot-v1.zip and homepilot-v2.zip under those entries.

<p align="center">
<img src=screenshots/homepilot-entry.png width="700">
</p>

**Note** While tracing these entries I spotted a deletion in the same window that doesn't answer this question but is worth logging: @ 2026-04-15 10:51:12 homepilot-v2.zip is placed in the recycling bin and the file name changes to $RGMT3I7.zip. Deleting the versioned copies right after staging them is a behavior to come back to.

**Answer: 148277, 148280**

---

### Timestamp the First Version Written to Disk

---

When was the first version of the home automation product downloaded and written to disk, as per the $J record? (2 points)

This question has me questioning if I can even do this; it's ambiguous and, if anything, poorly worded, and why are we working backward?

But if you start fighting with yourself, tell your friend Finn that you chose the wrong career to go into, spiral a little — sometimes clarity comes back.

Break the question down into parts: what was the first version of the home automation file before being renamed? homepilot-main.zip. Let's filter for that, and now we observe the file being written to disk.

Worth being explicit about why the entry number changes here. 148277 and 148280 from Q5 are the copies that ended up carrying the v1 and v2 names — they were created already named, at 10:50 on the same day. Entry 30497 is the record that was actually downloaded as homepilot-main.zip at 08:51 and renamed afterward. Q5 asked about the renamed files; this question asks about the download, so it's a different record:

**Update Reasons**: Reads Bottom Up
DataOverwrite|DataExtend|NamedDataOverwrite|NamedDataExtend|FileCreate|SecurityChange|BasicInfoChange|StreamChange|Close
DataOverwrite|DataExtend|NamedDataOverwrite|NamedDataExtend|FileCreate|SecurityChange|BasicInfoChange|StreamChange
DataOverwrite|DataExtend|NamedDataOverwrite|NamedDataExtend|FileCreate|SecurityChange|StreamChange
DataOverwrite|DataExtend|NamedDataExtend|FileCreate|SecurityChange|StreamChange
DataOverwrite|DataExtend|FileCreate|SecurityChange|StreamChange
DataOverwrite|DataExtend|FileCreate|SecurityChange
DataExtend|FileCreate|SecurityChange
FileCreate|SecurityChange
FileCreate

The `NamedDataExtend` flags in the middle of that cascade are what evidence the word "downloaded" in the question — a named data stream being written alongside the file is the `Zone.Identifier` marker, which means the file arrived from outside the machine rather than being copied locally.

<p align="center">
<img src=screenshots/curiosity-time.png width="700">
</p>

**Answer: 2026-04-15 08:51:19**

---

### Find the Archive Used for Staging

---

The source code from the suspect workstation was archived. What was the name of the file believed to contain these files? (2 points)

Using 2026-04-15 08:51:19 as the anchor, we move forward through the rest of that day rather than staying in the download window — staging happens after possession, not during it. I filtered on "zip" in the Name column and sorted ascending, and the archive activity lands roughly two hours later, at 10:51. We note entry number 148282, which appears after both the v1 and v2 entries. Prior to that was 148280, which is homepilot-v2.zip, and prior to that 148277, which is homepilot-v1.zip.

<p align="center">
<img src=screenshots/curiosity-file.png width="700">
</p>

**Answer: Files.zip**

---

### Timestamp the Archive Creation

---

Following Q7, when was the archive file created? (1 points)

Staying on entry 148282 from Q7 and sorting ascending, the earliest record for Files.zip is its `FileCreate` — that's the creation time. With no `$MFT` available there's no `Created0x10` to cross-check against, so the journal's first record for the entry is the authority here.

**Answer: 2026-04-15 10:51:07**

---

### Identify the Anti-Forensics Browser

---

The user downloaded a browser to cover its tracks. What browser was downloaded? What version? (1 points)

We now have a good time window — things seem to be happening around 2026-04-15 10:51:07. We can't input a specific time for some reason, but we can filter by date, and I guess that's something. I filtered for browser activity and looked for events occurring shortly after that timestamp.

Just over a minute later, at 2026-04-15 10:52:44, we get Name: tor-browser-windows-x86_64-portable-15.0.9.exe. The version is in the installer filename.

<p align="center">
<img src=screenshots/curiosity-tor.png width="700">
</p>

**Answer: TOR, 15.0.9**

---

### Timestamp and Entry Number for the Browser Installer

---

Following Q9, when was the browser installer first observed being written to disk, and what entry number corresponds to that file? (2 points)

Staying on the Tor installer from Q9, sort ascending and take the earliest record for that file — that first write is the "first observed" moment the question asks for. The entry number is read off that same row.

<p align="center">
<img src=screenshots/curiosity-tor.png width="700">
</p>

**Answer: 2026-04-15 10:52:44, 148286**

---

### Case Notes

---

## Closing Notes

Curiosity is a tight introduction to USN journal analysis: everything in the investigation is recoverable from `$J` alone, which makes it a good exercise in reading MFT entry numbers, reason flags, and timestamps rather than leaning on file contents. The investigation arc — possession, rename to versioned filenames, archive for staging, then a privacy-focused browser installed to move the data out — maps cleanly onto an insider-threat timeline, and the same reasoning applies to real exfiltration cases where the files themselves are long gone but the journal still remembers them.

---
