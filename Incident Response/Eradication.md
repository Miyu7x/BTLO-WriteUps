---
title: Eradication
module: Incident Response
platform: BTLO
tags: [yara, yargen, malware-analysis, threat-hunting, joe-sandbox, hidden-files, t1056-001, t1564-002]
status: Completed
date: 2026-08-13
date_completed: 2026-08-13
---
*Write-up by [Miyu7x](https://github.com/Miyu7x) | TryHackMe: [Miyu7](https://tryhackme.com/p/Miyu7) | BTLO: [Miyu7x](https://blueteamlabs.online/public/user/Miyu7x)*
<p align="center">
<img src=screenshots/eradication-intro.png width="1500">
</p>
---

## Task 1: Scenario

A threat actor has compromised a system and hidden a number of files across multiple user directories. Generate a Yara rule to identify the presence of additional binaries based on a collected sample, then write a custom rule using simple IOCs to identify another type of malware.

**Task:** Generate a Yara rule from the collected sample, scan the `/John/` and `/Trevor/` user directories for matches, verify the finding through Joe Sandbox, then build an IOC based rule by hand to catch a second malware family.

**Setup notes:**

- Run yarGen as the `ubuntu` user, not as root. The Python dependencies are installed under `ubuntu`, so `sudo su` first causes a `ModuleNotFoundError` that looks like a broken tool.
- Work from `/home/ubuntu/Desktop/Investigation/yarGen`. yarGen looks for its `dbs/` goodware databases relative to its own folder.
- Scope is `/home/John/` and `/home/Trevor/`. All files matching the generated rules inside those paths are in scope.

<p align="center">
<img src=screenshots/eradication-parts.png width="700">
</p>

---

## Investigation Submission - Part One

### Q1. What is the full file path for the rule match in /John/? _(5 points)_

First step is to point yarGen at MALWARE-SAMPLE.

- yarGen pulls every string out of the sample, then subtracts every string that also appears in its goodware database. "Weird" is not something yarGen detects, it is what survives after the normal is removed.
- Whatever survives gets scored and assembled into a draft Yara rule.
- Filenames and hashes change constantly, so the thing worth hunting is the signature, the DNA.

Mental model:

- I have this one bad thing. What unique parts of it can I extract to scan the system and see if any of it is hiding somewhere else.
- "Show me every file that looks like this fingerprint."

Flags:

- `-m` malware, and it takes a directory, not a file
- `-o` output file name

```
python3 yarGen.py -m /home/ubuntu/Desktop/Investigation/MALWARE-SAMPLE
```

<p align="center">
<img src=screenshots/eradication-q1a.png width="700">
</p>

Rules are saved to `/home/ubuntu/Desktop/Investigation/yarGen/yargen_rules.yar`.

Reading the generated rule before running it:

- `uint16(0) == 0x5a4d` means the first two bytes are `MZ`, the magic number on every Windows executable. This checks bytes, not the filename, so a disguised extension does not help the attacker.
- `filesize < 2000KB` is a cheap performance filter.
- `8 of them` means at least 8 of the 20 extracted strings must be present. That fuzziness is why Yara beats hashing.
- The strings are `mscorlib`, `System.Resources`, `Microsoft.VisualBasic`, `AssemblyCompanyAttribute`, `Bunifu_Button`. This is a .NET binary built with a GUI toolkit, which points at commodity kit malware.

Next step is running the rule against both users.

- `-r` is the recursive flag. It searches all subdirectories. The files are buried, so without it the scan returns a false all clear.
- Run it from inside `/home/ubuntu/Desktop/Investigation/yarGen`.

```
yara -r yargen_rules.yar /home/John/
```

<p align="center">
<img src=screenshots/eradication-q1b.png width="700">
</p>

**Answer:** `/home/John/.bash_history`

---

### Q2. What is the full file path for the rule match in /Trevor/? _(5 points)_

Same rule, different target.

```
yara -r yargen_rules.yar /home/Trevor/
```

<p align="center">
<img src=screenshots/eradication-q2.png width="700">
</p>

The path is worth stopping on. Those `...` entries are not truncation, they are real directories.

- `.` and `..` are special in Linux. `...` is not special at all, which makes it a legal directory name that someone chose.
- The leading dot hides it from plain `ls` and from the GUI file manager.
- It also sits right next to `.` and `..` in an `ls -a` listing, where the eye reads it as navigation noise.
- `ls -lA` with a capital A strips out `.` and `..` and leaves `...` standing alone with nowhere to hide.
- The filename `a.a` is deliberately forgettable, no meaningful extension.

That is T1564.001, Hide Artifacts: Hidden Files and Directories.

Confirming the file type independently of its name:

```
file /home/Trevor/Downloads/.../.../.../a.a
```

`file` reads magic bytes and reports a PE32 executable. A Windows binary staged in a Linux user's home folder cannot even run there, so it is suspicious on placement alone.

**Answer:** `/home/Trevor/Downloads/.../.../.../a.a`

---

### Q3. Search the SHA256 hash (either obtained via CLI from the sample or from the yarGen created rule) and submit it to joesandbox.com - What is the malware's name? _(5 points)_

yarGen writes the sample's SHA256 into the `meta:` block of the rule as `hash1`, so no `sha256sum` is needed.

<p align="center">
<img src=screenshots/eradication-q3a.png width="700">
</p>

Take the hash, not the filename. Filenames are attacker controlled, the hash is derived from the content. Submit it to an analysis platform such as Joe Sandbox, VirusTotal, or Hybrid Analysis, and check the result against the challenge tag T1056.001, Input Capture: Keylogging.

<p align="center">
<img src=screenshots/eradication-q3b.png width="700">
</p>

**Answer:** Snake Keylogger

---

## Investigation Submission - Part Two

### Q4. What is the full file path for the rule match in /John/? _(5 points)_

Part Two runs the same problem backwards. Part One went sample to rule and the tool wrote it. Part Two goes intel to rule and I write it. That translation from a human readable IOC into detection logic is the actual skill being tested.

The yarGen output is the skeleton, so the second rule reuses the same two blocks, `strings:` and `condition:`.

```
nano part2.yar
```

<p align="center">
<img src=screenshots/eradication-q4a.png width="700">
</p>

<p align="center">
<img src=screenshots/eradication-q4b.png width="700">
</p>

**Answer:** `/home/John/Downloads/Old/.history.sc`

---

### Q5. What is the full file path for the rule match in /Trevor/? _(5 points)_

Ran the same rule against `/home/Trevor/` and got nothing back.

- No output does not mean no malware. It means the condition is too strict.
- Every IOC joined with `and` has to be true at once, and real files are messier than intel reports.
- `filesize` is the most brittle condition in the set, since the file in Trevor is a different size to the one in John.
- Removed the size check, loosened the condition, re-ran.

<p align="center">
<img src=screenshots/eradication-q5a.png width="700">
</p>

<p align="center">
<img src=screenshots/eradication-q5b.png width="700">
</p>

The match is a `.png`. A picture file matching a malware rule is either a false positive or not a picture. Adding `-s` to the yara command prints which strings actually hit, which is how you tell the two apart. A hit on content strings is real, a hit on size alone is not.

**Answer:** `/home/Trevor/Pictures/richard-brutyo-Sg3XwuEpybU-unsplash.png`

---

## IOC Summary

| Type | Indicator | Context |
|---|---|---|
| File Hash (SHA256) | `9c6d167a1cd8ab7a815e167635aa97051b6cabb52049eaa215a7f897121647c0` | Collected sample, written into the yarGen rule `meta:` block as `hash1` |
| Malware Name | Snake Keylogger | Identified via Joe Sandbox hash lookup, matches T1056.001 |
| Binary Sample | `MALWARE-SAMPLE/.xterm.sh` | Hidden dotfile named as a shell script, MZ header proves it is a Windows PE |
| File Path | `/home/John/.bash_history` | Part One match, masquerading as a normal shell history file |
| File Path | `/home/Trevor/Downloads/.../.../.../a.a` | Part One match, buried in three nested directories named `...` |
| File Path | `/home/John/Downloads/Old/.history.sc` | Part Two match, hidden dotfile with a fake history extension |
| File Path | `/home/Trevor/Pictures/richard-brutyo-Sg3XwuEpybU-unsplash.png` | Part Two match, executable disguised with a `.png` extension |
| Yara Rule | `yargen_rules.yar` | Auto generated, condition `uint16(0) == 0x5a4d and filesize < 2000KB and 8 of them` |
| Yara Rule | `part2.yar` | Hand written from provided IOCs, loosened after zero matches in `/Trevor/` |
| User Directory | `/home/John/`, `/home/Trevor/` | Both compromised, two staged files each |

---

## Notes and open questions

- Eradication only works if enumeration is complete. Cleaning three of six dropped files gives the actor a nap, not a removal.
- Extension is a claim, magic bytes are evidence. Every match here was named to look like something it was not.
- `ls -lA` beats `ls -la` when hunting hidden directories, because it removes the `.` and `..` the attacker is camouflaging against.
- ModuleNotFoundError in a purpose built lab almost always means wrong user or wrong directory, not a broken tool. Check `whoami` and `pwd` before touching any code.
- The yarGen strings here are generic .NET runtime artifacts. On a production network this rule would generate false positives on legitimate .NET applications. It would need tightening before deployment.
- Open question: what is the minimum set of strings that keeps all four detections and drops the .NET noise.
- Open question: how would the `...` directory trick be caught proactively, rather than after a Yara sweep.
