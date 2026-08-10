---
title: Attacks
module: Investigations
path: BTL1
platform: BTLO
tags: [mitre-attack, windows-event-logs, event-viewer, sysmon, ssh, brute-force, persistence, defense-evasion, malware]
status: Complete
date: 2026-08-07
date_completed: 2026-08-10
---
*Write-up by [Miyu7x](https://github.com/Miyu7x) | TryHackMe: [Miyu7](https://tryhackme.com/p/Miyu7) | BTLO: [Miyu7x](https://blueteamlabs.online/public/user/Miyu7x)*
<p align="center">
<img src=screenshots/attacks-intro.png width="1500">
</p>

---

## Scenario

Test your knowledge of MITRE ATT&CK while investigating the logs from a compromised Windows host!

**Setup notes**

- Open `Event Viewer` from the Start menu. The saved logs for this lab live under `Windows Logs > Security` and `Windows Logs > System`, plus any `.evtx` files on the Desktop opened with `Action > Open Saved Log`.
- Use `Action > Filter Current Log` to filter by Event ID, and switch to the `Details > Friendly View` tab to read the full field names.
- Click the `Date and Time` column header to flip between newest first and oldest first. Any question asking for the first occurrence of something needs oldest first.
- MITRE technique lookups go to `https://attack.mitre.org`, use the site search box for the technique name.

---

## Investigation Submission

### Q1. Using the firewall log image on the Desktop, what MITRE ATT&CK reconnaissance technique was used? (Format: Technique Name, TXXXX) (1 points)

The firewall image shows 192.168.1.33 hitting a range of ports on a single host. That is a port scan, and MITRE files scanning under Reconnaissance.

<p align="center">
<img src=screenshots/attacks-q1.png width="700">
</p>

**Answer: Active Scanning, T1595**

---

### Q2. We can see from the firewall image in Q1 that the IP address 192.168.1.33 checked to see what ports were listening on the other system. What command can we use in CMD to check which ports are listening on the endpoint? (Format: command -x) (1 points)

`netstat` lists network connections and listening sockets. On Windows, `-a` is what adds listening ports to the output. Without it netstat only shows established connections, which would miss exactly what the scan in Q1 was probing for.

```
netstat -a
```

<p align="center">
<img src=screenshots/attacks-q2.png width="700">
</p>

**Answer: netstat -a**

---

### Q3. There are ports listening on the endpoint that would enable remote connection, this could potentially make the system vulnerable to intrusion. It's time to check the logs! Which protocol and port have been used by the attacker to gain access to the system? (Format: protocol, port) (1 points)

The OpenSSH log is the giveaway. The service is running and taking authentication attempts, which puts the attacker on the standard SSH port.

<p align="center">
<img src=screenshots/attacks-q3.png width="700">
</p>

**Answer: ssh, 22**

---

### Q4. What user account has been accessed by the attacker? (Format: Account) (1 points)

<p align="center">
<img src=screenshots/attacks-q4.png width="700">
</p>

**Answer: administrator**

---

### Q5. What time did the attacker first gain access to this account? (Format: MM/DD/YYYY H:MM:SS AM/PM) (1 points)

In the OpenSSH log we can see when the attacker finally cracked the password for Administrator after multiple failed attempts.

<p align="center">
<img src=screenshots/attacks-q5.png width="700">
</p>

**Answer: 11/18/2022 5:14:08 PM**

---

### Q6. What MITRE ATT&CK initial access technique did the attacker use? (Format: Technique Name, TXXXX) (1 points)

The attacker did not exploit anything. They logged in with real credentials on a real account, which is what Valid Accounts covers.

<p align="center">
<img src=screenshots/attacks-q6.png width="700">
</p>

**Answer: Valid Accounts, T1078**

---

### Q7. What MITRE ATT&CK credential access technique did the attacker use to gain access to the endpoint? (Format: Technique Name, TXXXX) (1 points)

In the OpenSSH log the evidence for brute force is clear: many failed attempts followed by one successful login.

<p align="center">
<img src=screenshots/attacks-q7.png width="700">
</p>

**Answer: Brute Force, T1110**

---

### Q8. What account did the attacker create after gaining access? (Format: Account) (1 points)

When a new local account is created it gets logged in the Windows Security log as Event ID 4720. Filter Current Log by 4720, which matters in a log holding four years of events.

<p align="center">
<img src=screenshots/attacks-q8.png width="700">
</p>

**Answer: sysadmin**

---

### Q9. What MITRE ATT&CK persistence technique is this? (Format: Technique Name, TXXXX) (1 points)

- 11/18/2022 5:14:59 PM, Microsoft Windows security auditing, 4720, User Account Management, Audit Success

<p align="center">
<img src=screenshots/attacks-q9.png width="700">
</p>

**Answer: Create Account, T1136**

---

### Q10. What time did the attacker add his created account to the Administrators group? (Format: MM/DD/YYYY H:MM:SS AM/PM) (1 points)

Whenever an account is added to a **security-enabled local group** it is logged in the Windows Security log as Event ID 4732.

<p align="center">
<img src=screenshots/attacks-q10.png width="700">
</p>

**Answer: 11/18/2022 5:15:33 PM**

---

### Q11. What account did the attacker delete? (Format: Account) (1 points)

The Windows Security log Event ID for deleted users is 4726. There are only two events and only one on the attack day.

- 11/18/2022 5:15:33 PM

<p align="center">
<img src=screenshots/attacks-q11.png width="700">
</p>

**Answer: DRB**

---

### Q12. What MITRE ATT&CK impact technique is this? (Format: Technique Name, TXXXX) (1 points)

Deleting an account takes access away from the person who owned it. That lands under Impact, not Persistence.

<p align="center">
<img src=screenshots/attacks-q12.png width="700">
</p>

**Answer: Account Access Removal, T1531**

---

### Q13. What MITRE ATT&CK detection ID applies to the attacker's actions here? (Format: DSxxxx) (1 points)

Data sources live on their own page: https://attack.mitre.org/datasources/

<p align="center">
<img src=screenshots/attacks-q13.png width="700">
</p>

**Answer: DS0002**

---

### Q14. What's the name of the compressed file that was extracted? (Format: filename.ext) (1 points)

In the Sysmon log I started from the last confirmed attacker action and read forward:

- Starting point: 11/18/2022 5:15:33 PM
- Filtered by Event ID 1

7-Zip showing up in a process creation event is the flag. Nothing on this box had a reason to be unpacking archives.

- 11/18/2022 5:22:40 PM

<p align="center">
<img src=screenshots/attacks-q14.png width="700">
</p>

**Answer: keylogger.rar**

---

### Q15. What MITRE ATT&CK collection technique would this file use? (Format: Technique Name, TXXXX) (1 points)

Keyloggers are a form of input capture, which falls under Collection.

<p align="center">
<img src=screenshots/attacks-q15.png width="700">
</p>

**Answer: Input Capture, T1056**

---

### Q16. What sub-technique of the previous answer would this file use? (Format: Technique Name, TXXXX.xxx) (1 points)

<p align="center">
<img src=screenshots/attacks-q16.png width="700">
</p>

**Answer: Key Logging, T1056.001**

---

### Q17. What two files were created from this file extraction (in order of creation time)? (Format: filename.exe, filename.exe) (1 points)

- Starting point: 11/18/2022 5:22:40 PM, when the archive was extracted
- Sysmon Event ID 11 logs file creation

Both names are masquerades. `rundll33.exe` is a typosquat of the real `rundll32.exe`, and `svchost.exe` belongs in System32, not in a 7-Zip folder.

<p align="center">
<img src=screenshots/attacks-q17.png width="700">
</p>

- 11/18/2022 5:22:47 PM, rundll33.exe from 7z.exe
- 11/18/2022 5:22:50 PM, svchost.exe from 7z.exe

**Answer: rundll33.exe, svchost.exe**

---

### Q18. What's the file path of the folder these two files created? (Format: C:\...\..\FOLDER) (1 points)

The payload needs a home address. `C:\Program Files\7-Zip\` is where it landed, not where it wants to live, since nothing there launches at boot and it is the first place an analyst looks.

`AppData\Roaming` is writable without admin rights, survives reboot, and is buried under dozens of legitimate application folders. `WPDNSE` is a real Windows folder name, the Portable Device Name Space Extender, which normally sits under `AppData\Local\Temp`. Seeing it under Roaming is the tell.

Read the `TargetFilename` field on Event ID 11 and strip the filename off the end.

- 11/18/2022 5:24:21 PM
	- C:\Users\Administrator\AppData\Roaming\WPDNSE\svchost.exe
- 11/18/2022 5:25:27 PM
	- C:\Users\Administrator\AppData\Roaming\WPDNSE\rundll33.exe

<p align="center">
<img src=screenshots/attacks-q18.png width="700">
</p>
<p align="center">
<img src=screenshots/attacks-q181.png width="700">
</p>

**Answer: C:\Users\Administrator\AppData\Roaming\WPDNSE**

---

### Q19. What's the name of the .sys file created by the malware? (Format: file.sys) (1 points)

- 11/18/2022 5:24:31 PM, Process ID 4604 wrote a file into the folder from the previous question.

<p align="center">
<img src=screenshots/attacks-q19.png width="700">
</p>

**Answer: atapi.sys**

---

### Q20. What time was a registry value first set by the malware? (Format: MM/DD/YYYY H:MM:SS AM/PM) (1 points)

Sysmon Event ID 13 logs registry value sets. Filter by Event ID 13 and sort oldest first, then read the `RuleName` field on each event in the attack window.

- Most Event 13s have a blank `RuleName`. This one is flagged `T1089,Tamper-Defender` and targets a Windows Defender real-time protection value.
- `Image` is `MsMpEng.exe`, Defender's own engine, because that key is protected and nothing else is permitted to write it. The malware requests the change, Defender performs the write, which is why no malicious filename appears in the record.

<p align="center">
<img src=screenshots/attacks-q20.png width="700">
</p>

**Answer: 11/18/2022 5:24:27 PM**

---

### Q21. What two registry values has the malware created (in order of creation)? (Format: regvalue, regvalue) (1 points)

Sysmon Event ID 13, `RuleName` of `T1060,RunKey`. In the `TargetObject` field, everything before the last backslash is the key and the part after it is the value name.

- 5:24:21 PM: `Windows Atapi x86_64 Driver`, written by `C:\Program Files\7-Zip\svchost.exe`, `Details` points to `WPDNSE\svchost.exe`
- 5:25:43 PM: `Windows SCR Manager`, written by `WPDNSE\rundll33.exe`, `Details` points to `WPDNSE\rundll33.exe`

Both names masquerade as Windows components. `atapi` is a real storage driver, so `Windows Atapi x86_64 Driver` reads as legitimate at a glance. Each binary wrote its own autostart entry pointing back into the WPDNSE folder.

<p align="center">
<img src=screenshots/attacks-q21.png width="700">
</p>
<p align="center">
<img src=screenshots/attacks-q212.png width="700">
</p>

**Answer: Windows Atapi x86_64 Driver, Windows SCR Manager**

---

### Q22. What MITRE ATT&CK persistence technique has the malware used? (Format: Technique Name, TXXXX) (1 points)

`RuleName` is the flag, `TargetObject` is the evidence. The test that separates real persistence from configuration noise is the `Details` field: if it points at an executable in a user-writable folder it is persistence, if it is a DWORD or a Microsoft path it is not.

- `5:24:21 PM`
	- `TargetObject` = `...\CurrentVersion\Run\Windows Atapi x86_64 Driver`, a Run key
	- `Details` = `C:\Users\Administrator\AppData\Roaming\WPDNSE\svchost.exe`, an attacker binary

<p align="center">
<img src=screenshots/attacks-q22.png width="700">
</p>

Worth noting, this one looks like persistence and is not:

- `5:24:18 PM`
	- `TargetObject` = `HKLM\System\CurrentControlSet\Services\WdNisDrv\Start`, a Services key
	- `Details` = `DWORD (0x00000003)`, a number and not a path
	- `Image` = `C:\Windows\system32\services.exe`, a Windows binary

`WdNisDrv` is the Windows Defender Network Inspection driver and `Start = 3` means manual start. That is a Defender setting change, same thread as the 5:24:27 event. Defense Evasion, not Persistence.

<p align="center">
<img src=screenshots/attacks-q222.png width="700">
</p>

**Answer: Boot or Logon Autostart Execution, T1547**

---

### Q23. What sub-technique of the previous answer has the malware used? (Format: Sub Technique Name, TXXXX.xxx) (1 points)

The hive tells you the blast radius:

- **HKU Run key**, fires only when that one user logs on. Here the SID ends in `-500`, the built-in Administrator
- **HKLM Run key**, fires for every user on the box
- **HKLM Services**, runs at boot before anyone logs in, as SYSTEM

The attacker took the weakest of the three. Persistence sits in one user's hive and only triggers when Administrator logs in.

<p align="center">
<img src=screenshots/attacks-q23.png width="700">
</p>

**Answer: Registry Run Keys / Startup Folder, T1547.001**

---

### Q24. What's the name of the user on GitHub who created this malware? (Format: Username) (2 points)

Nothing in the logs names a malware family. Every filename and registry value in this incident is attacker-chosen, so the only identifier that carries outside the box is the hash.

I pulled the `Hashes` field from the Sysmon Event ID 1 records for both binaries:

- C:\Program Files\7-Zip\svchost.exe
- C:\Program Files\7-Zip\rundll33.exe

Searched both SHA256 values on VirusTotal, search only and no upload, and the Community tab has the answer.

<p align="center">
<img src=screenshots/attacks-q24.png width="700">
</p>
<p align="center">
<img src=screenshots/attacks-svchash.png width="700">
</p>

**Answer: ajayrandhawa**

---

## Attack Timeline

| Time (11/18/2022) | Event | Source |
|---|---|---|
| 5:14:08 PM | SSH brute force succeeds against Administrator | OpenSSH |
| 5:14:59 PM | Local account `sysadmin` created | Security 4720 |
| 5:15:33 PM | `sysadmin` added to Administrators | Security 4732 |
| 5:15:33 PM | Account `DRB` deleted | Security 4726 |
| 5:22:40 PM | `keylogger.rar` extracted by 7-Zip | Sysmon 1 |
| 5:22:47 PM | `rundll33.exe` created in `C:\Program Files\7-Zip\` | Sysmon 11 |
| 5:22:50 PM | `svchost.exe` created in `C:\Program Files\7-Zip\` | Sysmon 11 |
| 5:24:18 PM | `WdNisDrv\Start` set to 3, manual start | Sysmon 13 |
| 5:24:21 PM | `svchost.exe` copied into WPDNSE | Sysmon 11 |
| 5:24:21 PM | Run value `Windows Atapi x86_64 Driver` created | Sysmon 13 |
| 5:24:27 PM | `DisableRealtimeMonitoring` set | Sysmon 13 |
| 5:24:31 PM | `atapi.sys` written into WPDNSE | Sysmon 11 |
| 5:25:27 PM | `rundll33.exe` copied into WPDNSE | Sysmon 11 |
| 5:25:43 PM | Run value `Windows SCR Manager` created | Sysmon 13 |

---

## IOC Summary

| Type | Indicator | Context |
|---|---|---|
| IP | 192.168.1.33 | Source of the port scan in the firewall log |
| Port | 22/TCP | SSH, brute forced for initial access |
| Account | Administrator | Compromised 5:14:08 PM, SID ends in `-500` |
| Account | sysadmin | Created by attacker, added to Administrators |
| Account | DRB | Deleted by attacker |
| File | keylogger.rar | Archive dropped and extracted |
| File | rundll33.exe | Payload, typosquat of `rundll32.exe` |
| File | svchost.exe | Payload, masquerades as the System32 service host |
| File | atapi.sys | Written into WPDNSE, borrows a real driver name |
| Registry Value | `HKU\S-1-5-21-1380269439-2501990341-67692824-500\...\Run\Windows Atapi x86_64 Driver` | Autostart, points to `WPDNSE\svchost.exe` |
| Registry Value | `HKU\S-1-5-21-1380269439-2501990341-67692824-500\...\Run\Windows SCR Manager` | Autostart, points to `WPDNSE\rundll33.exe` |
| Registry Value | `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring` | Defender tampering |
| Registry Value | `HKLM\System\CurrentControlSet\Services\WdNisDrv\Start` | Defender network inspection driver set to manual |
| Folder Path | `C:\Users\Administrator\AppData\Roaming\WPDNSE` | Malware working directory |
| Folder Path | `C:\Program Files\7-Zip` | Extraction destination, staging |
| Attribution | ajayrandhawa | GitHub user, from the VirusTotal Community tab |

---

## Techniques Observed

| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | Active Scanning | T1595 |
| Initial Access | Valid Accounts | T1078 |
| Credential Access | Brute Force | T1110 |
| Persistence | Create Account | T1136 |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 |
| Collection | Input Capture: Keylogging | T1056.001 |
| Impact | Account Access Removal | T1531 |

---

## Notes and open questions

- **Useful netstat variants for next time.** `-a` gives listening ports, `-n` skips DNS resolution so the output is numeric and fast, and `-o` adds the owning process ID. `netstat -ano` is the combination worth reaching for on a live box, since the PID lets you pivot straight into Task Manager or a Sysmon Event ID 1 lookup.
- **The Q20 answer conflicts with the Q21 evidence.** The Run key at 5:24:21 PM was written by `C:\Program Files\7-Zip\svchost.exe`, the malware named directly in the `Image` field, and it is six seconds earlier than the 5:24:27 PM answer. By the plain wording of "first set by the malware," 5:24:21 PM is the better answer. The key says 5:24:27 PM.
- **Deprecated IDs in the Sysmon config.** `RuleName` values `T1060` and `T1089` are retired. Current mappings are `T1547.001` and `T1562.001`. The config on this box is built on an older ATT&CK version, so the RuleName is a pointer and not an answer.
- **The broker pattern.** Defender settings live under keys the malware cannot write. `MsMpEng.exe` and `services.exe` commit the write on its behalf, so a legitimate `Image` field does not rule out malicious causation. This broke my first read of Q20.
- **Not verified:** whether the SHA256 of `7-Zip\svchost.exe` matches `WPDNSE\svchost.exe`. Matching hashes would confirm the relocation was a true self-copy rather than a second dropped file.
- **Not checked:** the Windows Defender Operational log, Event IDs 1116 and 1117, which would carry a `Threat Name` field if Defender ever flagged the payload.
