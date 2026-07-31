---
title: Phishy v1
module: Security Operations
path: Security Operations
platform: Blue Team Labs Online
tags: [phishing, phishing-kit, threat-intel, osint, T1566, T1598]
status: complete
date: 2026-07-30
date_completed: 2026-07-30
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

- Started with the page source and found the login form
- The form posts to `jeff.php` over POST, and the `name=` values are the keys the handler will receive

```
<input type="email" name="userrr" placeholder="Email ID" required ><br>
<input type="password" name="passss" placeholder="Email Password" required ><br>
```

- `placeholder=` is grey hint text that only ever lives in the browser, `name=` is what travels to the server
- Whatever the victim types gets mailed out by `jeff.php`
- `$recipient` is the attacker's inbox, the From header is spoofed so the log mail looks like it came from somewhere else

```
$recipient = "boris.smets@tfl-uk.co";
$subject = "Result!!!";
$headers = "From: Result <phishing@phishing.com>";
```

- Then checked securedocument.net itself, and the page is down: SORRY! If you are the owner of this website, please contact your hosting provider: webmaster@example.com
- Inspecting that page puts the answer at the very top, in an HTML comment the copier left behind
- `<!-- Mirrored from 61.221.12.26/cgi-sys/defaultwebpage.cgi by HTTrack Website Copier/3.x [XR&CO'2014], Thu, 18 Feb 2021 12:43:50 GMT -->`

<p align="center">
<img src=screenshots/phishy-cgi.png width="700">
</p>

**Answer: 61.221.12.26/cgi-sys/defaultwebpage.cgi, HTTrack**

---

### 2. What is the full URL of the background image which is on the phishing landing page?

- Fastest route is right-click and open the image in a new tab, which puts the full path in the address bar

<p align="center">
<img src=screenshots/phishy-image.png width="700">
</p>

**Answer: http://securedocument.net/secure/L0GIN/protected/login/portal/axCBhIt.png**

---

### 3. What is the name of the php page which will process the stolen credentials?

- Already noted at the start of the investigation from the form's `action=` value
- Same file holds the exfil address: boris.smets@tfl-uk.co

<p align="center">
<img src=screenshots/phishy-jeff.png width="700">
</p>

**Answer: jeff.php**

---

### 4. What is the SHA256 of the phishing kit in ZIP format? (Provide the last 6 characters)

- Question 1 named the tool outright: HTTrack Website Copier/3.x [XR&CO'2014]
- HTTrack is a website copier, so nothing on this site is what it appears to be
- That means the sub pages are worth walking, so I worked backward one directory at a time

    - http://securedocument.net/secure/L0GIN/protected/login/portal
      - http://securedocument.net/secure/L0GIN/protected/login
        - http://securedocument.net/secure/L0GIN/protected
          - http://securedocument.net/secure/L0GIN
            - http://securedocument.net/secure/

- Each layer revealed more in the page source
- http://securedocument.net/secure/ should have been a red flag right away, an exposed directory listing sitting on a path called "secure"
- The kit was still sitting there in the listing, never cleaned up after deployment

```
<a href="0ff1cePh1sh.zip">0ff1cePh1sh.zip</a>
```

- Hashed the archive exactly as downloaded, since extracting and re-zipping produces a different hash

```
sha256sum 0ff1cePh1sh.zip
```

<p align="center">
<img src=screenshots/phishy-sha.png width="700">
</p>

**Answer: fa5b48**

---

### 5. What email address is setup to receive the phishing credential logs?

- Noted this one twice already, which is exactly why the running case notes are worth keeping
- It is the `$recipient` value in `jeff.php`, the inbox every set of stolen credentials gets mailed to

**Answer: boris.smets@tfl-uk.co**

---

### 6. What is the function called to produce the PHP variable which appears in the index1.html URL?

- Instead of fighting the browser, unzipped the kit and grepped it directly

```
unzip 0ff1cePh1sh.zip
```

- The archive carries its own `Desktop/` path inside it, so everything landed under `Desktop/0ff1cePh1sh/protected/login/portal/`
- That directory structure is the operator's own local layout, which is attribution material on its own

```
grep -rn 'index1' 0ff1cePh1sh
```

- The hit is in `index.html` line 3, and it is JavaScript rather than PHP, which is why grepping the PHP for it goes nowhere
- `window.location='index1.html?'+new Date().getTime();`
- `new Date()` builds a date object, `.getTime()` returns milliseconds since the Unix epoch
- The timestamp is a cache buster, so every victim gets a fresh copy of `index1.html` and never a stale cached one
- Side effect worth noting: each submission produces a distinct 13 digit query string, which is a shape you can pivot on in proxy logs

<p align="center">
<img src=screenshots/phishy-time.png width="700">
</p>

**Answer: getTime()**

---

### 7. What is the domain of the website which should appear once credentials are entered?

- The bottom of `jeff.php` handles the forward, sending the victim somewhere legitimate right after the credentials are mailed off

```
<script language=javascript>
window.location='https://www.office.com/';
</script>
```

<p align="center">
<img src=screenshots/phishy-office.png width="700">
</p>

**Answer: office.com**

---

### 8. There is an error in this phishing kit. What variable name is wrong causing the phishing site to break? (Enter any of 4 potential answers)

- This one was hard for me, I did not grasp what it was asking until I researched it
- The break is a key mismatch between two files in the kit
- `index1.html` sends the keys `userrr` and `passss`
- `jeff.php` reads the keys `user1` and `pass1`

```
$message .= "User : ".$_POST['user1']."\n";
$message .= "Password: " .$_POST['pass1']."\n";
```

- Neither key lines up, so both reads come back empty and the credential email arrives blank
- What the victim types never matters here: typing fills the value, while the key is fixed by `name=` in the HTML and the victim cannot change it
- Four answers are accepted because the fix could go on either side, renaming in the HTML or renaming in the PHP
- Inline note: line 14 of `jeff.php` also reads `$_POST['eMailAdd']`, a key the form never sends at all, which is a separate bug from the graded four

<p align="center">
<img src=screenshots/phishy-wrongcode.png width="700">
</p>

**Answer: user1**

---

## Closing Notes

- Phishing kits carry their own attribution: the exfil address, the mirroring tool's signature, and the redirect target all sit in the source
- Reading a kit end to end beats answering questions one at a time -- the credential handler, the config, and the redirect explain each other
- A broken variable in a live kit is a reminder that operators ship bugs too, and those bugs are a fingerprint
