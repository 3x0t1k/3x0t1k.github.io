---
title: "Active Directory Penetration Testing: How It All Starts (Enumeration & First Credentials)"
date: 2026-08-11
categories: [Active Directory, Enumeration]
tags: [active-directory, enumeration, recon, nmap, osint, responder, ldap, smb]
---

## Introduction

If we're talking about Active Directory pentesting, we're already inside the client's internal network. (Not a victim's network — that would be illegal, and also a very different kind of blog post.)

Most of the time, in my personal experience, the foothold machine is a Linux host. That's because the most common path in is through a poorly written web application running on Apache or Nginx. Occasionally it's a broken app on IIS — but in my experience, that's less frequent.

Either way, once we have a shell, the first question is always the same: *where are we, and what's around us?*

Enumeration is an iterative process. It covers multiple layers — the host itself, the network, users, services, configurations. And here's the most important thing I can tell you as a reader:

> **If you're stuck and can't move forward — go back. Enumerate again. Something is always there.**

---

## The General Flow

The typical path from initial access to Active Directory looks something like this:

```
Broken web app
    → Shell obtained
        → Privilege escalation
            → Persistence
                → Local recon (credentials, config files, etc.)
                    → Pivoting
                        → Network recon
                            → AD identified
```

At some point during network recon, you'll spot a machine that looks different from the rest. The port layout gives it away immediately.

---

## Recognizing a Domain Controller

A Domain Controller has a very recognizable fingerprint. When you run an Nmap scan against a host and see something like this — you know exactly what you're looking at:

```
Nmap scan report for 192.168.1.10
Host is up (0.039s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: corp.local)
445/tcp   open  microsoft-ds  Windows Server microsoft-ds (workgroup: CORP)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: corp.local)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
```

The key ports to recognize:

| Port | Service | Why it matters |
|------|---------|----------------|
| 88   | Kerberos | Authentication — this is a DC |
| 389  | LDAP | Directory services |
| 636  | LDAPS | LDAP over SSL |
| 3268 | Global Catalog | Forest-wide LDAP |
| 445  | SMB | File sharing, lateral movement |
| 5985 | WinRM | Remote management — useful if you get creds |

The LDAP banner will usually give you the domain name directly:

```
389/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: corp.local)
```

You now know the domain. You know there's a DC. Time to start pulling information.

---

## The Goal

Before we dive into tools and techniques, let's be clear about one thing:

**Our objective is to authenticate to Active Directory.**

Everything we do at this stage serves that single goal. Keep it in mind — it'll help you stay focused when you're deep in enumeration and losing the thread.

Now, how you approach this depends entirely on what you have in hand. Two scenarios:

1. **You have credentials** — a username, a password, a hash, anything that can authenticate you.
2. **You have nothing** — no creds, no accounts, just a shell on a machine inside the network.

---

## The Analogy

Think of it like building a wooden house.

- **Goal** — build the house (authenticate to AD)
- **Material** — wood and nails (credentials in any form)
- **Tool** — a hammer (something that lets you use those credentials — Kerbrute, Impacket, NetExec, etc.)

You can have the best hammer in the world. Without material, you're not building anything. So the first task is always finding material — credentials in any shape or form that lets us authenticate.

---

## Part 1: No Credentials

### Step 1 — Low Hanging Fruit

Before doing anything noisy, check what the network is already giving away for free. Misconfigured services are extremely common in real environments and can hand you a username list — or even credentials — without a single authentication attempt.

#### LDAP Anonymous Bind

Some DCs still allow anonymous LDAP queries. This means you can pull users, groups, and other directory objects without any credentials at all.

```bash
# Check if anonymous bind is allowed
ldapsearch -x -H ldap://192.168.1.10 -b "DC=corp,DC=local"

# Pull all users
ldapsearch -x -H ldap://192.168.1.10 -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName
```

If this works — you already have a user list. Skip the OSINT section and move straight to password attacks.

#### SMB Null Sessions

Same idea on SMB. Null sessions allow unauthenticated access to certain SMB resources and can expose user and group information.

```bash
# Check for null session
nxc smb 192.168.1.0/24 -u '' -p ''
nxc smb 192.168.1.0/24 -u 'guest' -p ''

# Enumerate shares
nxc smb 192.168.1.10 -u '' -p '' --shares

# Spider shares for interesting files
nxc smb 192.168.1.10 -u '' -p '' -M spider_plus
```

People leave things in file shares. Credentials in scripts, passwords in Excel files, config files with plaintext secrets. It happens constantly in real environments.

#### Other Services — FTP, Web, Databases

Don't tunnel vision on AD. Scan the full network and check everything:

```bash
# Check FTP anonymous login
nxc ftp 192.168.1.0/24 -u 'anonymous' -p 'anonymous'
```

Any service that exposes files or data without authentication is worth checking. Web applications running internally, exposed databases, unprotected network shares — all potential sources of credentials or usernames.

#### Critical Vulnerabilities — Don't Skip Vuln Scanning

While you're at it — don't forget to check for known critical vulnerabilities on the hosts you discover. A classic example is **MS17-010 (EternalBlue)**, which exploits a vulnerability in SMBv1 and gives you SYSTEM-level access without any credentials at all.

```bash
nxc smb 192.168.1.0/24 -M ms17-010
```

If a domain-joined machine is vulnerable, you land as SYSTEM on that host. From there you can dump local credentials and machine account hashes:

```bash
impacket-secretsdump LOCAL -target-ip 192.168.1.20
```

Since the machine is joined to the domain, you can use the machine account to query AD — which means you're no longer operating blind. EternalBlue is old but still found in real environments, especially on legacy infrastructure. Always check.

> Obviously, exploiting production systems carries risk. Coordinate with your client and know your scope before pulling the trigger on anything this impactful.

---

### Step 2 — Responder (Passive Credential Capture)

If low hanging fruit didn't produce anything useful, the next step is to listen. Since we're on a Linux host with port 445 available, we can run Responder and passively capture authentication material from the network.

```bash
responder -I eth0 -wf
```

Responder poisons LLMNR, NBT-NS, and MDNS responses — when a machine on the network tries to resolve a hostname that doesn't exist in DNS, Responder answers and captures the authentication attempt. The result is an NTLMv2 hash.

```
[SMB] NTLMv2-SSP Hash : john.doe::CORP:a3f8c2d1e9b8...
```

Take it offline:

```bash
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

If it cracks — you have a valid credential. If not, the hash may still be useful for relay attacks.

> Capturing hashes is just the beginning. LLMNR/NBT-NS poisoning, NTLMv2 relay, and coercion techniques are covered in depth in a separate post.

---

### Step 3 — Building a Valid Username List (OSINT)

If neither passive capture nor unauthenticated access produced results, we need to build a username list from scratch and start actively enumerating. But before generating any list, there's something critical to figure out first.

#### Understanding the Login Format

Even with a list of real employee names, you can't do anything useful until you know how the company formats their logins.

Take **Rick Nilson**. His AD username could be any of these:

```
rick.nilson
r.nilson
rnilson
nilson.rick
nilsonr
rick
```

Without knowing the format, you're generating five to ten variations per person and throwing all of them at the DC — noisy, slow, and likely to trigger lockouts. Figure out the format first, then build one clean list.

Also worth noting: not every company follows standard patterns. In real engagements I've come across formats like `XXX000` — completely custom schemes that no wordlist or tool will guess. When you find a confirmed username through any means, study it carefully before assuming the format.

#### LinkedIn — Employee Names at Scale

LinkedIn gives you employee names in bulk. **linkedin2username** scrapes a company's LinkedIn and generates lists in every common format simultaneously:

```bash
git clone https://github.com/initstring/linkedin2username
cd linkedin2username
uv sync
uv run python linkedin2username.py -c target-company -n corp.local
```

Output:

```
first.last.txt   → rick.nilson@corp.local
f.last.txt       → r.nilson@corp.local
flast.txt        → rnilson@corp.local
firstl.txt       → ricks@corp.local
lastf.txt        → nilsonr@corp.local
```

Once you've confirmed the format from the company website, pick the right file. One clean list instead of five noisy ones.

> **Note:** Requires a LinkedIn account. More connections = better results. Use `--geoblast` or `--keywords` to bypass the 1000 employee cap.

#### Company Website — Finding the Format

The company's own website often gives away the login format directly. Sales teams, department heads, and managers frequently leave their personal corporate email addresses for client contact. One email address tells you everything:

If you find `r.nilson@corp.com` on a contact page — the format is `f.last`. Done. Now go back to your linkedin2username output, pick `f.last.txt`, and you have one clean targeted list instead of five noisy ones.

Medium and larger companies also often publish a management board or leadership page. Check those first — high-value targets with confirmed names and sometimes confirmed email formats.

#### Google Dorks & PDF Metadata

Published documents are another underrated source. Companies put PDFs on their websites constantly — reports, presentations, brochures. Those PDFs often contain metadata, and that metadata sometimes includes the username of whoever created or saved the file.

```bash
# Google dork to find PDFs from a specific domain
site:corp.com filetype:pdf
```

Download a few, then extract metadata:

```bash
exiftool document.pdf
```

Output might look like this:

```
File Name         : annual_report_2025.pdf
Author            : r.nilson
Creator           : Microsoft Word
Producer          : Adobe PDF
```

There's your username format confirmed, and potentially a specific username as a bonus.

#### theHarvester

For broader OSINT — emails, subdomains, hosts — **theHarvester** is built into Kali and still relevant:

```bash
theHarvester -d corp.com -b google,bing,linkedin -l 500
```

It won't replace LinkedIn scraping for usernames, but it's useful for finding exposed email addresses and confirming the email format before you start enumerating.

#### Generating the Final List

Once you know the format, **username-anarchy** converts raw names to the right pattern:

```bash
git clone https://github.com/urbanadventurer/username-anarchy
./username-anarchy --input-file names.txt --select-format first.last > usernames.txt
```

Or a simple bash one-liner for `f.last`:

```bash
while IFS= read -r line; do
  first=$(echo "$line" | awk '{print tolower(substr($1,1,1))}')
  last=$(echo "$line" | awk '{print tolower($2)}')
  echo "${first}.${last}@corp.local"
done < names.txt
```
