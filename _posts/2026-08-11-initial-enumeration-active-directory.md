---
title: "Initial Enumeration in Active Directory Environment"
date: 2026-08-11
categories: [Active Directory, Enumeration]
tags: [active-directory, enumeration, recon, nmap, osint, linkedin2username, exiftool]
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

### Step 1 — Getting Valid Usernames

Before throwing anything at the DC, we need a list of valid usernames. Spraying garbage at Kerberos is noisy and inefficient — and in a real engagement, you're not there to trigger lockouts or alerts.

The first thing I do in a real pentest is **OSINT**. And the best source of corporate usernames is sitting in plain sight.

#### Understanding the Login Format First

Here's something people skip and then waste hours on: even if you have a list of real employee names, you can't do anything useful with it until you know how the company formats their logins.

Take a name like **Rick Nilson**. His AD username could be any of these:

```
rick.nilson
r.nilson
rnilson
nilson.rick
nilsonr
rick
```

Without knowing the format, you're generating five to ten variations per person and spraying all of them — which is slow, noisy, and likely to trigger lockouts. So before building any list, figure out the format first.

#### LinkedIn — Names and Context

LinkedIn is your primary source of employee names. People publicly list their employer, their role, their full name. For a pentester that's a goldmine — but names alone aren't enough, remember the format problem above.

**linkedin2username** scrapes a company's LinkedIn page and generates username lists in every common format at once:

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

> **Note:** Requires a LinkedIn account. More connections = better results. LinkedIn caps at 1000 employees — use `--geoblast` or `--keywords` to bypass.

But you still have multiple format files and don't know which one is correct. That's where the next steps come in.

#### Company Website — Finding the Format

The company's own website often gives away the login format directly. Sales teams, department heads, and managers frequently leave their personal corporate email addresses for client contact. One email address tells you everything:

If you find `r.nilson@corp.com` on a contact page — the format is `f.last`. Done. Now go back to your linkedin2username output, pick `f.last.txt`, and you have one clean targeted list instead of five noisy ones.

Medium and larger companies also often publish a management board or leadership page. Check those first — high-value targets with confirmed names and sometimes confirmed email formats.

#### Google Dorks & PDF Metadata

Another underrated source. Companies publish PDFs constantly — reports, presentations, brochures. Those documents often contain metadata including the username of whoever created or saved the file.

```bash
# Find PDFs published by the target
site:corp.com filetype:pdf
```

Download a few, then pull the metadata:

```bash
exiftool document.pdf
```

Output:

```
File Name         : annual_report_2025.pdf
Author            : r.nilson
Creator           : Microsoft Word
Producer          : Adobe PDF
```

Username format confirmed. And you got a specific username as a bonus.

#### Building the Final List

Once you know the format, generate a clean list. If you collected names manually (from LinkedIn browsing, the company website, or other sources), **username-anarchy** converts them:

```bash
git clone https://github.com/urbanadventurer/username-anarchy
./username-anarchy --input-file names.txt --select-format first.last > usernames.txt
```

Or a simple bash one-liner for `f.last` format:

```bash
while IFS= read -r line; do
  first=$(echo "$line" | awk '{print tolower(substr($1,1,1))}')
  last=$(echo "$line" | awk '{print tolower($2)}')
  echo "${first}.${last}@corp.local"
done < names.txt
```

For broader OSINT — emails, subdomains, exposed hosts — **theHarvester** is in Kali by default and still relevant:

```bash
theHarvester -d corp.com -b google,bing,linkedin -l 500
```

It won't replace LinkedIn scraping for usernames but it's useful for confirming the email format from exposed addresses and finding other attack surface.
