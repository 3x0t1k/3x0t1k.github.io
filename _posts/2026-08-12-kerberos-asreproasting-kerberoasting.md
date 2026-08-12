---
title: "Active Directory Penetration Testing: Kerberos, AS-REP Roasting & Kerberoasting Explained"
date: 2026-08-12
categories: [Active Directory, Credential Attacks]
tags: [kerberos, asreproasting, kerberoasting, ntlm, active-directory]
---

## Introduction

In [Active Directory Penetration Testing: How It All Starts](https://3x0t1k.github.io/posts/initial-enumeration-active-directory/) I mentioned both AS-REP Roasting and Kerberoasting as techniques for getting a first credential. But I glossed over the details — what they actually are, how they differ from each other, and how Kerberos authentication differs from NTLM in the first place.

This post fills in that gap. We'll cover how Kerberos actually works, why it's fundamentally different from NTLM, and then break down exactly what AS-REP Roasting and Kerberoasting each exploit — and why they're not the same attack even though they're often mentioned in the same breath.

---

## Kerberos vs NTLM — The Core Difference

**Kerberos** replaces NTLM as the default domain authentication protocol. The fundamental problem with NTLM is that even though a third party (the DC) ends up verifying the response, there's no cryptographic binding to *which* server the response was intended for. The DC just confirms "yes, this response matches this user's password hash" — it has no way to know or verify the destination. This is what enables NTLM relay: an attacker intercepts the response meant for one server and forwards it to a different one, and nothing in the protocol catches the switch.

Kerberos solves this differently. Instead of a challenge-response verified after the fact, you get a **ticket** upfront — issued once by the KDC. The service ticket is encrypted for the target service principal. Presenting that ticket to a different service won't work, because that service doesn't have the key needed to decrypt the ticket.

### NTLM Flow

```
1. Client → Server: "I want to authenticate"
2. Server → Client: sends a random challenge
3. Client: encrypts the challenge using a hash derived from the password
4. Client → Server: sends the response
5. Server → DC (Netlogon): "I received this response from this client, please verify it"
6. DC: has the user's password hash in AD, verifies the response on the server's behalf
7. DC → Server: "valid" or "invalid"
8. Server → Client: access granted or denied
```

The server itself never stores password hashes — it doesn't have the user's secret at all. Every single authentication requires the server to check back with the DC over Netlogon. Two parties talking, plus a third party (DC) verifying on request — but crucially, no cryptographic proof of *which* server the response was meant for. This is what enables NTLM relay: an attacker can capture the response meant for one server and forward it to a different server, and the DC has no way to detect that the destination changed — provided the target doesn't enforce additional protections like SMB signing or LDAP channel binding. We covered these protections in detail in the [LLMNR/NBT-NS poisoning post](https://3x0t1k.github.io/posts/llmnr-nbtns-poisoning/).

### Kerberos Flow

```
1. Client → KDC (AS): "I want a TGT" — sends username, realm, requested encryption types
2. KDC → Client: "Prove it first" — KDC_ERR_PREAUTH_REQUIRED
3. Client: encrypts the current timestamp using a key derived from the password
4. Client → KDC (AS): sends the encrypted timestamp (this is the AS-REQ)
5. KDC: decrypts the timestamp using its own copy of the password hash — if it decrypts cleanly, identity confirmed
6. KDC → Client: issues a TGT + session key (this is the AS-REP)
```

> **A quick technical note:** "password hash" is a simplification here. For RC4-HMAC (`etype 23`), the encryption key really is close to the NT hash — which is why you'll see hashcat mode 18200 and similar tools reference it directly. For AES (the modern default), the key is derived through a more involved process using the password plus a salt of username and realm — not simply the raw hash. The distinction matters more once you get into things like Golden Tickets, but for understanding AS-REP Roasting, "password-derived key" is close enough.

At this point the client has a TGT — but no access to anything yet. To reach a service:

```
7. Client → KDC (TGS): "I want a ticket for cifs/fileserver.corp.local" — sends the TGT + an authenticator (TGS-REQ)
8. KDC: decrypts the TGT with its own master secret, verifies the authenticator, looks up who owns that SPN
9. KDC → Client: issues a service ticket, encrypted with the target service account's password hash (TGS-REP)
10. Client → Service: presents the service ticket + authenticator (this is the AP-REQ)
11. Service: decrypts the ticket with its own secret, reads the PAC's authorization data — the user's SID, group memberships, and other attributes
12. Service grants or denies access based on its own permissions and ACLs — Kerberos itself doesn't decide authorization, only authentication
```

The service doesn't need to verify your password itself. It verifies the Kerberos ticket and authenticator, trusting that the KDC already confirmed your identity when it issued the ticket.

> **Worth being precise here:** the PAC doesn't grant access — it just states who you are (SID, groups). The service still checks that identity against its own ACLs to decide what you can actually touch. This distinction matters later when we talk about PAC forgery.

This is also the reason the service ticket **can't be presented to a different service** — it's encrypted for the target service account, and that other service simply doesn't have the key to decrypt it.

### The Analogy

Think of it like concert tickets.

**NTLM** is like a bouncer at the door who doesn't trust anyone on sight. Every time someone shows up, he calls the box office: "Did this person actually buy a ticket?" The box office checks its records and confirms — yes, valid purchase. But nobody ever checks *which door* the ticket was meant for. If someone intercepts your confirmation call and repeats it to a different bouncer at a different door, that bouncer has no way to know the confirmation wasn't meant for him.

**Kerberos** is like buying an actual physical ticket once, at the box office, with a specific section and seat printed on it. From then on, no phone calls. Every bouncer just looks at the ticket — it's self-contained proof, signed by the box office. And critically, a ticket for Section A physically won't get you through the door to Section B. It's not a matter of trust — the ticket itself is scoped to a specific destination.

That's the entire shift Kerberos makes: from "let me call and check" to "here's proof that's already scoped to exactly where I'm going."

---

## Quick Glossary

Before going further, here's the terminology worth having straight.

**KDC (Key Distribution Center)** — the trusted authority behind all of this. Conceptually, it provides three things: access to the principal database (every account and its secret), an **AS** (Authentication Server) function that issues TGTs, and a **TGS** (Ticket Granting Server) function that issues service tickets. In a Windows domain, these functions run on your Domain Controllers — the DC has the long-term secrets needed to authenticate domain principals and issue Kerberos tickets.

**TGT (Ticket Granting Ticket)** — your proof of identity, issued by the AS once you've verified who you are. From this point on, you don't type your password again — this is what gives Windows its single sign-on feel.

**Service** — anything a principal wants to reach: an SMB share, a database, a web app. Every service instance is identified by an SPN, typically in the format `class/instance:port` — e.g. `cifs/fileserver.corp.local`.

**Service Ticket** — obtained from the TGS by presenting your TGT. Scoped to one specific service. Also called a "TGS ticket" colloquially — same thing, different name.

**PAC (Privileged Attribute Certificate)** — authorization data bolted onto a ticket: your RID, group memberships, UAC flags. This is how a service gets your SID and group info without querying AD directly — faster, but it also means the PAC can be a target if you're thinking about privilege forgery (a topic for another post). PAC validation can be enforced if the service wants an extra check with the KDC instead of trusting it blindly.

Keep these five terms in mind — everything from here forward builds directly on them.

---

## A Closer Look at AS-REQ / AS-REP

Let's zoom into the very first exchange — the one that produces your TGT — because this is where AS-REP Roasting lives.

```
Client                          KDC                          Service
  |                               |                               |
  |------- 1. AS-REQ ----------->|                               |
  |<------ 2. AS-REP ------------|                               |
  |                               |                               |
  |------- 3. TGS-REQ ---------->|                               |
  |<------ 4. TGS-REP -----------|                               |
  |                               |                               |
  |------------------------- 5. AP-REQ ------------------------->|
  |<----------------------------------------- (optional PAC check) ---|
  |<------------------------- 6. AP-REP --------------------------|
```

Steps 1 and 2 are what we care about right now.

### What's Inside the AS-REP

The response the KDC sends back isn't one blob of encrypted data — it's layered, and different layers use different keys. This is the part that trips people up, so here's the structure broken down:

```
AS-REP
└── Ticket (TGT)
    └── EncTicketPart   [encrypted with the krbtgt account's long-term key]
        └── Logon Session Key

└── EncASRepPart         [encrypted with the principal's long-term key]
    └── Logon Session Key (same key, second copy)
```

Two separate containers, two separate keys:

- **The TGT itself (EncTicketPart)** is encrypted with the **krbtgt account's hash** — the KDC's own master secret. The client can never decrypt this. It doesn't need to; it just carries the TGT around and hands it back to the KDC later.
- **The EncASRepPart** is encrypted with the **requesting principal's own password hash**. This is the part the client *can* decrypt — using their own password — to pull out the logon session key they need for the next step.

### Why AS-REP Roasting Works

Look again at that second container — `EncASRepPart`. It's encrypted directly with the user's password hash. Under normal circumstances, this doesn't matter to an attacker: you'd need the password to decrypt it, and if you already had the password, you wouldn't need to attack anything.

But there's a catch. Recall from earlier: normally the client has to prove their identity before getting anything back — encrypting the current timestamp with a key derived from their password and sending that inside the AS-REQ. The KDC decrypts it with its own copy of the hash, and only then issues the AS-REP.

**If pre-authentication is disabled on an account**, that entire step is skipped. The AS-REQ we send doesn't need to contain an encrypted timestamp at all — there's nothing to prove. The KDC still processes the request for that specific principal, but it doesn't require the client to prove knowledge of the account's secret before issuing the AS-REP. Anyone — no credentials required — can do this for any account with pre-auth disabled.

And that AS-REP still contains `EncASRepPart`, encrypted with the target's password hash. You don't have the password. But you have ciphertext that was encrypted with it. Take it offline, run it through hashcat with a wordlist, and if the password is guessable — you now have it.

No authentication attempt against the account. No lockout risk. Just a single unauthenticated request and an offline crack.

### Is Pre-Authentication Enabled by Default?

Yes. Every account created in Active Directory has Kerberos pre-authentication enabled by default. This isn't something admins have to turn on — it's already there.

So why do you ever find accounts with it disabled? A few common reasons in real environments:

- **Legacy applications or devices** that don't support Kerberos pre-auth and only work with the older, weaker flow. Rather than fix the underlying issue, someone flips the setting to get things working.
- **Misconfiguration during account setup** — copying settings from a template account, or fat-fingering a checkbox in AD Users and Computers.
- **Third-party software requirements** — some legacy identity or authentication tools historically required pre-auth to be off to function.
- **Plain oversight** — nobody's actively removing this setting on purpose in most cases; it's usually inherited from an old configuration nobody revisited.

The setting itself lives on the account object as a User Account Control flag: `DONT_REQ_PREAUTH`. If that flag is set, the account is AS-REP roastable — no matter how strong the password is, you get the ciphertext for free.

That matters because it's rarely intentional — when you find it, it's often on an account nobody has looked at in years.

### Putting It Into Practice

This is exactly the flow we walked through in the [first post in this series](https://3x0t1k.github.io/posts/initial-enumeration-active-directory/). Quick recap of how it connects:

We built a username list from OSINT — LinkedIn, company website, PDF metadata — and validated it with Kerbrute:

```bash
kerbrute userenum -d corp.local --dc 192.168.1.10 usernames.txt
```

That gave us a clean list of confirmed valid accounts — no guessing, no noise from usernames that don't exist. Now that we understand *why* AS-REP Roasting works, running it against that list makes a lot more sense:

```bash
impacket-GetNPUsers corp.local/ -no-pass -usersfile valid_users.txt -dc-ip 192.168.1.10
```

What's actually happening here: for every username in the list, Impacket sends an AS-REQ with no encrypted timestamp — no pre-auth proof at all. Most accounts will respond with `KDC_ERR_PREAUTH_REQUIRED`, because pre-auth is enabled and they expect that timestamp. Impacket just moves on to the next username.

But if it hits an account with `DONT_REQ_PREAUTH` set, the KDC doesn't ask for anything — it just returns the full AS-REP. That's the `EncASRepPart` we talked about, encrypted with that account's password hash:

```
$krb5asrep$23$r.nilson@CORP.LOCAL:a3f8c2d1e9b87f4c...
```

Take it offline:

```bash
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

If the account uses AES instead of RC4, the hash format and hashcat mode change accordingly:

```bash
# AES128
hashcat -m 19600 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# AES256
hashcat -m 19700 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

> **Note:** The `$23$` in the hash is the etype — 23 means RC4-HMAC, which is why mode 18200 works. If you see `$17$` or `$18$` instead, that's AES128 or AES256, and you need mode 19600 or 19700 respectively. Impacket will output whichever etype the account actually uses — check the hash format before picking a hashcat mode, don't just default to 18200 out of habit.

If the password cracks — you now understand exactly why. It wasn't luck, and it wasn't a vulnerability in the traditional sense. It's a single unauthenticated request that skipped a verification step that most accounts don't skip. Once you see the AS-REQ/AS-REP structure, this attack stops being "a command someone told you to run" and becomes something you could explain to a client in the debrief.

> **Quick reminder on honeypots:** we covered this in detail in the [first post](https://3x0t1k.github.io/posts/initial-enumeration-active-directory/) — defenders sometimes set up decoy accounts with pre-auth deliberately disabled just to catch AS-REP Roasting attempts. Requesting a ticket for one fires an alert instantly. Checking `lastLogon` and `logonCount` can give some context here, but they aren't a reliable indicator on their own — a real but dormant account can look just as inactive as a honeypot. Treat this as one signal among several, not a filter you can trust blindly.

---

## Kerberoasting

If AS-REP Roasting didn't pan out — or even if it did and we already have a set of credentials — we can go after Kerberoasting instead. The logic here is straightforward once you've seen the AS-REQ/AS-REP flow.

With a valid username and password, we go to the KDC and get a TGT from the AS — completely normal, expected behavior. With that TGT, we go to the TGS and request a service ticket for whatever service interests us. That's the part worth zooming into.

### Why the Service Trusts the Ticket

The TGS-REP looks a lot like the AS-REP structurally — layered, different keys for different parts:

```
TGS-REP
└── Ticket (Service Ticket)
    └── EncTicketPart    [encrypted with the service account's long-term key]
        └── Service Session Key

└── EncTGSRepPart         [encrypted with our Logon Session Key]
    └── Service Session Key (same key, second copy)
```

Here's the logic behind why this works as a trust mechanism: the TGS encrypts part of that ticket using the **service account's long-term key** — because the service is the only other party besides the KDC that has that key. When we hand the ticket to the service, the service decrypts it with its own key. If decryption succeeds, the service knows the ticket had to come from something that also had that key — which is the KDC, since we certainly don't.

That's the whole chain of trust: we never touched the service account's secret directly, but the fact that we're holding a ticket that decrypts correctly is proof enough that the KDC vouched for us.

From there, the service reads the PAC — figures out who we are — and checks that identity against its own ACLs to decide what we're allowed to touch.

### Why Kerberoasting Is Possible at All

Now here's the part that makes this attackable: **that EncTicketPart is encrypted with the service account's password hash — and Kerberos lets any authenticated user request a service ticket for any SPN in the domain.** There's no special privilege check at request time. You just need to be authenticated, period.

This is why Kerberoasting isn't really a misconfiguration in the way AS-REP Roasting is. Pre-auth being disabled is a mistake someone made. Service accounts having SPNs and Kerberos allowing anyone to request tickets for them — that's just how the protocol is designed to work. The only real mitigation is making sure service account passwords are strong enough that offline cracking doesn't succeed.

### Putting It Into Practice

So we request a ticket for a service we have no intention of actually using — say, a SQL service running under `svc_sql`. We get back a TGS-REP containing a ticket encrypted with `svc_sql`'s password. We can't decrypt it (we don't know that password) — but we don't need to. We take it offline and crack it exactly the way we cracked the AS-REP earlier.

In practice this looks like:

```bash
impacket-GetUserSPNs corp.local/r.nilson:'Winter2025!' -dc-ip 192.168.1.10 -request
```

This automatically finds every account in the domain with an SPN set, requests a service ticket for each one, and outputs the crackable portion of each ticket:

```
ServicePrincipalName          Name          MemberOf  PasswordLastSet
----------------------------  ------------  --------  -------------------
MSSQLSvc/sql01.corp.local     svc_sql                 2023-04-12 09:14:22

$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local*$a3f8c2...
```

Crack it offline:

```bash
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

Same `$23$` etype logic as before — if the service account uses AES instead of RC4, switch to mode 19600 or 19700 depending on AES128 or AES256.

### Opsec Notes for Both Techniques

A few detection-relevant details worth knowing before running either attack in a real engagement:

**Event IDs.** AS requests are logged as Event ID **4768**, TGS requests as **4769** — when Kerberos auditing is enabled on the DC. Neither event alone means an attack; normal authentication generates plenty of both. What stands out is the pattern: a single account requesting a burst of these in a short window, especially across many different SPNs, is the kind of anomaly SOC rules are built to catch.

**RC4 can stand out.** Some tooling has historically favored requesting RC4-encrypted tickets because they're easier to crack, though this varies by tool version and configuration. Modern Windows environments use AES for Kerberos by default — so an RC4 ticket request in an AES-standard environment is a downgrade worth noticing, and some detection rules flag exactly that.

**Dummy SPNs are a known defense.** As covered earlier, defenders can plant decoy accounts with SPNs that don't map to any actual running service. Since nothing real is behind them, there's never a legitimate reason for a TGS-REQ/REP to hit that SPN — so when one does, it's about as close to a guaranteed Kerberoasting signal as detection gets. This is the whole reason enumerate-then-target beats spraying every SPN in the domain: it's not just quieter, it avoids walking straight into a trap built specifically to catch the lazy version of this attack.

### Targeting Specific Accounts, Not Everything

Running `-request` blindly asks for tickets on every SPN in the domain at once — convenient, but loud. You're generating TGS-REQ traffic for every service account in one go.

A more careful approach: enumerate SPNs first without requesting anything, review the list, then go after specific accounts:

```bash
# Enumerate SPNs only, no ticket requests yet
impacket-GetUserSPNs corp.local/r.nilson:'Winter2025!' -dc-ip 192.168.1.10
```

Once you know which accounts are worth targeting:

```bash
impacket-GetUserSPNs corp.local/r.nilson:'Winter2025!' -dc-ip 192.168.1.10 -request-user svc_sql
```

> **SPN honeypots exist too.** Same idea as the AS-REP honeypot accounts covered earlier — defenders sometimes set an SPN on a decoy account purely to catch Kerberoasting attempts. Requesting a ticket for it triggers an alert immediately. Unlike regular user accounts, `lastLogon`/`logonCount` isn't a reliable signal here — legitimate service accounts often don't log on interactively at all, so a low count doesn't necessarily mean honeypot. Better signals to check: `whenCreated` (a suspiciously recent account is worth a second look), `pwdLastSet` (a password that's never been rotated since account creation on an otherwise "important" service), and simply whether the SPN makes sense for a real service running somewhere on the network. There's no single reliable indicator — this is judgment based on the environment, not a checklist.
