---
title: "Initial Enumeration in Active Directory Environment"
date: 2026-08-11
categories: [Active Directory, Enumeration]
tags: [active-directory, enumeration, recon, nmap, bloodhound]
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
