---
title: Implementing a tiered AD
description:
date: 2026-02-11
summary:
categories:
  - Labs
  - AD Hardening
---
# Implement a Tiered AD Model

![featured.jpg](featured.jpg)
## What?
The tiered AD model categorises assets and accounts based on their criticality. Tiers are used to prevent attackers from moving vertically from lower-tier, more easily compromised assets to higher-tier, more critical assets. This is achieved by ensuring accounts only log on to systems within their assigned tier, preventing privileged credentials from being exposed on lower-tier systems.
![model.png](images/model.png "Model")
## How?
### Segment Tiers
#### Tier 0: 
Tier 0 contains the most critical identities and infrastructure in the Active Directory environment. *SpectreOps* has a [guide](https://specterops.github.io/TierZeroTable/) to help identify what should go in tier 0. Common assets include:
- Domain Controllers
- Domain Administrators
#### Tier 1: 
Tier 1 typically consists of less critical business resources, including:
- Application servers
- File servers
- Application administrators
#### Tier 2: 
Tier 2 is where end-users and devices are placed. This includes:
- Standard user accounts
- Staff workstations
### Enforce Segregation of Tiers
#### GPO:
Configure the following location - *Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment*, and configure these settings:

> [!info]- GPO
> - Deny access to this computer from the network
> - Deny log on as a batch job
> - Deny log on as a service
> - Deny log on locally
> - Deny log on through Terminal Services

##### Tier 0 GPO:
- Deny Tier 1 and 2 users from logging on
##### Tier 1 GPO:
- Deny Tier 0 and 2 users from logging on
![tier1.png](images/tier1.png "Tier 1")
##### Tier 2 GPO:
- Deny Tier 0 and 1 users from logging on
![tier2.png](images/tier2.png "Tier 2")
## Why?
### Reduce the blast radius of a compromise
#### The scenario 
Imagine a helpdesk administrator logs on to a user's workstation using their Domain Administrator account to troubleshoot an issue. Unknown to them, the workstation has already been compromised. The attacker later exploits a local privilege escalation vulnerability to obtain local administrator privileges.

When the administrator logs on, Windows stores credential material in LSASS to support the logon session. The attacker can dump this material using a tool such as _mimikatz_ and perform a pass-the-hash attack to authenticate as the Domain Administrator, potentially compromising the entire Active Directory environment.
## Pass the hash
### LSASS and NTLM
When a user authenticates, Windows creates a logon session in Local Security Authority Subsystem Service (LSASS) and maintains the appropriate credential material. LSASS stores credential material in memory, including NT LAN Manager (NTLM) hashes . The NTLM hash is a secret derived from the user's password. NTLM treats the possession of this hash as proof of identity.
### In action
**Step 1**. They use a free tool called *mimikatz* to dump the credential material in memory from LSASS.
![alert.png](images/dump.png "Dumping the hash")

**Step 2**.  The attacker passes the stolen NTLM hash to authenticate as the Domain Administrator without knowing the password, allowing them to authenticate as the Domain Administrator without knowing the password.
![alert.png](images/winrm.png "Passing the hash")






















