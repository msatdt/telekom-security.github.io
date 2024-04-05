---
title: Unquoted Service Path exploit in Fortinet FortiClient
description: Unquoted Service Path exploit in FortiClient (CVE-2019-17658)
header: Unquoted Service Path exploit in Fortinet FortiClient
tags: ['advisories']
cwes: ['Unquoted Search Path or Element (CWE-428)']
affected_product: 'Fortinet FortiClient'
vulnerability_release_date: '2020-03-12'
---
FortiClient for Windows prior to 6.2.3 is vulnerable to an unquoted service path vulnerability (CVE-2019-17658). That may allow an attacker to gain elevated privileges via the FortiClientConsole executable service path.

<!--more-->

Base Score: 9.8

Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

### Affected Component
FortiClient FortiTray

### Affected Products
FortiClient for Windows Versions 6.2.2 and below.

### Patched in Version
FortiClient for Windows version 6.2.3 or above.

### PoC

Private: The PoC is not published because it's obvious. 

### Links:
- https://nvd.nist.gov/vuln/detail/CVE-2019-17658
- https://fortiguard.com/psirt/FG-IR-19-281

**Michael Wollner** ([@Ibonok](https://github.com/Ibonok))
