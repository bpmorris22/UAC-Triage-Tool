# UAC Triage Tool

A single-file Windows **HTA** that triages the output of [**UAC** (Unix-like Artifacts Collector)](https://github.com/tclahr/uac) — the tarball a responder collects from a Linux, macOS, \*BSD, Solaris or ESXi host. Point it at the `uac-<host>-<os>-<timestamp>.tar.gz` (or an already-extracted folder); it extracts the archive with Windows' built-in `tar.exe` and turns the plain-text process, network, logon and filesystem-timeline artifacts into scored, searchable triage views.

**It never runs UAC and never touches the target host.** There is no SSH, no remote anything, and no parser engine to install — the tarball is the entire interface.

![Overview tab](screenshots/overview.png)

> All screenshots use **synthetic demo data** (fictional host `web01`, documentation IPs).

## Why

UAC is excellent at *collecting* a Unix-like host. This tool is about *reading the result fast on a Windows analysis box* — surfacing the handful of rows that matter (a hidden process, a brute-forced login, a malicious cron job) out of a capture with tens of thousands of files, and doing it with no dependencies beyond the copy of `tar.exe` already on every modern Windows machine.

## Quick start

1. **On the \*nix host**, download UAC from [its releases](https://github.com/tclahr/uac/releases) and run it from its own folder:
   ```
   cd uac-3.3.0
   ./uac -p ir_triage /tmp
   ```
2. **Copy** the resulting `uac-<host>-<os>-<ts>.tar.gz` to a Windows box.
3. **Open** `UAC-Triage-Tool.hta`, drop the tarball path in (or **Browse…**), confirm the target hostname, and click **Analyze capture**.
4. **Read Overview first**, then work the tabs. Anything scored **≥ 3** is flagged suspicious.

## What it shows

Eight tabs:

| Tab | Built from | Highlights |
|---|---|---|
| **Overview** | `uac.log`, `uptime`, `date` | Run metadata incl. **boot time / uptime**, per-dataset stat cards, cross-dataset **Top findings**, scored **Persistence findings**, package activity (with attribution), containers, integrity/journal-gap summaries, and a presence inventory with "open folder" links |
| **Processes** | `ps -ef` + `/proc` maps | Hidden-from-ps processes are **synthesized** into rows; deleted-binary and kernel-thread-masquerade detection |
| **Network** | `ss` / `netstat` | External connections; links each socket to its owning process |
| **Logons** | `auth.log` (**ISO-8601 + classic syslog**), **wtmp/btmp/lastlog binaries**, `last`, `lastb` | SSH accepted/failed, **sudo / pkexec / pam sessions / account changes / su**, per-account lastlog, spray + **BRUTEWIN** detection, service-account-login and new-login-account flags |
| **Timeline** | TSK bodyfile | Full filesystem MAC-times; case-window filterable; capped for MFT-scale captures |
| **Logs** | journal, syslog, kern.log, sysstat, cloud-init | **Journal coverage + gap/generation-change detection**, **log-integrity** checks, **syslog service inventory**, notable events (OOM, promiscuous, USB, new units), **sar** CPU summary, **cloud-init** provisioning baseline |
| **IOC hits** | tree sweep + `hash_executables` | Line-scan of the whole tree, **plus** SHA1 matches against on-disk (dormant) executables |
| **Inventory** | ~50 key artifacts | Present/absent map across nine categories, each with an "open folder" link to the raw file |

Rotated **`.gz` logs** under `[root]/var/log` are inflated at parse time, so weeks of rotated auth/syslog/dpkg/apt history are included automatically — usually where a logs-only capture's real activity lives.

![Logons tab — a brute-force that succeeded](screenshots/logon.png)

## Scoring

Rows are scored with additive rules; **≥ 3 is suspicious**. Highlights: IOC / SHA1 hit (+3), executable under a temp/ram path (+2), hidden path component (+1), interactive/decoder shell one-liner (+2), kernel-thread masquerade (+2), running binary deleted from disk (+3), PID hidden from ps (+3), external/root logins, **brute-force-then-success** (+3), **service account with an interactive login** (+3), **new account with a login shell** (+4), privilege escalation (sudo/pkexec) running a temp/shell command (+2), a populated `ld.so.preload` (+3), a **journal gap with a generation change** (integrity, high sev), suspicious package installs (nmap/socat/xmrig/…), and more. Full reference in the manual.

## Command line

```
mshta "UAC-Triage-Tool.hta" "<archiveOrFolder>" ["<outDir>"] [/auto] [/from:yyyy-MM-dd] [/to:yyyy-MM-dd]
```

`/auto` extracts and parses immediately; `/from` `/to` set a UTC case window (filters the timeline, logons and package activity — **never** affects scoring). A shared `IOC.txt` next to the app is auto-merged at launch.

## Full manual

See **[`UAC-Triage-Manual.html`](UAC-Triage-Manual.html)** — a self-contained field manual with a screenshot of every tab, the complete scoring reference, a triage methodology, and the notes/limitations.

## Notes

- Windows' `tar.exe` (bsdtar) **returns exit code 1** on UAC tarballs because they contain Unix symlinks Windows can't create — this is expected; success is judged by `uac.log` appearing, and the regular files all extract.
- Encrypted zips (UAC `-P`) can't be opened by bsdtar — extract with 7-Zip first and use **Pick folder…**.
- Displayed times are **UTC** by default; a **host-TZ toggle** (Logons, Timeline, Logs) re-renders them in the collector's local time using the offset recorded in `uac.log`.
- Rotated-log inflation and the sar/journal parsers use **PowerShell** (already present on Windows 10+) for `.gz` decompression; if PowerShell is unavailable, rotated history simply stays compressed and everything else still works.

## Requirements

Windows 10 1803+ (for the bundled `tar.exe`). No install, no admin required for reading a collected capture. Rotated-`.gz` inflation uses the built-in PowerShell + .NET `GzipStream` (no separate install).

## License

MIT © 2026 Ben Morris. UAC is a project of Thiago Canozzo Lahr ([tclahr/uac](https://github.com/tclahr/uac)); this is an independent triage viewer for its output.
