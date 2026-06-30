# LethalDFIR Linux Forensics

> Offline Linux DFIR triage tool. Parses logs, configuration files,
> persistence locations, and binary login accounting from a directory
> tree, a single file, a mounted disk image, a tar/tar.gz archive, or a
> forensic collector ZIP. Produces JSON, CSVs, an HTML
> investigation report, and a LethalDFIR-branded XLSX workbook.
>
> Runs from native Linux or WSL. Windows-style paths
> (`C:\Cases\evidence`, `D:/IR/wtmp`) are auto-translated to
> `/mnt/<drive>/...` mount points.

```
   __     ___   __        __    ___  ___ __ ___
  / /  ___| |_/ /_  __ _ / /   / _ \/ __/ // _ \
 / /__/ -_) __/ _ \/ _` / /   / // / _// // , _/
/____/\__/\__/_//_/\__,_/_/  /____/_/ /_//_/|_|
       Linux Forensics  -  Offline Triage
```

---

## What it does

28 stdlib-only parsers walk the evidence and emit timeline events and
severity-tagged findings into a shared `Case` container. Five report
writers then render the case to disk:

| Report          | File                                | Notes                                                   |
| --------------- | ----------------------------------- | ------------------------------------------------------- |
| JSON bundle     | `case.json`                         | Full structured dump                                    |
| Findings CSV    | `findings.csv`                      | Severity-sorted                                         |
| Timeline CSV    | `timeline.csv`                      | l2tcsv-compatible columns                               |
| HTML report     | `report.html`                       | Self-contained; severity dashboard, filterable findings, paginated timeline |
| XLSX workbook   | `<case>_LethalDFIR_Report.xlsx`     | Branded; Summary, Findings, Timeline, Login Records, Brute-Force Analysis, Tamper Detection (requires `openpyxl`) |
| Per-parser CSVs | `csv/` directory                    | Individual output per parser (utmpdump dumps, last/lastb sessions, brute-force analysis, lastlog, etc.) |

---

## Quick start

### On WSL (Windows)

One-time setup from PowerShell (Administrator):

```powershell
wsl --install -d Ubuntu
```

Then inside the Ubuntu shell:

```bash
sudo apt update
sudo apt install -y python3 python3-pip
pip3 install --break-system-packages openpyxl

# Install this tool
cd lethaldfir_linux/
pip3 install --break-system-packages -e .

# Run against a forensic collector ZIP dropped on Windows
lethaldfir-linux -i 'C:\Cases\IR-2026\Collection-web01.zip' -o /mnt/c/Cases/IR-2026/out

# Or against a mounted folder
lethaldfir-linux -i /mnt/c/Cases/IR-2026/evidence -o ./out --case-name web01
```

### On native Linux

```bash
pip install -r requirements.txt
pip install -e .

lethaldfir-linux -i Collection-web01.zip -o ./out
lethaldfir-linux -i /mnt/image -o ./out --case-name web01
lethaldfir-linux -i ./extracted -o ./out --parsers auth_log,wtmp_btmp,ssh
```

### Without installation

The package is stdlib-only at import time, so you can also run from a
checkout:

```bash
python3 -m lethaldfir_linux -i ./evidence -o ./out
```

XLSX output requires `openpyxl`; everything else works without it.

---

## Inputs accepted

| Shape                          | Example                                      |
| ------------------------------ | -------------------------------------------- |
| Directory tree                 | `/mnt/image/`, `./extracted/`                |
| Single binary file             | `/var/log/wtmp`, `/var/log/lastlog`          |
| ZIP archive                    | `Collection-web01.zip` (forensic collector)  |
| Tar / tar.gz archive           | `evidence.tar.gz`                            |
| Windows-style path (WSL only)  | `'C:\Cases\evidence'`, `D:/IR/wtmp`          |

The evidence finder is suffix-based, so collected files under arbitrary
prefixes (`./host/files/etc/passwd`, `./auto/uploads/var/log/auth.log`,
etc.) are matched correctly.

---

## Parsers (28)

| Parser                  | Sources                                                                 | Sample findings                                                              |
| ----------------------- | ----------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `host_metadata`         | `/etc/hostname`, `/etc/os-release`, `/etc/hosts`, `/etc/resolv.conf`, `/etc/fstab` | hosts-file redirects of well-known domains; unusual DNS resolver             |
| `passwd_shadow_group`   | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`              | non-root UID 0 backdoor; empty password + interactive shell; service account with shell; privileged group membership |
| `ssh`                   | `/etc/ssh/sshd_config(.d)`, every user's `~/.ssh/authorized_keys[2]`    | `PermitRootLogin yes`; `PermitEmptyPasswords yes`; suspicious `command="..."` options; multiple root keys |
| `sudoers`               | `/etc/sudoers`, `/etc/sudoers.d/*`                                      | `ALL ALL=(ALL) NOPASSWD: ALL`; per-user passwordless sudo; visudo grants     |
| `auth_log`              | `/var/log/auth.log`, `/var/log/secure` (+ rotated/gz)                   | brute-force pattern; success-after-failures correlation; root SSH from non-loopback; new user account; usermod into privileged group |
| `syslog`                | `/var/log/messages`, `/var/log/syslog`, `/var/log/kern.log`, `/var/log/dmesg`, `/var/log/boot.log`, `/var/log/cron[.log]`, `/var/log/maillog`, `/var/log/mail.log`, `/var/log/daemon.log`, `/var/log/user.log`, `/var/log/debug` (+ rotated/gz) | suspicious tokens; OOM-killer activity; USB mass-storage attach; SELinux/AppArmor denials; segfault clusters |
| `journald`              | Binary systemd journal files via `journalctl --root=`/`--file=` (`/var/log/journal/`, `/run/log/journal/`) | emergency/alert/critical messages; OOM killer; coredumps; service failures; suspicious tokens |
| `wtmp_btmp`             | `/var/log/wtmp`, `/var/log/btmp`, `/var/run/utmp`, `/run/utmp` (binary utmp) | per-session login/logout/boot events; ≥50 failed-login records on btmp        |
| `lastlog`               | `/var/log/lastlog` (sparse, UID-indexed binary)                         | service / system account (UID < 1000, except root) with a recorded interactive login |
| `faillog`               | `/var/log/faillog` (binary), `/var/run/faillock/*` (pam_faillock, RHEL 8+) | system account with failed logins; high cumulative failure count             |
| `history_files`         | `.bash_history`, `.zsh_history`, `.python_history`, `.mysql_history`, `.psql_history`, etc. | suspicious command tokens; anti-forensic (`history -c`, `unset HISTFILE`); sensitive-file edits |
| `cron`                  | `/etc/crontab`, `/etc/anacrontab`, `/etc/cron.{d,hourly,daily,weekly,monthly}/*`, `/var/spool/cron(/crontabs)/*` | suspicious cron commands; `@reboot` persistence                              |
| `at_jobs`               | `/var/spool/at/*`, `/var/spool/atjobs/*`, `/var/spool/cron/atjobs/*`    | suspicious tokens in at job body; root-owned at jobs                          |
| `systemd`               | `/etc/systemd/system/`, `/run/systemd/system/`, `/usr/lib/systemd/system/`, `/lib/systemd/system/` | `ExecStart` in `/tmp` `/var/tmp` `/dev/shm`; vendor unit overridden in `/etc` |
| `audit`                 | `/var/log/audit/audit.log`                                              | suspicious EXECVE; SELinux AVC denials; ANOM_* kernel anomalies; failed user auth |
| `package_logs`          | `dpkg.log`, `apt/history.log`, `yum.log`, `dnf.log`                     | removal of security packages (auditd, fail2ban, ossec, wazuh, …)             |
| `web_logs`              | Apache / Nginx Combined-format access logs                              | scanner UAs (sqlmap, nikto, nuclei, …); webshell access (wso/c99/r57); path traversal; high-rate 4xx |
| `web_error_logs`        | Apache / Nginx error logs (`error.log`, `error_log`)                    | PHP errors from `/tmp`; ModSecurity rule triggers; web server segfaults       |
| `firewall_logs`         | `/var/log/ufw.log`, firewalld logs, kernel iptables/nftables log lines  | ≥100 blocks from single IP (scan); structured SRC/DST/port extraction        |
| `ftp_logs`              | `vsftpd.log`, `xferlog`, ProFTPD / Pure-FTPd logs                      | anonymous login; suspicious file uploads (.php/.war); FTP brute-force         |
| `database_logs`         | MySQL/MariaDB error/query logs, PostgreSQL logs                         | `INTO OUTFILE`/`LOAD_FILE`; auth failures; `CREATE USER`/`GRANT ALL`         |
| `container_logs`        | Docker JSON logs, Podman/CRI-O logs, daemon logs, `daemon.json`        | privileged containers; crypto-miner indicators; insecure registries           |
| `samba_logs`            | `/var/log/samba/log.smbd`, `/var/log/samba/log.*`                       | Samba authentication failures (lateral movement indicator)                    |
| `nfs_exports`           | `/etc/exports`, `/var/lib/nfs/etab`                                     | world-accessible exports; `no_root_squash`; sensitive path exports            |
| `pam_config`            | `/etc/pam.d/*`, `/etc/login.defs`, `/etc/securetty`, `/etc/selinux/config`, `/etc/apparmor.d/*`, `/etc/hosts.allow` | SELinux disabled/permissive; `pam_exec` backdoors; `pam_permit` in auth; weak password hashing |
| `kernel_modules`        | `/etc/modules`, `/etc/modules-load.d/*`, `/etc/modprobe.d/*`            | known rootkit module names (diamorphine, reptile…); suspicious `install` directives |
| `persistence`           | `/etc/ld.so.preload`, `/etc/profile`, `/etc/profile.d/*`, per-user RC files, `/etc/rc.local`, SUID/SGID binaries, XDG autostart, `/etc/ld.so.conf.d/*` | non-empty `ld.so.preload` (rootkit); SUID binary in user-writable dir; suspicious tokens in shell init files |

---

## XLSX workbook contents

| Sheet                  | Contents                                                                          |
| ---------------------- | --------------------------------------------------------------------------------- |
| Summary                | Brand header, host info, severity dashboard, parser run statistics                |
| Findings               | Every finding, severity-coloured, with evidence + metadata                        |
| Timeline               | Full super-timeline, frozen header, auto-filter                                   |
| Login Records          | wtmp / btmp / utmp / lastlog events extracted from the timeline                   |
| Brute-Force Analysis   | Top 25 attacker IPs + targeted users; **compromise indicator** (IPs in both failed AND successful) |
| Tamper Detection       | Findings tagged anti-forensic / tampering / rootkit / disabled-defenses           |

---

## CLI reference

```text
usage: lethaldfir-linux [-h] -i INPUT -o OUTPUT [--case-name CASE_NAME]
                        [--parsers PARSERS] [--list-parsers] [--jobs N]
                        [--no-html] [--no-xlsx] [--no-timeline]
                        [--no-banner] [--no-color] [--quiet] [--version]

  -i, --input          Path to evidence (directory, ZIP, tar, tar.gz, single file).
                       Windows-style paths (C:\..., D:/...) accepted on WSL.
  -o, --output         Output directory (created if missing).
  --case-name          Case name (default: derived from input filename).
  --parsers            Comma-separated subset of parsers to run.
  --list-parsers       List available parsers and exit (no -i/-o needed).
  --jobs, -j N         Parser worker threads (default: auto from CPU count).
                       Use 1 for fully sequential, deterministic execution.
  --no-html            Skip HTML report.
  --no-xlsx            Skip XLSX workbook.
  --no-timeline        Skip super-timeline CSV.
  --no-color           Disable ANSI colours (for piped/redirected output).
  --quiet, -q          Reduce console output.
  --no-banner          Suppress banner.
  --version            Show version and exit.
```

### Parallel execution

Independent parsers run concurrently on a thread pool (host-metadata and
the account parsers run first, in order, since the reports depend on
them). This overlaps the I/O- and subprocess-bound work — reading evidence
off a mounted image / network share / extracted archive, and the
`journalctl` calls the `journald` parser makes — which is where offline
triage runs actually spend their wall-clock time. Results are identical to
a sequential run (the JSON/CSV outputs are sorted, so they're
byte-stable). Pass `--jobs 1` for a fully sequential, deterministic run.

---

## Severity model

| Level     | Use                                                                                |
| --------- | ---------------------------------------------------------------------------------- |
| CRITICAL  | Direct evidence of compromise (rootkit, backdoor account, root password SSH login from external IP) |
| HIGH      | Strong indicator requiring immediate review (brute-force success, suspicious `ExecStart`, NOPASSWD: ALL) |
| MEDIUM    | Notable misconfiguration or weak persistence indicator                              |
| LOW       | Hardening gap; supporting context                                                   |
| INFO      | Inventory / context for the timeline                                                |

---

## WSL gotchas

| Symptom                                                | Fix                                                                                       |
| ------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| `Input not found: /mnt/c/...`                          | Confirm path: `ls /mnt/c/<your-folder>`. Watch case-sensitivity and spacing.              |
| Garbled colour codes when redirecting                  | Add `--no-color`, set `NO_COLOR=1`, or use Windows Terminal / PowerShell 7.               |
| Slow scan against `/mnt/c/...`                         | Copy evidence into the WSL filesystem first (`cp -r /mnt/c/Cases/IR ~/`). WSL2 disk I/O is much faster on the VHD than over the 9P bridge. |
| `pip install` says "externally-managed-environment"    | Use a venv (`python3 -m venv ~/.venv/lethaldfir`), or `pip install --break-system-packages`, or `sudo apt install python3-openpyxl`. |

---

## Caveats and limitations

* **No `journald` binary parsing.** Collect the journal in text form
  (`journalctl --no-pager > journal.txt`) and add it to the
  collection.
* **Apache log format.** Only NCSA Combined is parsed.
* **Rotated logs are read.** `auth.log`, `auth.log.1`, `auth.log.2.gz`,
  and date-suffixed variants are all parsed transparently.
* **Year fudging on syslog timestamps.** RFC 3164 timestamps lack a
  year; defaults to current year. RFC 5424 timestamps are unaffected.

---

## License

MIT. See `LICENSE`.
