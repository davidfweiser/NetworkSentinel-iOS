# Network Sentinel (macOS)

Native **macOS** desktop app for **live network monitoring**, **remote peer tracking**, **break-in heuristics**, and **host firewall blocking** — with a modern dark Avalonia UI.

> Awareness / monitoring tooling — not a full IDS/IPS replacement.

macOS port of [davidfweiser/NetworkSentinel](https://github.com/davidfweiser/NetworkSentinel) (Linux Avalonia / original Windows WPF). Platform layers use **`lsof`/`netstat`**, **PF (`pfctl`)** elevated via **osascript** or **sudo**, the **macOS unified log** (`log stream`), and **`~/Library/Application Support/NetworkSentinel`**. Version **0.3.4**.

---

## Features

### Monitoring
| Area | What you get |
|------|----------------|
| **Open ports** | TCP listeners and UDP endpoints via `lsof` (with `netstat` fallback) |
| **Live connections** | Process name, local/remote endpoints, TCP state, origin summary |
| **Remote computers** | Peers observed talking to this Mac, reverse DNS, geo/ISP when public |
| **Activity chart** | Live ~5-minute chart of connection samples with **threat markers** and a current/peak legend |
| **Poll interval** | Selectable in **Settings** (0.5 s – 10 s); doubles as the chart's sample rate |

### Threat awareness
Heuristics flag patterns such as:
- Multi-port scans / reconnaissance — fast (45 s window) **and slow/paced** (10 min window, catches `nmap -T1`-style scans)
- **Scans of closed ports** (opt-in) — a PF SYN-log rule makes probes visible that never appear as connections (the kernel answers closed-port SYNs with a RST before the socket table ever sees them); a `pflog0` watcher turns them into alerts within seconds
- **Failed logon bursts** from the macOS unified log (`sshd`, `sudo`, `login`, Screen Sharing) — catches SSH/PAM brute-force even when it reuses one TCP session or paces below the connection-rate thresholds
- **Outbound beaconing** — regular-interval new sessions to an uncommon remote port (C2 "calling home" signature); common client ports and LAN peers are excluded
- SSH and SMB hammering
- Sensitive-port probing (admin, DB, remote access)
- Short-lived / transitional TCP bursts
- First-seen remote hosts

Each alert includes **source IP**, **method**, and **where it’s coming from** (DNS + best-effort geo).

### Firewall & block
- **Block / unblock** remote IPs (inbound, outbound, or both)
- **Block local ports** (TCP/UDP)
- Dedicated **PF anchor** `com.networksentinel` (only manages its own rules)
- Block rules are created as an `-In`/`-Out` pair and **removed together** in one click
- **Auto-block** on/off with minimum severity (`Medium` / `High` / `Critical`)
- Settings in `~/Library/Application Support/NetworkSentinel/settings.json`
- **Authorize firewall** — elevates only `pfctl` via Mac admin password dialog. The GUI always runs as your user

### Known-good allowlist (never block)
Trusted sites are protected so auto-block (and manual block) will not cut off everyday tools:

| Source | Location |
|--------|----------|
| **Built-in defaults** | `Data/allowlist-default.json` (GitHub, xAI/Grok, Microsoft, Google, Cloudflare DNS, NuGet, …) |
| **Your additions** | `~/Library/Application Support/NetworkSentinel/allowlist.json` |
| **Remote feed** | Optional refresh from the upstream repo’s `allowlist-default.json` on GitHub |

---

## Requirements

- **macOS** 12+ (Apple Silicon or Intel)
- [.NET 8 SDK or runtime](https://dotnet.microsoft.com/download) (or use a self-contained publish)
- Avalonia desktop dependencies (bundled with the runtime on macOS)
- Admin rights (password dialog) for PF firewall changes

---

## Quick start

```bash
cd NetworkSentinel-mac
export PATH="$HOME/.dotnet:$PATH"
export DOTNET_ROOT="$HOME/.dotnet"

dotnet run -c Release
```

### Terminal UI (TUI)

```bash
dotnet run -c Release -- --tui
# or after publish:
./NetworkSentinel --tui
# or:  NETWORKSENTINEL_TUI=1 ./NetworkSentinel
```

| Key | Action |
|-----|--------|
| `1`–`7` / `Tab` | Dashboard · Connections · Hosts · Threats · Ports · Firewall · **Allowlist** |
| `↑` `↓` / `j` `k` | Move selection |
| `/` or `f` | Filter |
| `p` | Pause / resume monitoring |
| `a` | Toggle auto-block |
| `m` | Cycle auto-block minimum severity |
| `b` / `x` | Block / unblock selected IP (or prompt) |
| `n` / `+` | **Add domain or IP to allowlist** (never block) |
| `d` | Remove selected allowlist Domain/IP (on Allowlist view) |
| `g` | Restore good sites (unblock allowlisted IPs) |
| `u` | Authorize firewall elevation (admin password) |
| `c` | Clear threat alerts |
| `r` | Refresh firewall · on Allowlist: refresh DNS/feed |
| `h` / `F1` | Help |
| `q` | Quit |

### Headless web console

Runs the same monitor and firewall engine with a browser front-end instead of the Avalonia GUI — useful over SSH or on a Mac with no logged-in desktop session.

```bash
dotnet run -c Release -- -w          # auto-picks a free high port (prefers 18765)
dotnet run -c Release -- -w 18765    # explicit port
# or:  NETWORKSENTINEL_WEB=1 ./NetworkSentinel
```

| Tab | What you can do |
|-----|-----------------|
| **Dashboard** | Live counters, **5-minute activity chart** (connections + threat markers), monitoring/firewall status, recent threats |
| **Connections / Threats** | Live traffic with a **Block** button on every row |
| **Hosts** | Remote peers; block / unblock by row or by typed IP |
| **Ports** | Local listeners; one-click **Block port** |
| **Firewall** | Managed rules grouped as In/Out pairs; manual IP and port blocking; **Restore allowlisted** |
| **Allowlist** | Add/remove trusted domains and IPs; refresh the feed |
| **Settings** | Monitoring on/off, page refresh speed, poll interval, geo lookups, auth-log monitoring, closed-port scan detection, auto-block + minimum severity, block direction, allowlist feed, **change master password**, **Remove all rules** |

**Master password.** The first visit creates one; every later visit requires it. Change it under **Settings → Master password**. If you can't reach a browser yet, set or reset it from the terminal:

```bash
sudo ./NetworkSentinel --set-master-password
```

That requires root and resolves the real target user via `SUDO_USER` (using `dscl`), so the hash lands in **your** `~/Library/Application Support/NetworkSentinel/web-master.json` — not root's. Restart the web console afterwards so it picks up the change. The hash is PBKDF2-SHA256 (random salt, 200k iterations) — never plain text.

The web console **refuses to block its own port**, which would otherwise cut off your browser mid-request and look like a crash.

### Release build

```bash
dotnet build -c Release
dotnet publish -c Release -r osx-arm64 --self-contained false -o bin/publish
./bin/publish/NetworkSentinel
```

Self-contained (no system .NET runtime needed):

```bash
./scripts/package.sh              # osx-arm64 on Apple Silicon
./scripts/package.sh osx-x64      # Intel Macs
```

---

## Firewall / auto-block

**Prefer running the GUI as your user** (not `sudo`). When you block an IP/port (or click **Authorize firewall**), only `pfctl` is elevated and macOS shows a standard admin password dialog.

```bash
# correct
./NetworkSentinel

# avoid for GUI
# sudo ./NetworkSentinel
```

PF details:
- Anchor name: `com.networksentinel`
- Rules file: `/etc/pf.anchors/com.networksentinel` (mirrored under Application Support)
- First authorize may append an anchor hook to `/etc/pf.conf` (backup: `/etc/pf.conf.networksentinel.bak`)
- Only Network Sentinel’s own rules are managed; other PF rules are left alone

---

## Using the app

| Tab | Purpose |
|-----|---------|
| **Dashboard** | Stats, activity chart, latest threats, observed hosts |
| **Live Connections** | Active TCP sessions; block remote IP per row |
| **Remote Computers** | Tracked peers, origin, threat level; block / unblock |
| **Break-in Attempts** | Heuristic alerts with origin and method |
| **Open Ports** | Listening TCP/UDP; optional inbound port block |
| **Firewall & Block** | Manual IP/port rules, auto-block, allowlist, managed rule list |

### Auto-block
1. Click **Authorize firewall** (or allow the first password prompt when blocking).
2. Turn **Auto-block** **On**.
3. Choose **Minimum severity** (default **High**).
4. Public IPs that hit that severity get PF drop rules automatically.
5. Private/LAN addresses, “new host” info events, and allowlisted sites are **never** auto-blocked.

---

## How it works (high level)

```text
┌─────────────────┐     poll ~1.2s      ┌──────────────────────┐
│  macOS lsof /   │ ─────────────────► │ NetworkMonitorService │
│  netstat        │                    └──────────┬───────────┘
└─────────────────┘                               │
                                                  ▼
                                       ┌──────────────────────┐
                                       │ IntrusionDetector    │
                                       │ (heuristics)         │
                                       └──────────┬───────────┘
                                                  │
                    ┌─────────────────────────────┼─────────────────────────────┐
                    ▼                             ▼                             ▼
           Geo / DNS lookup         Avalonia UI  or  TUI          FirewallService
           (origin details)         (MVVM / Spectre)              osascript → pfctl
```

---

## Project layout

| Path | Role |
|------|------|
| `Native/MacNetTable.cs` | `lsof` / `netstat` parsing + PID mapping |
| `Services/NetworkMonitorService.cs` | Polling loop, host tracking, stats |
| `Services/IntrusionDetector.cs` | Heuristic threat engine |
| `Services/GeoIpService.cs` | Reverse DNS + public geo lookup |
| `Services/FirewallService.cs` | PF via pfctl + osascript; rule ledger; PF probe-log rule |
| `Services/AuthLogMonitor.cs` | Failed-logon detection from the macOS unified log |
| `Services/ProbeLogMonitor.cs` | Closed-port scan detection from the PF packet log |
| `Services/AppSettings.cs` / `AppPaths.cs` | Application Support + JSON settings |
| `ViewModels/MainViewModel.cs` | UI state, commands, auto-block wiring, Settings view |
| `MainWindow.axaml` | Avalonia dashboard UI |
| `Tui/TuiApp.cs` | Spectre.Console terminal UI (`--tui`) |
| `Web/WebApp.cs` / `WebAuthStore.cs` | Headless browser console (`--web`) + master-password auth |
| `Program.cs` | Entry point; GUI / TUI / web routing, crash log |

---

## Linux / Windows → macOS changes

| Upstream | macOS |
|----------|--------|
| Linux Avalonia / Windows WPF | Avalonia 11 (`net8.0`) |
| `/proc/net` + inode map | `lsof -nP -iTCP/-iUDP` (+ `netstat` fallback) |
| nftables / iptables + pkexec | PF (`pfctl`) + osascript admin dialog |
| `~/.local/share/NetworkSentinel` | `~/Library/Application Support/NetworkSentinel` |
| `linux-x64` package | `osx-arm64` / `osx-x64` package |
| `journalctl` / `/var/log/auth.log` | `log stream` over the unified log (+ `/var/log/system.log` fallback) |
| iptables/nft `LOG` rule + `kern.log` | PF `log` rule + `tcpdump` on `pflog0` |
| `getent passwd` (service user) | `dscl . -read /Users/…` + `id -u/-g` |
| `systemd` web service | run `--web` directly (no launchd unit shipped yet) |

---

## Important notes

- This is an **awareness console**, not a substitute for enterprise IDS, EDR, or carefully tuned host firewall policy.
- Scan/brute-force heuristics count **new inbound connections to ports this Mac is listening on** — long-lived sessions and ordinary outbound client traffic are never treated as probing. The only outbound rule is the beacon detector, which requires a regular cadence to an uncommon port on a public IP.
- Public IP geolocation uses the free `ipwho.is` endpoint over **HTTPS**, falling back to `ip-api.com` (plain HTTP) only if that fails. Both are rate-limited and best-effort. Toggle lookups off in **Settings**, or set `"GeoLookupEnabled": false`; reverse DNS still runs.
- **Failed-logon detection** reads the unified log via `log stream` and needs no elevation. macOS redacts some message arguments as `<private>`, which can hide the peer address; when that happens the app says so under **Settings → Auth-log monitoring** rather than silently reporting nothing. Set `"AuthLogMonitorEnabled": false` to turn it off.
- **Closed-port scan detection** is off by default because it needs admin rights twice over: to add the PF log rule, and to run the privileged `tcpdump` that decodes `pflog0` (BPF devices are root-only). Enable it under **Settings → Closed-port scan detection** — a single password prompt installs the rule, creates `pflog0`, and starts the decoder, which writes `/var/log/networksentinel-probe.log` for the app to tail unprivileged. The rule appears on the **Firewall** tab as `NetworkSentinel-ProbeLog` and is removed with the toggle.
  - The rule is `pass in log proto tcp from any to any flags S/SA no state`, placed **last** in the anchor and deliberately **not** `quick`. macOS `pfctl` has no `match` keyword, so a log-only rule is impossible — but every managed block above it is `block drop … quick`, so blocked peers short-circuit and never reach it, and `no state` confines the pass to the SYN alone without adding a state entry. The behaviour change is limited to inbound TCP SYNs nothing else in your ruleset blocked. If you maintain your own PF rules, review that before enabling.
- Process names for other users’ sockets may show as `Kernel / unknown` without root; monitoring still works.
- Existing TCP sessions may remain until they reconnect after a block; new matching traffic is stopped by PF.
- **Full Disk Access / Privacy**: `lsof` may warn about unreadable mounts (e.g. Time Machine SMB); that is normal and ignored.
- If the app ever exits unexpectedly, check `~/Library/Application Support/NetworkSentinel/logs/crash.log` — unhandled errors are logged there with a stack trace.

---

## Troubleshooting

| Problem | What to do |
|---------|------------|
| Password dialog cancelled | Click **Authorize firewall** again, or allow the dialog when blocking. |
| `.NET location: Not found` | Set `DOTNET_ROOT` / `PATH` to your .NET install, or use a self-contained publish. |
| Process names missing | Expected for protected / other users’ processes; monitoring still works. |
| PF rules not taking effect | Run **Authorize firewall** once so the anchor is hooked into `/etc/pf.conf`. Check `sudo pfctl -a com.networksentinel -s rules`. |
| `lsof` SMB warnings | Harmless; Time Machine / network volumes the process cannot stat. |
| Auth-log alerts never fire | Check **Settings → Auth-log monitoring**. If it reports addresses redacted as `<private>`, macOS is withholding the peer IP; an Apple logging profile that enables private data for `com.apple.sshd` restores it. |
| Closed-port detection stuck on "waiting for the PF probe log" | The privileged decoder isn't running. Toggle **Closed-port scan detection** off and on and allow the password prompt; verify with `sudo pfctl -a com.networksentinel -s rules` and `ls -l /var/log/networksentinel-probe.log`. |
| Port shows `LISTEN` locally but the web console is unreachable from another machine | The process listening only proves the app is up. macOS Application Firewall or an upstream network firewall can still drop inbound traffic — allow the binary in **System Settings → Network → Firewall**. |

---

## License

Private project — all rights reserved unless you add a license file later.
