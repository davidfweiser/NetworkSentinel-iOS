# Network Sentinel (macOS)

Native **macOS** desktop app for **live network monitoring**, **remote peer tracking**, **break-in heuristics**, and **host firewall blocking** — with a modern dark Avalonia UI.

> Awareness / monitoring tooling — not a full IDS/IPS replacement.

macOS port of [davidfweiser/NetworkSentinel](https://github.com/davidfweiser/NetworkSentinel) (Linux Avalonia / original Windows WPF). Platform layers use **`lsof`/`netstat`**, **PF (`pfctl`)** elevated via **osascript** or **sudo**, and **`~/Library/Application Support/NetworkSentinel`**. Version **0.3.0**.

---

## Features

### Monitoring
| Area | What you get |
|------|----------------|
| **Open ports** | TCP listeners and UDP endpoints via `lsof` (with `netstat` fallback) |
| **Live connections** | Process name, local/remote endpoints, TCP state, origin summary |
| **Remote computers** | Peers observed talking to this Mac, reverse DNS, geo/ISP when public |
| **Activity chart** | Live sparkline of connection samples |

### Threat awareness
Heuristics flag patterns such as:
- Multi-port scans / reconnaissance
- SSH and SMB hammering
- Sensitive-port probing (admin, DB, remote access)
- Short-lived / transitional TCP bursts
- First-seen remote hosts

Each alert includes **source IP**, **method**, and **where it’s coming from** (DNS + best-effort geo).

### Firewall & block
- **Block / unblock** remote IPs (inbound, outbound, or both)
- **Block local ports** (TCP/UDP)
- Dedicated **PF anchor** `com.networksentinel` (only manages its own rules)
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
| `Services/FirewallService.cs` | PF via pfctl + osascript; rule ledger |
| `Services/AppSettings.cs` / `AppPaths.cs` | Application Support + JSON settings |
| `ViewModels/MainViewModel.cs` | UI state, commands, auto-block wiring |
| `MainWindow.axaml` | Avalonia dashboard UI |
| `Tui/TuiApp.cs` | Spectre.Console terminal UI (`--tui`) |
| `Program.cs` | Entry point; GUI / TUI routing |

---

## Linux / Windows → macOS changes

| Upstream | macOS |
|----------|--------|
| Linux Avalonia / Windows WPF | Avalonia 11 (`net8.0`) |
| `/proc/net` + inode map | `lsof -nP -iTCP/-iUDP` (+ `netstat` fallback) |
| nftables / iptables + pkexec | PF (`pfctl`) + osascript admin dialog |
| `~/.local/share/NetworkSentinel` | `~/Library/Application Support/NetworkSentinel` |
| `linux-x64` package | `osx-arm64` / `osx-x64` package |

---

## Important notes

- This is an **awareness console**, not a substitute for enterprise IDS, EDR, or carefully tuned host firewall policy.
- Threat heuristics count **new inbound connections to ports this Mac is listening on**.
- Public IP geolocation uses the free `ip-api.com` endpoint (rate-limited, best-effort, **plain HTTP**). Set `"GeoLookupEnabled": false` in settings to disable it.
- Process names for other users’ sockets may show as `Kernel / unknown` without root; monitoring still works.
- Existing TCP sessions may remain until they reconnect after a block; new matching traffic is stopped by PF.
- **Full Disk Access / Privacy**: `lsof` may warn about unreadable mounts (e.g. Time Machine SMB); that is normal and ignored.

---

## Troubleshooting

| Problem | What to do |
|---------|------------|
| Password dialog cancelled | Click **Authorize firewall** again, or allow the dialog when blocking. |
| `.NET location: Not found` | Set `DOTNET_ROOT` / `PATH` to your .NET install, or use a self-contained publish. |
| Process names missing | Expected for protected / other users’ processes; monitoring still works. |
| PF rules not taking effect | Run **Authorize firewall** once so the anchor is hooked into `/etc/pf.conf`. Check `sudo pfctl -a com.networksentinel -s rules`. |
| `lsof` SMB warnings | Harmless; Time Machine / network volumes the process cannot stat. |

---

## License

Private project — all rights reserved unless you add a license file later.
