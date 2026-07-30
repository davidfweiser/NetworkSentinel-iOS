# Network Sentinel — iOS

Modern iOS companion for **Network Sentinel** web servers (Linux & Windows).

Connect to one or more hosts running the headless web UI (`-w` / `--web`), sign in with the master password, and monitor critical network state from your iPhone or iPad.

## Features

| Area | What you get |
|------|----------------|
| **Multi-server** | Add/edit/delete servers; switch between home, lab, VPS, etc. |
| **Dashboard** | Live stats, activity sparkline, pause/resume, auto-block controls |
| **Detection** | Toggle geo lookups, auth-log brute-force monitoring, and closed-port scan detection, with the server's status text inline |
| **Threats** | Severity filters, search, clear alerts, block source IP |
| **Hosts** | Remote peers with geo/threat badges; swipe to block/unblock |
| **Connections** | Live process + endpoint table; block remote peers |
| **More** | Listening ports, firewall rules, allowlist add/remove/refresh, change master password |
| **Secure storage** | Session tokens & optional remembered passwords in Keychain |

Talks to the same JSON API as the browser console (Linux & Windows web **0.3.x**, current through **0.3.4**):

- `GET /api/auth/status`
- `POST /api/auth/login` · `/api/auth/setup` · `/api/auth/logout`
- `POST /api/auth/change-password` (0.3.2+) — `currentPassword`, `newPassword`, `confirm`
- `GET /api/state` (settings include `geoLookupEnabled` / `allowlistUseRemoteFeed` / `authLogMonitorEnabled` + `authLogStatus` / `probeLogEnabled` + `probeLogStatus`; rules include `isProtected`, `address`, `ports`)
- `POST /api/action` — `block`, `unblock`, `set_setting`, `block_port`, `unblock_port`, `remove_rule`, `remove_all_rules`, allowlist, auto-block, …

Sessions use the web UI’s `ns_session` cookie, sent as `Authorization: Bearer` from the app.

Compatible with older web servers for core monitor/block; newer settings and actions appear only when the server advertises them, so the detection toggles stay hidden on servers that predate them.

### Detection settings (0.3.4)

- **Auth-log monitoring** — watches system auth logs for failed SSH/PAM logons and raises brute-force threats.
- **Closed-port scan detection** — installs a rate-limited firewall SYN-log rule (needs elevation on the server) and watches the kernel log, catching port scans that never show up as connections.

Both toggles show the server's own status line, so you can tell when a feature is on but blocked (for example, waiting on elevation — use **Authorize firewall** in More).

### Changing the master password

**More → Change master password** calls the 0.3.2+ endpoint. The server keeps this device signed in and revokes every other session; if you saved the password on this device, the Keychain copy is updated so background refresh keeps working.

## Requirements

- **Xcode 15+** (iOS 17 deployment target)
- A Network Sentinel host with web mode enabled, reachable from your phone (LAN or VPN)

On the server:

```bash
# Linux / Windows Network Sentinel
./NetworkSentinel -w
# or fixed port:
./NetworkSentinel -w 18765
```

Note the URL printed in the console, e.g. `http://192.168.1.10:18765`.

## Open & run

```bash
cd NetworkSentinel-iOS
xcodegen generate   # creates NetworkSentinel.xcodeproj
open NetworkSentinel.xcodeproj
```

Select an iPhone simulator or device, then **Run** (⌘R).

If you use a physical device, set your **Development Team** in the Xcode project’s Signing settings.

### ATS note

The web UI typically serves **plain HTTP** on the LAN. The app allows arbitrary loads (`NSAllowsArbitraryLoads`) so those URLs work. Prefer VPN or trusted networks when exposing the web UI beyond localhost.

## First launch

1. **Add server** — name + base URL (`http://host:port`)
2. **Setup or sign in** — create master password (first visit) or enter existing one
3. Optionally **Remember on this device** (Keychain)
4. Use tabs: Dashboard · Threats · Hosts · Connections · More

## Project layout

```
NetworkSentinel-iOS/
  project.yml                 # XcodeGen spec
  NetworkSentinel/
    NetworkSentinelApp.swift
    Theme.swift
    Models/
    Services/                 # API client, server store, Keychain, app model
    Views/
      Servers/                # Onboarding, auth, server list
      Dashboard/              # Tabs & detail lists
```

## Privacy

- Server list is stored in `UserDefaults` on device only.
- Passwords/session tokens live in the Keychain (`AfterFirstUnlockThisDeviceOnly`).
- No analytics or third-party network calls from this app.

## License

Matches the parent [NetworkSentinel](https://github.com/davidfweiser/NetworkSentinel) project.
