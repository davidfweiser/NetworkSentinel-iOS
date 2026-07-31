# Network Sentinel — iOS

Modern iOS companion for **Network Sentinel** web servers (Linux, Windows & macOS).

Connect to one or more hosts running the headless web UI (`-w` / `--web`), sign in with the master password, and monitor critical network state from your iPhone or iPad.

## Features

| Area | What you get |
|------|----------------|
| **Multi-server** | Add/edit/delete servers; switch between home, lab, VPS, etc. |
| **Dashboard** | Live stats, activity sparkline, pause/resume, auto-block controls |
| **Detection** | Toggle geo lookups, auth-log brute-force monitoring, closed-port scan detection, and the server's own Critical warnings, with its status text inline |
| **Threats** | Severity filters, search, clear alerts, block source IP |
| **Hosts** | Remote peers with geo/threat badges; swipe to block/unblock |
| **Connections** | Live process + endpoint table; block remote peers |
| **More** | Listening ports, firewall rules, allowlist add/remove/refresh, change master password |
| **Alerts** | Time-sensitive notifications and in-app popups for Critical threats, with catch-up on launch |
| **Secure storage** | Session tokens & optional remembered passwords in Keychain |

Talks to the same JSON API as the browser console (Linux, Windows & macOS web **0.3.x**, current through **0.3.5**):

- `GET /api/auth/status`
- `POST /api/auth/login` · `/api/auth/setup` · `/api/auth/logout`
- `POST /api/auth/change-password` (0.3.2+) — `currentPassword`, `newPassword`, `confirm`
- `GET /api/state` (settings include `geoLookupEnabled` / `allowlistUseRemoteFeed` / `authLogMonitorEnabled` + `authLogStatus` / `probeLogEnabled` + `probeLogStatus` / `criticalAlertsEnabled`; threats include `ts`; rules include `isProtected`, `address`, `ports`)
- `POST /api/action` — `block`, `unblock`, `set_setting`, `block_port`, `unblock_port`, `remove_rule`, `remove_all_rules`, allowlist, auto-block, …

Sessions use the web UI’s `ns_session` cookie, sent as `Authorization: Bearer` from the app.

Compatible with older web servers for core monitor/block; newer settings and actions appear only when the server advertises them, so the detection toggles stay hidden on servers that predate them.

### Detection settings (0.3.4 – 0.3.5)

- **Auth-log monitoring** — watches system auth logs for failed SSH/PAM logons and raises brute-force threats. On macOS this reads the unified log (sshd, sudo, login, Screen Sharing).
- **Closed-port scan detection** — installs a rate-limited firewall SYN-log rule (needs elevation on the server) and watches the kernel log — PF plus `pflog0` on macOS — catching port scans that never show up as connections.
- **Critical alerts on server** (0.3.5+) — the server's own Critical warnings: a desktop notification from its GUI and a tab-title badge in its web console. On by default.

The first two toggles show the server's own status line, so you can tell when a feature is on but blocked (for example, waiting on elevation — use **Authorize firewall** in More).

### Two kinds of Critical alert

They are independent, and the app never changes one when you change the other:

| Toggle | Where | What it does |
|--------|-------|--------------|
| **Critical alerts on this device** (More → Alerts) | On the iPhone, stored locally | Local notifications and in-app popups from this app, foreground and via Background App Refresh |
| **Critical alerts on server** (Dashboard → settings) | On the server, web 0.3.5+ | Desktop notification from the server's GUI, tab badge + browser notification in its web console |

From 0.3.5 each threat also carries a full ISO-8601 `ts`, so the app's notification dedupe keys on the real date. Against older servers only `HH:mm:ss` is available, so it falls back to that.

Critical notifications are sent `.timeSensitive`, so they break through Focus and Do Not Disturb rather than waiting for Scheduled Summary. That needs the **Time Sensitive Notifications** capability, which the project declares in `NetworkSentinel/NetworkSentinel.entitlements`; your signing team must have it enabled for the app ID.

**Catch-up on launch.** The first time the app connects to a given server, everything already on its threat list is treated as backlog and never notified. After that, opening the app surfaces any Critical it missed while force-quit or between background wake-ups, as long as the event is under 24 hours old — older ones are marked seen quietly, and servers predating `ts` stay on the silent path since their timestamps carry no date.

### How timely are device alerts?

Honest answer: dependable while the app is open, best-effort once it is not.

| App state | Behaviour |
|-----------|-----------|
| Foreground | Polls every ~2.5s; alerts are effectively immediate |
| Just backgrounded | The poll loop continues for the ~30s of background time iOS grants |
| Backgrounded longer | `BGAppRefreshTask`, asking for 15 minutes but scheduled at iOS's discretion — often less frequent |
| Force-quit from the app switcher | **Nothing.** iOS does not relaunch apps the user swiped away |

Background polling also needs Background App Refresh enabled (Settings → Network Sentinel), the server reachable from the phone at that moment (LAN or VPN), and **Remember on this device** so the app can re-authenticate without you. Low Power Mode suppresses it too.

Treat this as a companion console, not a pager: it is not a substitute for alerting that runs on the server itself.

### Changing the master password

**More → Change master password** calls the 0.3.2+ endpoint. The server keeps this device signed in and revokes every other session; if you saved the password on this device, the Keychain copy is updated so background refresh keeps working.

## Requirements

- **Xcode 15+** (iOS 17 deployment target)
- A Network Sentinel host with web mode enabled, reachable from your phone (LAN or VPN)

On the server:

```bash
# Linux / Windows / macOS Network Sentinel
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
    NetworkSentinel.entitlements   # Time Sensitive Notifications
    Theme.swift
    Models/
    Services/                 # API client, server store, Keychain, app model, alerts
    Views/
      Servers/                # Onboarding, auth, server list
      Dashboard/              # Tabs & detail lists
```

## Privacy

- Server list is stored in `UserDefaults` on device only, alongside already-notified threat IDs so alerts are not repeated.
- Passwords/session tokens live in the Keychain (`AfterFirstUnlockThisDeviceOnly`).
- No analytics or third-party network calls from this app.

## License

Matches the parent [NetworkSentinel](https://github.com/davidfweiser/NetworkSentinel) project.
