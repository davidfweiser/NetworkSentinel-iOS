# Network Sentinel — iOS

Modern iOS companion for **Network Sentinel** web servers (Linux, Windows & macOS).

Connect to one or more hosts running the headless web UI (`-w` / `--web`), sign in with the master password, and monitor critical network state from your iPhone or iPad.

## Features

| Area | What you get |
|------|----------------|
| **Multi-server** | Add/edit/delete servers; switch between home, lab, VPS, etc. |
| **Dashboard** | Needs-attention card with one-tap block, live stats, scrubbable activity chart, pause/resume, auto-block controls and rule expiry |
| **Detection** | Toggle geo lookups, auth-log brute-force monitoring, closed-port scan detection, and the server's own Critical warnings, with its status text inline |
| **Intrusion detection** | Threat-intel blocklists, new-listener alerts, process reputation, ARP/gateway watch, launch-item watch, exfiltration monitor with threshold, honeypot decoy ports (web 0.4+) |
| **Threats** | Severity filters, search, clear alerts, block source IP |
| **Hosts** | Remote peers with geo/threat badges; swipe to block/unblock |
| **Connections** | Live process + endpoint table; block remote peers |
| **More** | Listening ports, firewall rules, allowlist add/remove/refresh, server webhook URL, change master password |
| **Alerts** | Time-sensitive notifications and in-app popups for Critical threats, with catch-up on launch |
| **Secure storage** | Session tokens & optional remembered passwords in Keychain |

Talks to the same JSON API as the browser console (Linux, Windows & macOS web **0.3.x – 0.4.x**, current through **0.4.0**):

- `GET /api/auth/status`
- `POST /api/auth/login` · `/api/auth/setup` · `/api/auth/logout`
- `POST /api/auth/change-password` (0.3.2+) — `currentPassword`, `newPassword`, `confirm`
- `GET /api/state` (settings include `geoLookupEnabled` / `allowlistUseRemoteFeed` / `authLogMonitorEnabled` + `authLogStatus` / `probeLogEnabled` + `probeLogStatus` / `criticalAlertsEnabled`, and on 0.4+ the intrusion-detection group below; threats include `ts`; rules include `isProtected`, `address`, `ports`)
- `POST /api/action` — `block`, `unblock`, `set_setting`, `block_port`, `unblock_port`, `remove_rule`, `remove_all_rules`, allowlist, auto-block, …

`set_setting` carries booleans as `"true"`/`"false"` and the 0.4 numeric/text settings as their literal value, including the empty string that switches the webhook off.

Sessions use the web UI’s `ns_session` cookie, sent as `Authorization: Bearer` from the app.

Compatible with older web servers for core monitor/block; newer settings and actions appear only when the server advertises them, so the detection toggles stay hidden on servers that predate them.

### Detection settings (0.3.4 – 0.3.5)

- **Auth-log monitoring** — watches system auth logs for failed SSH/PAM logons and raises brute-force threats. On macOS this reads the unified log (sshd, sudo, login, Screen Sharing).
- **Closed-port scan detection** — installs a rate-limited firewall SYN-log rule (needs elevation on the server) and watches the kernel log — PF plus `pflog0` on macOS — catching port scans that never show up as connections.
- **Critical alerts on server** (0.3.5+) — the server's own Critical warnings: a desktop notification from its GUI and a tab-title badge in its web console. On by default.

The first two toggles show the server's own status line, so you can tell when a feature is on but blocked (for example, waiting on elevation — use **Authorize firewall** in More).

### Intrusion detection (0.4.0)

A second Dashboard card, shown only against servers that advertise the suite. Each row carries the server's own status line where it publishes one, so a detector that is switched on but not actually running says why.

| Setting | What the server does |
|---------|----------------------|
| **Threat-intel blocklists** | Checks remote peers against FireHOL level1 and Spamhaus DROP; a listed peer is an instant Critical |
| **New-listener alerts** | Diffs listening ports against a persisted baseline — a new port is Medium, a known port changing owner process is High |
| **Process reputation** | Unsigned or quarantined binaries talking to public hosts, executables in temp/download folders, shells with outbound connections |
| **ARP / gateway watch** | Gateway MAC change (Critical) and duplicate MAC on the LAN (High) |
| **Launch-item watch** | LaunchAgents / LaunchDaemons additions and modifications |
| **Exfiltration monitor** | Outbound bytes to one non-allowlisted public host, with a threshold picker (default 250 MB / 10 min; the server's floor is 10) |
| **Honeypot decoy ports** | Binds decoy TCP ports; any completed connection is Critical. The port list is editable, and the server refuses its own console port |

Two more 0.4 settings live where they belong rather than in that card: **auto-block rule expiry** sits with the other auto-block controls (Never / 1 hour / 6 hours / 24 hours / 7 days), and the server's **webhook URL** is in More, next to this device's alerts — it is the one alert path that still works when the phone is asleep or the app has been force-quit.

**Threats that are not an address.** The new detectors that watch the machine itself — new listener, launch-item change — report `127.0.0.1` rather than a peer, and the server refuses to firewall loopback. Wherever the app would otherwise offer **Block** for one of those (needs-attention card, threat list, in-app Critical banner), it shows what was detected instead, so the primary action is never a button that can only fail. Threat rows also carry a per-type icon, since 0.4 raised the number of distinct threat types from eight to fifteen.

Linux and Windows are still on 0.3.5 as of this writing; these rows appear as soon as those builds ship the same settings.

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

## Design

The interface is built on **Liquid Glass** (iOS 26), and its one organising idea is that
severity drives the whole surface rather than a single badge:

- **The background is the data.** A cool wash at rest that brightens with connection volume,
  and breathes in the severity colour once a High or Critical threat is live — so you can
  read the state of the network before focusing on any number. The motion only runs while
  something is actually wrong, which also keeps a 2.5s poll loop from paying for an
  animation that never stops. Reduce Motion swaps the breath for a static wash.
- **The chrome follows.** Tab bar and controls tint interactive blue when things are calm
  and shift to the severity colour when they are not.
- **Alarm is spent in one place.** Only the needs-attention card carries the tint; the
  status panel above it stays neutral so two red panels never compete.
- **Readouts are compressed-width numerals**, addresses are monospaced, section labels are
  tracked uppercase — instrument, not dashboard.

**Needs attention** surfaces the single worst live threat with a Block button, so acting on
the thing the app exists to catch does not start with scanning a list. A Critical arriving
while you are in the app shows a non-blocking banner rather than a modal alert — the modal
used to cover the very card offering the same action.

The activity chart is Swift Charts: drag anywhere on it to pin a sample and read its exact
connection, host and threat counts, with the same red markers and zero baseline the web
console uses.

### Changing the master password

**More → Change master password** calls the 0.3.2+ endpoint. The server keeps this device signed in and revokes every other session; if you saved the password on this device, the Keychain copy is updated so background refresh keeps working.

## Requirements

- **Xcode 26+** (iOS 26 deployment target — the UI is built on Liquid Glass)
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
