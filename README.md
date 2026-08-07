# Network Sentinel — iOS

Modern iOS companion for **Network Sentinel** web servers (Linux, Windows & macOS).

Connect to one or more hosts running the headless web UI (`-w` / `--web`), sign in with the master password, and monitor critical network state from your iPhone or iPad.

## Features

| Area | What you get |
|------|----------------|
| **Multi-server** | Add/edit/delete servers; switch between home, lab, VPS, etc. |
| **Dashboard** | Needs-attention card with one-tap block, live stats, scrubbable activity chart, sleep/wake, pause/resume, auto-block controls and rule expiry |
| **Sleep / Wake** | Stops every watcher on the server and parks the app — dimmed data, an Asleep banner on each live tab, a 30-second heartbeat, no Critical alerts. Firewall blocks stay in force |
| **Detection** | Toggle geo lookups, auth-log brute-force monitoring, closed-port scan detection, kernel flow events, and the server's own Critical warnings, with its status text inline |
| **Intrusion detection** | Threat-intel blocklists, new-listener alerts, process reputation, ARP/gateway watch, startup-item watch, exfiltration monitor with threshold, honeypot decoy ports (web 0.4+) |
| **DNS hygiene** | Plaintext egress, encrypted DNS going away, unapproved resolvers, allowlist drift — with the approved-resolver list (web 0.6+) |
| **VPN peers** | WireGuard peer monitoring, per-peer transfer threshold, and the read-only peer table (web 0.6+) |
| **Signatures** | Suricata EVE ingestion — feed path, maximum severity, muted signature ids (web 0.6+) |
| **Threats** | Severity filters, search, clear alerts, block source IP — each row saying whether that IP is actually blocked (web 0.6.3+) |
| **Hosts** | Remote peers with geo/threat badges; swipe to block/unblock |
| **Connections** | Live process + endpoint table; block remote peers |
| **More** | Listening ports, firewall rules, allowlist add/remove/refresh, server webhook URL, HTTPS + DuckDNS remote access and certificate issuance, change master password |
| **Alerts** | Time-sensitive notifications and in-app popups for Critical threats, leading with whether the address was blocked (web 0.6.3+), with catch-up on launch |
| **Secure storage** | Session tokens & optional remembered passwords in Keychain |

Talks to the same JSON API as the browser console (Linux, Windows & macOS web **0.3.x – 0.6.x**, current through **0.6.3**):

- `GET /api/auth/status`
- `POST /api/auth/login` · `/api/auth/setup` · `/api/auth/logout`
- `POST /api/auth/change-password` (0.3.2+) — `currentPassword`, `newPassword`, `confirm`
- `GET /api/state` (settings include `geoLookupEnabled` / `allowlistUseRemoteFeed` / `authLogMonitorEnabled` + `authLogStatus` / `probeLogEnabled` + `probeLogStatus` / `criticalAlertsEnabled`, on 0.4+ the intrusion-detection group, on 0.5+ the HTTPS/DuckDNS group, and on 0.6+ `preventionDryRun` / `conntrackEventsEnabled` / the DNS, WireGuard and Suricata groups, on 0.6.3+ `autoBlockSummary`; threats include `ts` and on 0.6.3+ `blockStatus` / `blockShort` / `blocked`; rules include `isProtected`, `address`, `ports`)
- `POST /api/action` — `block`, `unblock`, `set_setting`, `block_port`, `unblock_port`, `remove_rule`, `remove_all_rules`, allowlist, auto-block, …
- `POST /api/action` — `sleep` / `wake` (web 0.5.1+), falling back to the `pause` / `resume` names every 0.3–0.5.0 server drives the same monitor state under
- `POST /api/action` — `issue_cert` (web 0.5+)

`set_setting` carries booleans as `"true"`/`"false"` and the numeric/text settings as their literal value, including the empty string that switches the webhook off, un-mutes every Suricata signature, or clears the approved-resolver list.

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

The persistence watcher is one detector under two names: macOS publishes it as `launchItemWatchEnabled` and watches LaunchAgents/LaunchDaemons, Linux and Windows publish `persistenceWatchEnabled` and watch systemd units, cron and autostart entries. The app reads whichever key the server sent, labels the row to match, and writes the same one back — sending the other name comes back as `Unknown setting`, which reads as a toggle that silently does nothing.

**Threats that are not an address.** Several detectors report a source the server will refuse to firewall: the ones watching the machine itself — new listener, persistence change — report `127.0.0.1`, DNS hygiene reports the resolver being queried (routinely a LAN or tunnel address), and a WireGuard peer with no live endpoint falls back to loopback. Wherever the app would otherwise offer **Block** for one of those (needs-attention card, threat list, in-app Critical banner), it shows what was detected instead, so the primary action is never a button that can only fail. Threat rows also carry a per-type icon, since 0.4 raised the number of distinct threat types from eight to fifteen and 0.6 to eighteen.

Linux and Windows carry the same suite as of web 0.5.1.

### Prevention, DNS, VPN and signatures (0.6.0)

0.6 put every automatic block behind one enforcement engine and added three detection sources that the connection heuristics cannot reach. Each appears only when the server advertises it, and each carries the server's own status line — most of these need root, and a detector switched on but not running says why.

| Where | What you get |
|-------|--------------|
| **Controls → Dry run** | Auto-block walks every gate and reports what it *would* have dropped without writing a rule. Where a new detection source belongs before it is allowed to enforce |
| **Detection → Kernel flow events** | Conntrack `NEW` events, so a snapshot is taken because a connection arrived rather than because the poll timer fired |
| **DNS hygiene** | Plaintext DNS egress, encrypted DNS silently stopping, an unapproved resolver, a VPN client bypassing yours, and an allowlisted domain resolving into a network it has never used before. **Approved resolvers** is editable here — DoH is HTTPS on 443 and only counts as encrypted DNS when its destination is on that list |
| **VPN peers · WireGuard** | Peer monitoring plus the per-peer transfer threshold (off by default — a peer streaming video moves gigabytes). The peer table is read-only by design: revoking a peer is a WireGuard configuration change. Only public keys ever reach the app; the server drops private and preshared keys where it parses `wg show` |
| **Signatures · Suricata** | EVE ingestion, the feed path, the maximum severity accepted (Suricata counts down — 1 is most severe), and the muted signature ids that stop one noisy rule burying every other alert |

**Blocking a tunnel address.** The prevention engine screens CGNAT (100.64/10 — Tailscale and most WireGuard tunnels) out of auto-block entirely. A manual block still reaches it, so every **Block** button in the app routes through one confirmation first: the address is reachable, the block will succeed, and what it cuts off may be the tunnel you are managing the server through.

### Every warning says whether the address is blocked (0.6.3)

0.6.3 runs each batch of threats past the prevention engine *before* any alert about it leaves the machine, so a warning that names an address can also say whether that address is being stopped. The app carries the verdict everywhere it names one:

| Where | What it shows |
|-------|----------------|
| **Threats** | A badge per row — **Blocked** (red), **Dry run** / **Block failed** (amber), **Not blocked** (muted) — with the server's own sentence beside it saying *why*: the gate that stopped it, or the rule already in force |
| **Threats** | A row whose address is already blocked offers **Unblock** in place of **Block**, as the Hosts tab does. Re-blocking would only rewrite a rule that is already in force |
| **Needs-attention card** | The verdict sentence, and the **Blocked** state in place of the hero Block button once the server has already blocked it |
| **Critical notifications** | The title leads with it — `Blocked · Critical — <server>` or `NOT blocked · Critical — <server>` — and the body carries the full reason. A batch overflowing the per-alert cap reports the tally (`+3 more critical alerts — 2 of 3 blocked`) |
| **Critical banner** | The same sentence, and no Block button on an address already being dropped |

Dry run and a refused rule both read as **NOT blocked** in an alert, because neither one is stopping anything.

The verdict is deliberately left off the host-local detections. The server does answer for those (*"private address, never auto-blocked"*), but a new-listener or persistence-change row has already replaced the address with *what* was detected, precisely because there is no peer to firewall — a "No" beside it only raises a question the row has already answered.

**Auto-block has three states, not two.** The Dashboard control now reads **Auto-block off** / **Auto-block dry run** (amber) / **Auto-block on** (red), rather than showing a red "on" over an engine that is deliberately writing no rules. 0.6.3 publishes the engine's own `autoBlockSummary` for exactly this reason — every frontend used to rebuild that string and every one of them dropped dry run. The app keeps the button compact because the minimum level sits in its own chip beside it; the engine's full sentence still arrives in the status header the moment the toggle flips, and VoiceOver reads it from the button.

Servers older than 0.6.3 send none of these fields, so every badge, sentence and Unblock swap simply does not appear — the app behaves exactly as it did before.

### Sleep / Wake

The web console's header **Sleep ⇄ Wake** button, in the Dashboard controls and again under More → Monitoring.

Sleeping stops *everything the server watches* — the connection/port poll plus the auth-log, closed-port probe, ARP, startup-item, exfiltration and honeypot watchers, and on 0.6 servers the DNS, WireGuard, Suricata and kernel-event feeds too — so asleep means nothing is observed, not a frozen dashboard. **Firewall blocks stay in force**: sleeping stops watching, it never unblocks an address the machine is already protected from.

The app parks itself alongside the server, which is what makes Sleep feel different from a plain Pause:

- live readings dim on every data tab, so stale rows cannot be read as current traffic
- an **Asleep** banner explains what stopped and carries its own Wake button
- the 2.5-second poll drops to a 30-second heartbeat — that heartbeat is what lets a wake from the web console or another device still reach this phone
- Critical alerts are held: a sleeping console detects nothing, so anything left in its list is history

Sleep applies to the process you pressed it in, and the server does not persist it — restarting the service comes back up monitoring. **Pause/Resume** is still there and unchanged (monitor off, app keeps refreshing live); it is hidden while asleep, where Wake is the only sensible way back.

On servers older than web 0.5.1 the app sends `pause` / `resume` instead, which is the same monitor state under its earlier name.

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
used to cover the very card offering the same action. Acting on a threat — block, unblock,
clear — holds that banner back for 20s, since the refresh right after an action reliably
turns up the next backlog Critical and letting it slam over the confirmation reads as "your
block did nothing"; notifications, the tab badge and the Threats list are unaffected, only
the in-app banner waits its turn.

The activity chart is Swift Charts: drag anywhere on it to pin a sample and read its exact
connection, host and threat counts, with the same red markers and zero baseline the web
console uses.

### Remote access — HTTPS and DuckDNS (0.5.0)

**More → Remote access** and **Dynamic DNS & certificate** mirror the web console's own settings, because a console you reach from outside the LAN is exactly the one you cannot walk over to and fix.

The section leads with **This connection**, which reports `httpsActive` — what the server is serving right now. Everything below it is configuration: TLS endpoints are bound when the console starts, so the HTTPS switch, port, redirect and certificate/key paths are saved immediately and take effect at the next restart. The server validates a path as soon as it arrives and tries to load the pair, so a bad one is reported here rather than as a console that fails to come back up.

**Issue certificate** starts Let's Encrypt issuance through DuckDNS. It waits on DNS propagation and runs for minutes, so its progress arrives in the state poll rather than in the action's reply — the button disables itself while issuance is running and the outcome appears under it. The DuckDNS token is write-only: the server reports only whether one is stored and never sends it back, so the field always starts empty and saving it empty clears it.

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
