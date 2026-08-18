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
| **Data flow** | Bandwidth meter on Status: live in/out rates, this month a day at a time, the year a month at a time (web 0.7+) |
| **Firewall Config** | The whole host firewall — UFW's rules, WireGuard's, Docker's and this app's — in evaluation order, with add / edit / remove, the default policies, and what is listening behind them — tap a listening socket to start a rule for it (web 0.7+; host-wide on 0.7.4+) |
| **Hosts** | Remote peers with geo/threat badges; swipe to block/unblock |
| **Connections** | Live process + endpoint table; block remote peers |
| **More** | Listening ports, firewall rules, allowlist add/remove/refresh, server webhook URL, HTTPS + DuckDNS remote access and certificate issuance, change master password |
| **Alerts** | Time-sensitive notifications and in-app popups for Critical threats, leading with whether the address was blocked (web 0.6.3+), with catch-up on launch |
| **Secure storage** | Session tokens & optional remembered passwords in Keychain |

Talks to the same JSON API as the browser console (Linux, Windows & macOS web **0.3.x – 0.7.x**, current through **0.7.4**):

- `GET /api/auth/status`
- `POST /api/auth/login` · `/api/auth/setup` · `/api/auth/logout`
- `POST /api/auth/change-password` (0.3.2+) — `currentPassword`, `newPassword`, `confirm`
- `GET /api/state` (settings include `geoLookupEnabled` / `allowlistUseRemoteFeed` / `authLogMonitorEnabled` + `authLogStatus` / `probeLogEnabled` + `probeLogStatus` / `criticalAlertsEnabled`, on 0.4+ the intrusion-detection group, on 0.5+ the HTTPS/DuckDNS group, and on 0.6+ `preventionDryRun` / `conntrackEventsEnabled` / the DNS, WireGuard and Suricata groups, on 0.6.3+ `autoBlockSummary`, on 0.7+ `trafficMeterEnabled` + `trafficStatus`; threats include `ts` and on 0.6.3+ `blockStatus` / `blockShort` / `blocked`; rules include `isProtected`, `address`, `ports`; on 0.7+ the top-level `traffic` and `configRules`; on 0.7.4+ the top-level `hostFirewall` and `listeners`, and `configRules` entries gain `key` and `isForeign`)
- `POST /api/action` — `block`, `unblock`, `set_setting`, `block_port`, `unblock_port`, `remove_rule`, `remove_all_rules`, allowlist, auto-block, …
- `POST /api/action` — `save_config_rule` (web 0.7+) — `label`, `ruleAction`, `direction`, `protocol`, `ports`, `addresses`, and `replace` when editing rather than adding; on 0.7.4+ `key` instead of `replace` when the rule being edited belongs to the host
- `POST /api/action` — `delete_host_rule` (`key`) and `rescan_firewall` (web 0.7.4+)
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

### Data flow and Firewall Config (0.7.0 – 0.7.2)

0.7 added two readings the app had no equivalent for. Both appear only when the server sends them, so a 0.6 server's screens are unchanged.

**Data flow.** A bandwidth meter, on Status under the instrument panel. The counts in that panel are all cardinalities — connections, hosts, ports — and none of them move when one connection pulls a disk image at line rate; this is the reading that does. The card gives the live in/out rates and the month total, and opens onto three charts at coarsening time bases: the live window, this month a day at a time, and the last twelve months. They are separate charts rather than one zoomable one because they answer separate questions — *is something happening now*, *was yesterday unusual*, *are we going to blow through the cap* — and the middle one is unreadable at either of the other two scales.

Every figure is printed as the server formatted it. The server settled the byte convention once (SI, where 1 GB is 1,000,000,000 bytes — what link speeds and data caps use) and a phone re-deriving it would eventually disagree with the console about the same month. The raw numbers are used only to draw. Switching the meter on starts the counters from zero, which the toggle says out loud: turning it on to answer a question about last week cannot work, and the empty chart afterwards would otherwise look like a fault.

**Firewall Config.** Every rule the firewall evaluates, in the order it evaluates them, under More. This is not the existing *Firewall rules* list and the difference is the point: that one is the blocks this app and the prevention engine minted, which is the set you act on during an incident. This one is everything, engine blocks first and then the operator's own rules. A permissive rule sitting above a block is the misconfiguration the screen exists to make visible, and it is invisible in any list that leaves half the rules out. The order is therefore never re-sorted — not by name, not by action, not to group the editable ones.

Rules can be added, edited and removed. On a 0.7.0–0.7.3 server only a rule the operator wrote is editable: an engine block there is lifted by unblocking its address, not by rewriting the rule under it, which would leave the engine believing it still holds a block it no longer has. 0.7.4 lifts that restriction, because the server can then write through whichever backend owns the rule — see below. The console's own allow rule is marked and cannot be removed on any version.

**The server owns validation, and the form mirrors only part of it.** `save_config_rule` revalidates everything, and the guard against writing a rule that cuts off the console stays server-side because only the server knows which ports it listens on. What the form checks locally is the purely textual half — port tokens, ranges, addresses and CIDR blocks — so a typo is caught while the keyboard is still up. Two shapes are refused before sending: an Allow rule with protocol Any, no port and no address (which allows everything), and an inbound catch-all Block (which takes the machine off the network, this app's connection with it). A refusal from the server leaves the sheet open with its own wording on it; dismissing would look exactly like a rule that had been written.

Validation order matters and reversing it is dangerous rather than untidy: normalising re-renders the port field from what parsed and drops what did not, so `443-80` would come out as an empty port field — and an empty port field means *every port*. What was typed is validated, never what was normalised. The server carries the same warning over `FirewallRuleSpecs.TryPrepare`.

0.7.2's upgrade banner is deliberately not ported. It fixes a browser-only problem — an open tab keeps the markup it was served, so a console upgraded underneath it silently lacks the new UI. The app re-decodes `/api/state` on every poll and has no stale markup to reconcile.

### The whole host firewall (0.7.4)

**It is 0.7.4, not 0.7.3.** The rebuild was written against a 0.7.3 tree, but 0.7.3 was packaged and installed before it merged, so no build carrying that number has it — the server re-released the same work as 0.7.4 rather than let two different binaries claim one version. A server reporting 0.7.3 behaves like 0.7.2 here. None of it is version-sniffed either way: every screen below keys off whether the fields arrive.

Firewall Config used to list this app's own ledger and nothing else. On a machine running UFW that is a near-empty page sitting beside a firewall full of rules — and the rules Network Sentinel wrote were invisible in `ufw status` in turn, so neither view was the firewall. 0.7.4 makes the server read all of it: `ufw status verbose`, `nft -j list ruleset` keeping each handle, `iptables -S`, and `ss -tulpnH`. UFW's helper chains and the established/loopback boilerplate fold out; UFW's rules, WireGuard's, Docker's and ours fold into one list, each row tagged with who wrote it. One machine has one firewall, and both front-ends now show it.

**The screen leads with what the machine is.** Backend, whether it is switched on, and the default policies, because the default is what decides how every Allow row below it should be read: under a default of Drop an Allow rule is what makes a service reachable at all, under Accept it only opens a path through the rules above it. The same header carries the privilege note — the scans are inspections that never raise a password dialog, so an unelevated server still answers, with a short list and a line saying that is why. A short list is not an empty firewall and the two are not shown as though they were.

**Rules are addressed by shape, not by name.** Names are not unique across a host — two UFW rules can both be called `allow-inbound-ssh` — so the server sends each row a `key` built from its whole shape, and `delete_host_rule` takes that. An ambiguous match is refused rather than guessed at. The app sends `key` for a rule the host owns and the old `remove_rule`/`replace` path for one of its own, because a rule this app wrote still has a ledger entry and its bookkeeping has to stay truthful.

**Editing a foreign rule is a replace, and the sheet says so.** UFW has no in-place edit, so saving removes the original where it lives and writes the values as a new rule — which moves it in evaluation order. That is a different thing from editing one of our own rules and is worth reading before pressing Save, so it is stated on the sheet rather than discovered afterwards.

**Removal warnings are per rule.** A foreign rule says it belongs to something else and is going for good; an engine block says the traffic is unblocked until something detects it again; and any Allow rule whose ports admit 22 says that removing it can end the SSH session the host is administered over. That last check expands ranges rather than matching text, so `20-25` triggers it and `2222` does not.

**Listening** sits under the rules, and the pairing is the reading. The rules say what the firewall would do; the listener list says what is actually accepting connections. A listener the firewall does not admit is not reachable however loudly it is listening, and a listener nothing covers is the row to read first. Each one carries the server's own verdict — Open, Restricted, Not allowed, Local only, No firewall.

**One row per bind address, and a rule can be started from any of them.** The list is the set `ss -tuln` prints, bind addresses included, so a service like NetBIOS shows its separate rows on `0.0.0.0`, the LAN address and the broadcast address rather than one collapsed entry — which of them is listening is the thing a rule is written about. Tapping a row, or swiping it, opens the rule sheet on that socket: inbound, its protocol, its port. That is the point of listing the sockets next to the rules, since the alternative is reading the port off `ss` in a terminal and retyping it, which is how a port goes missing from the rule set.

**The bind address deliberately does not carry into Addresses**, and the sheet says so where the empty field is. On an inbound rule that field matches the *far end* of a connection, so seeding it with `0.0.0.0`, `::` or this host's own LAN address would write a rule matching nothing an attacker sends. A socket whose port is not a plain number — `ss` labels some kernel sockets rather than numbering them — has nothing to prefill, so the tap is answered with that sentence instead of a form the server would refuse a round trip later.

**Listeners arrive even when no firewall could be read.** They come from `ss`, which needs no privilege, so an unprivileged server and a host with no firewall configured both still send the inventory, each row carrying a **No firewall** verdict. The section is therefore drawn empty rather than hidden on a 0.7.4 server that reports none — "nothing is listening" and "the screen has nothing to say" are different readings and should not look the same.

**Rescan is separate from pull-to-refresh, because they do different things.** The scan shells out to four tools, and `/api/state` is polled every couple of seconds, so the server caches it. Pulling to refresh re-reads the server's cached scan; Rescan re-reads the kernel. Every write invalidates the cache server-side, so Rescan is for the case where something else changed the firewall underneath the app.

A 0.7.0–0.7.3 server sends no `hostFirewall`, no `listeners` and no `key`, so the screen falls back to exactly what it was: this app's ledger, one list, with only the operator's own rules editable.

0.7.4 also splits a bind `address` out of each `ports` entry, beside the `endpoint` the payload already carried. The app does not decode it: More's *Listening ports* prints `endpoint`, which is that address and the port already joined, and the web console's own Open Ports table still prints the same field.

The 0.7.4 web console's `blockedCount` is not ported. It is the hero subtitle on a page that has one; the app's blocked addresses are a list you scroll under More, not a number over a banner.

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
