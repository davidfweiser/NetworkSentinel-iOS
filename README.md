# Network Sentinel — iOS

Modern iOS companion for **Network Sentinel** web servers (Linux, Windows & macOS).

Connect to one or more hosts running the headless web UI (`-w` / `--web`), sign in with the master password, and monitor critical network state from your iPhone or iPad.

## Features

| Area | What you get |
|------|----------------|
| **Multi-server** | Add/edit/delete servers; switch between home, lab, VPS, etc. |
| **Dashboard** | Needs-attention card with one-tap block, live stats, scrubbable activity chart, sleep/wake, pause/resume, auto-block controls and rule expiry, and the way through to Data flow |
| **The console's rail** | All ten of the browser console's menu entries, in its order, under its names, with its status block — one tap from every screen. Plus **Blocked Sites**, the eleventh, which appears only where the console shows it: on a server with a filtering resolver (0.7.15+) |
| **Sleep / Wake** | Stops every watcher on the server and parks the app — dimmed data, an Asleep banner on each live tab, a 30-second heartbeat, no Critical alerts. Firewall blocks stay in force |
| **Settings** | The console's own Settings page, entire — every group it has, in its order, with its titles and its explanations. **Monitoring** (live monitoring, refresh speed, geo lookups, auth-log, closed-port scan, kernel flow events, traffic metering, server Critical alerts) · **Intrusion detection** (threat-intel, new-listener, process reputation, ARP/gateway, startup-item, exfiltration + threshold, honeypot + decoy ports) · **DNS hygiene** · **DNS filtering** (0.7.15) · **VPN (WireGuard)** with the read-only peer table · **Signatures (Suricata)** · **Alerting** · **Remote access** including HTTPS-only (0.7.6) · **Auto-block** · **Allowlist** · **Danger zone**. Anything the browser can change on that server, this changes |
| **Break-in Attempts** | Severity filters, search, clear alerts, block source IP — each row saying whether that IP is actually blocked (web 0.6.3+) |
| **Data flow** | Bandwidth meter on Dashboard: live in/out rates, this month a day at a time, the year a month at a time (web 0.7+) |
| **Firewall** | Opens on **Firewall Config**, with **Firewall & Block** (managed blocks, manual IP blocking, *Authorize firewall*, *Remove all*), **Open Ports** and **Allowlist** a tap inside it. Firewall Config is the whole host firewall — UFW's rules, WireGuard's, Docker's and this app's — in evaluation order, with add / edit / remove, service presets, the default policies, and what is listening behind them; tap a listening socket to start a rule for it (web 0.7+; host-wide on 0.7.4+) |
| **Blocked Sites** | The names your filtering resolver refused — what, from which client, why, and under which rule — newest first, 50 to 500 at a time. Read when the screen opens and when it is pulled, never on the poll (web 0.7.15+) |
| **Connections** | One tab, two readings of who this machine is talking to, switched by a picker in the navigation bar: **Remote Computers** — peers with geo/threat badges, swipe to block/unblock — and **Live Connections** — the process + endpoint table, with blocking on the row |
| **This device** | First in Settings and unique to the app: which server, its address, the master password, sign-out, this iPhone's own Critical alerts and background polling, and how fast this phone polls |
| **Alerts** | Time-sensitive notifications and in-app popups for Critical threats, leading with whether the address was blocked (web 0.6.3+), with catch-up on launch |
| **Secure storage** | Session tokens & optional remembered passwords in Keychain |

Talks to the same JSON API as the browser console (Linux, Windows & macOS web **0.3.x – 0.7.x**, current through **0.7.15**):

- `GET /api/auth/status`
- `POST /api/auth/login` · `/api/auth/setup` · `/api/auth/logout`
- `POST /api/auth/change-password` (0.3.2+) — `currentPassword`, `newPassword`, `confirm`
- `GET /api/state` (settings include `geoLookupEnabled` / `allowlistUseRemoteFeed` / `authLogMonitorEnabled` + `authLogStatus` / `probeLogEnabled` + `probeLogStatus` / `criticalAlertsEnabled`, on 0.4+ the intrusion-detection group, on 0.5+ the HTTPS/DuckDNS group, and on 0.6+ `preventionDryRun` / `conntrackEventsEnabled` / the DNS, WireGuard and Suricata groups, on 0.6.3+ `autoBlockSummary`, on 0.7+ `trafficMeterEnabled` + `trafficStatus`; threats include `ts` and on 0.6.3+ `blockStatus` / `blockShort` / `blocked`; rules include `isProtected`, `address`, `ports`; on 0.7+ the top-level `traffic` and `configRules`; on 0.7.4+ the top-level `hostFirewall` and `listeners`, and `configRules` entries gain `key` and `isForeign`; on 0.7.6+ `httpsOnly`; on 0.7.10+ `hostFirewall.canWriteRules` and the five `elevation*` strings that go with it; on 0.7.15+ `dnsFilterEnabled` / `dnsFilterConfigured` / `dnsFilterUrl` / `dnsFilterUsername` / `dnsFilterPasswordSet` / `dnsFilterStatus`)
- `POST /api/action` — `block`, `unblock`, `set_setting`, `block_port`, `unblock_port`, `remove_rule`, `remove_all_rules`, allowlist, auto-block, …
- `POST /api/action` — `save_config_rule` (web 0.7+) — `label`, `ruleAction`, `direction`, `protocol`, `ports`, `addresses`, and `replace` when editing rather than adding; on 0.7.4+ `key` instead of `replace` when the rule being edited belongs to the host
- `POST /api/action` — `delete_host_rule` (`key`) and `rescan_firewall` (web 0.7.4+)
- `GET /api/dns-blocked?limit=N` (web 0.7.15+) — `{ ok, message, entries[] }`, each entry `time` / `domain` / `client` / `reason` / `rule`. Read when Blocked Sites opens, when the count changes and on pull-to-refresh — **never on the poll**: the query log is the heaviest document the resolver serves, and that resolver is what every tunnel client resolves through. A 404 means this server has no such page; a 200 with `ok: false` means it has one and could not reach its resolver, and its message says which
- `GET /api/hostfirewall` (+ `?rescan=1`) — the same `hostFirewall` / `configRules` / `listeners` on their own endpoint, which is where a **Windows** 0.7.4 server keeps them. Read when the Firewall screen opens, after a write, on pull-to-refresh and on Rescan; a 404 means this server has no such route and whatever `/api/state` carries is all there is
- `POST /api/action` — `sleep` / `wake` (web 0.5.1+), falling back to the `pause` / `resume` names every 0.3–0.5.0 server drives the same monitor state under
- `POST /api/action` — `issue_cert` (web 0.5+)

`set_setting` carries booleans as `"true"`/`"false"` and the numeric/text settings as their literal value, including the empty string that switches the webhook off, un-mutes every Suricata signature, or clears the approved-resolver list.

Sessions use the web UI’s `ns_session` cookie, sent as `Authorization: Bearer` from the app.

Compatible with older web servers for core monitor/block; newer settings and actions appear only when the server advertises them, so the detection toggles stay hidden on servers that predate them.

### Detection settings (0.3.4 – 0.3.5)

- **Auth-log monitoring** — watches system auth logs for failed SSH/PAM logons and raises brute-force threats. On macOS this reads the unified log (sshd, sudo, login, Screen Sharing).
- **Closed-port scan detection** — installs a rate-limited firewall SYN-log rule (needs elevation on the server) and watches the kernel log — PF plus `pflog0` on macOS — catching port scans that never show up as connections.
- **Critical alerts on server** (0.3.5+) — the server's own Critical warnings: a desktop notification from its GUI and a tab-title badge in its web console. On by default.

The first two toggles show the server's own status line, so you can tell when a feature is on but blocked (for example, waiting on elevation — use **Authorize firewall** on Firewall & Block).

### Intrusion detection (0.4.0)

A second card on Detection, reached from Status, shown only against servers that advertise the suite. Each row carries the server's own status line where it publishes one, so a detector that is switched on but not actually running says why.

| Setting | What the server does |
|---------|----------------------|
| **Threat-intel blocklists** | Checks remote peers against FireHOL level1 and Spamhaus DROP; a listed peer is an instant Critical |
| **New-listener alerts** | Diffs listening ports against a persisted baseline — a new port is Medium, a known port changing owner process is High |
| **Process reputation** | Unsigned or quarantined binaries talking to public hosts, executables in temp/download folders, shells with outbound connections |
| **ARP / gateway watch** | Gateway MAC change (Critical) and duplicate MAC on the LAN (High) |
| **Launch-item watch** | LaunchAgents / LaunchDaemons additions and modifications |
| **Exfiltration monitor** | Outbound bytes to one non-allowlisted public host, with a threshold picker (default 250 MB / 10 min; the server's floor is 10) |
| **Honeypot decoy ports** | Binds decoy TCP ports; any completed connection is Critical. The port list is editable, and the server refuses its own console port |

Two more 0.4 settings live where they belong rather than in that card: **auto-block rule expiry** sits with the other auto-block controls (Never / 1 hour / 6 hours / 24 hours / 7 days), and the server's **webhook URL** is in Settings, next to this device's alerts — it is the one alert path that still works when the phone is asleep or the app has been force-quit.

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
| **VPN peers · WireGuard** | Peer monitoring plus the per-peer transfer figure (off by default — a peer streaming video moves gigabytes). 0.7.15 renamed it from an *alert* to a **notice** and demoted what it emits from a High *Data exfiltration* to an Info *VPN peer change*: all that counter can see is encrypted volume, and volume through a tunnel is the tunnel working. The peer table is read-only by design: revoking a peer is a WireGuard configuration change. Only public keys ever reach the app; the server drops private and preshared keys where it parses `wg show` |
| **Signatures · Suricata** | EVE ingestion, the feed path, the maximum severity accepted (Suricata counts down — 1 is most severe), and the muted signature ids that stop one noisy rule burying every other alert |

**Blocking a tunnel address.** The prevention engine screens CGNAT (100.64/10 — Tailscale and most WireGuard tunnels) out of auto-block entirely. A manual block still reaches it, so every **Block** button in the app routes through one confirmation first: the address is reachable, the block will succeed, and what it cuts off may be the tunnel you are managing the server through.

### Every warning says whether the address is blocked (0.6.3)

0.6.3 runs each batch of threats past the prevention engine *before* any alert about it leaves the machine, so a warning that names an address can also say whether that address is being stopped. The app carries the verdict everywhere it names one:

| Where | What it shows |
|-------|----------------|
| **Threats** | A badge per row — **Blocked** (red), **Dry run** / **Block failed** (amber), **Not blocked** (muted) — with the server's own sentence beside it saying *why*: the gate that stopped it, or the rule already in force |
| **Threats** | A row whose address is already blocked offers **Unblock** in place of **Block**, as the Hosts list does. Re-blocking would only rewrite a rule that is already in force |
| **Needs-attention card** | The verdict sentence, and the **Blocked** state in place of the hero Block button once the server has already blocked it |
| **Critical notifications** | The title leads with it — `Blocked · Critical — <server>` or `NOT blocked · Critical — <server>` — and the body carries the full reason. A batch overflowing the per-alert cap reports the tally (`+3 more critical alerts — 2 of 3 blocked`) |
| **Critical banner** | The same sentence, and no Block button on an address already being dropped |

Dry run and a refused rule both read as **NOT blocked** in an alert, because neither one is stopping anything.

The verdict is deliberately left off the host-local detections. The server does answer for those (*"private address, never auto-blocked"*), but a new-listener or persistence-change row has already replaced the address with *what* was detected, precisely because there is no peer to firewall — a "No" beside it only raises a question the row has already answered.

**Auto-block has three states, not two.** The Status control now reads **Auto-block off** / **Auto-block dry run** (amber) / **Auto-block on** (red), rather than showing a red "on" over an engine that is deliberately writing no rules. 0.6.3 publishes the engine's own `autoBlockSummary` for exactly this reason — every frontend used to rebuild that string and every one of them dropped dry run. The app keeps the button compact because the minimum level sits in its own chip beside it; the engine's full sentence still arrives in the status header the moment the toggle flips, and VoiceOver reads it from the button.

Servers older than 0.6.3 send none of these fields, so every badge, sentence and Unblock swap simply does not appear — the app behaves exactly as it did before.

### Data flow and Firewall Config (0.7.0 – 0.7.2)

0.7 added two readings the app had no equivalent for. Both appear only when the server sends them, so a 0.6 server's screens are unchanged.

**Data flow.** A bandwidth meter, on Status under the instrument panel. The counts in that panel are all cardinalities — connections, hosts, ports — and none of them move when one connection pulls a disk image at line rate; this is the reading that does. The card gives the live in/out rates and the month total, and opens onto three charts at coarsening time bases: the live window, this month a day at a time, and the last twelve months. They are separate charts rather than one zoomable one because they answer separate questions — *is something happening now*, *was yesterday unusual*, *are we going to blow through the cap* — and the middle one is unreadable at either of the other two scales.

Every figure is printed as the server formatted it. The server settled the byte convention once (SI, where 1 GB is 1,000,000,000 bytes — what link speeds and data caps use) and a phone re-deriving it would eventually disagree with the console about the same month. The raw numbers are used only to draw. Switching the meter on starts the counters from zero, which the toggle says out loud: turning it on to answer a question about last week cannot work, and the empty chart afterwards would otherwise look like a fault.

**Firewall Config.** Every rule the firewall evaluates, in the order it evaluates them, under Firewall & Block. This is not the existing *Firewall rules* list and the difference is the point: that one is the blocks this app and the prevention engine minted, which is the set you act on during an incident. This one is everything, engine blocks first and then the operator's own rules. A permissive rule sitting above a block is the misconfiguration the screen exists to make visible, and it is invisible in any list that leaves half the rules out. The order is therefore never re-sorted — not by name, not by action, not to group the editable ones.

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

0.7.4 also splits a bind `address` out of each `ports` entry, beside the `endpoint` the payload already carried. The app does not decode it: *Open Ports* prints `endpoint`, which is that address and the port already joined, and the web console's own Open Ports table still prints the same field.

**Two servers, two deliveries.** A Linux or macOS server puts the scan in `/api/state`: `ufw`, `nft` and `ss` are fast enough to cache behind a 2.5-second poll. A Windows server does not — `netsh` takes seconds on a host carrying a few thousand rules, and the payload is hundreds of KB — so 0.7.4 there serves the whole scan from `GET /api/hostfirewall`, read when the page is opened, after a write, and on Rescan. Its own console works exactly that way. The app now reads whichever one this server uses, and the screen cannot tell the difference: it shows *Reading the host firewall…* while the request is out, the failure with a Try again if it fails, and — only once the endpoint has answered 404 with no `configRules` in state — that this server has no Firewall Config page at all. That last case used to be silent, with the tab quietly opening a different screen, which reads as the app having lost a feature rather than the server not having one.

A rule's `key` is its shape, and the Windows Firewall holds the same shape once per profile — so several rows can arrive carrying one key, which SwiftUI's `ForEach` reads as one row appearing repeatedly. Row identity is disambiguated locally (the same `uniquedRows()` the connection and threat tables use); the key itself still goes to the server untouched, where an ambiguous one is the server's to refuse rather than the app's to guess at.

Windows also says **Allow/Block** where Linux says **Accept/Drop**, so the default-policy reading takes both vocabularies — matching only Accept called a permissive Windows host locked down, which is the worst way round to get it. And because the Windows Firewall stores one rule per profile and protocol, the scan folds identical rows: a folded row is marked `×4` and the header says how many were folded and how many disabled rules were left out, so the count here and the count in `netsh` agree.

**The screen carries the same fields the console and the desktop grid do.** Each rule row prints Label, Action, Protocol, Port range, Sources (Destinations on an outbound rule) and Created by — in the server's own wording, so a rule matching everything reads `All ports` and `All IPv4, All IPv6` rather than as two blank cells, and a long source list wraps instead of being clipped. Above the lists the header says how much of the firewall is this app's: *N from Network Sentinel, M from the rest of the host*, with the scan's own description of what it read and the listener line's *29 listening sockets · 4 reachable from anywhere*.

**And it is out of More.** The console carries Firewall Config in its navigation rail and the desktop as a view in its menu; on the phone it was two taps down inside More, next to the webhook URL. It is the **Firewall** tab now — see [Navigation](#navigation-the-consoles-rail-on-a-phone).

**And the same edits.** Edit and Delete sit on the row as buttons rather than only behind a swipe — a swipe is idiomatic but invisible until you try it, and the console and the desktop both put the two verbs where the rule is. Adding asks for a direction first, from the toolbar or from the foot of either list, because that is the first thing a rule is. The form carries the **service presets** both other front-ends fill protocol and port from — SSH, HTTP, HTTPS, DNS, MySQL, PostgreSQL, WireGuard, the web console's own ports, ICMP — and drops back to *Custom* the moment either field is typed over. The address field is headed **Sources** or **Destinations** with the direction, since on an outbound rule the far end is not a source, and the sheet is titled *Add an Inbound Rule* / *Edit an Outbound Rule* the way the console's editor heading is.

The 0.7.4 web console's `blockedCount` is not ported. It is the hero subtitle on a page that has one; the app's blocked addresses are a list you scroll under Firewall & Block, one tap inside the Firewall tab, not a number over a banner.

### HTTPS only, and a firewall that admits it cannot be written (0.7.6 – 0.7.13)

Two things the console gained while the app was at 0.7.4, both of which change what the app should offer rather than only what it shows.

**HTTPS only** (0.7.6) drops the plain-HTTP listener entirely, so the master password can only cross the wire encrypted. It sits in **Settings → Remote access** under the redirect switch, and it is drawn only when the server sends `httpsOnly` — the field's arrival is the version check, and a switch that writes `Unknown setting` to a 0.7.5 server reads as a control that does nothing. The server refuses the change while HTTPS is off or its certificate will not load, deliberately, so a bad certificate cannot lock the console out; its refusal is surfaced verbatim.

**Read-only firewalls** (0.7.10) close a gap that was the app's worst kind of lie. A server reads the whole ruleset through `sudo -n` and can still have no way to change any of it — a user service with no passwordless sudo and no `CAP_NET_ADMIN` reads everything and writes nothing. Until 0.7.10 nothing said so until Save had already failed, which reads as the app being broken rather than the host being locked down. The server now decides it up front and publishes `canWriteRules` with the two remedies attached, capability first.

When it says no, the app stops offering what cannot happen: the **+** in the toolbar is disabled, the *Add an Inbound/Outbound Rule* rows are gone, every rule row reads **read-only** where its Edit and Delete were, tap-to-edit and the swipe actions are off, and the listening rows no longer invite a rule that could not be written. Above the lists sits the console's own amber notice — the lead, the `setcap` line, the sudoers alternative, and the tail — with each command block selectable and carrying a copy button, since the phone cannot run either one and the point of showing them is getting them onto the machine that can.

`canWriteRules` absent is **not** a no. A 0.7.0–0.7.9 server never sends the field and writes rules perfectly well, so silence leaves every affordance exactly where it was.

### Settings: the console's page, entire (0.7.13)

The app used to spread the server's configuration over three screens of its own devising — a **Detection** list of eighteen switches grouped by what each detector looks at, an **Enforcement** sheet holding the four that change what blocking does, and a **Settings** list holding the server picker, this device's alerts, the webhook and remote access. Three screens, three groupings, none of them the console's. Someone who knew where *Exfiltration threshold* lived in the browser knew nothing about where it lived here.

There is now one Settings screen and it is the console's page: **Monitoring · Intrusion detection · DNS hygiene · VPN (WireGuard) · Signatures (Suricata) · Alerting · Remote access · Auto-block · Allowlist · Danger zone**, in that order, with the console's own titles and the console's own sentence under each row. Each group's explanatory note comes over too — the paragraphs above DNS hygiene, WireGuard and Suricata that say why the group exists at all, without which those groups are switches nobody can weigh.

Three things are the app's rather than the console's:

- **Server** comes first. A browser is already at the console it is configuring; a phone talks to several, so which one, its address and its master password precede anything the server itself holds.
- **A filter box** sits above the groups. Forty-odd rows fit a 1400px desktop in one screen and take eleven scrolls here. It matches titles, explanations, setting keys and the server's status lines, and a group with nothing left in it removes its own heading.
- **On, but not running** interrupts the page when a detector is switched on that the server says it cannot actually run, with the server's own wording and an *Authorize* button. The console has no need of it — it appends each detector's status to its row and a desktop shows twenty rows at once. A phone shows three, so the one that matters is lifted to the top.

Every row is drawn from the settings payload, so a setting a server does not report is a row that is not there. That is the only version check the screen does, and it is why the same screen serves a 0.3.4 server and a 0.7.15 one.

**Page refresh speed** is the one row whose value never leaves the device. It is per-browser in the console — it lives in that browser's storage, not on the server — so it is per-device here, and it persists: a phone on a metered connection should not have to re-choose ten seconds every launch.

### DNS filtering, and the names it refused (0.7.15)

The console gained the one control in this product that stops a connection from ever being attempted, and the app carries both halves of it.

Everything else here acts on a flow that already exists: the prevention engine writes a rule for an address the socket tables have already seen. On a VPN gateway a client's forwarded traffic never becomes a tracked connection at all — it has no local socket — so nothing else in this app can decide where a tunnel client goes. A resolver that refuses to answer can, because the client learns no address and dials nothing.

**Settings → DNS filtering** is its own group, sitting under DNS hygiene and deliberately not inside it: hygiene *watches* queries, this *refuses* them. Four rows — the switch, the resolver's admin address, its user, and its password. The password follows the DuckDNS token's contract exactly: the server sends back only whether one is stored, so the field always opens empty and an empty save removes it.

The switch turns **filtering** on and off, not the resolver. Stopping the resolver would take name resolution away from every tunnel client at once, which is an outage rather than "filtering off" — so what the switch writes leaves DNS answering normally, unfiltered. And unlike every other toggle on that page, this one talks to a second machine, so its failures are surfaced verbatim: *the resolver rejected the credentials*, *no answer within 6s*. The status line beside it is also the only thing that separates **off** from **unreachable** — the server reads the live state back from the resolver rather than trusting a stored flag, because a switch reading "on" while nothing is being filtered is worse than no switch at all.

**Blocked Sites** is the second half: what the filtering actually caught. Each row is one refused query — the name, the client that asked, why it was refused (Blocklist, Safe browsing, Parental, Blocked service, Safe search) and the rule that matched — newest first, 50 to 500 at a time.

Three things about that screen are the server's design and are kept:

- **It is not on the poll.** The query log is the busiest thing the resolver serves, and every tunnel client depends on that resolver for name resolution. It is read when the screen opens, when the count changes and on pull-to-refresh. Nothing else in this app is fetched that way except the Windows firewall scan, and for the same kind of reason.
- **The server's sentence is the diagnosis.** *Nothing blocked yet — the log is empty, or the query log is switched off in AdGuard* is something the phone cannot work out for itself, so it is shown as written rather than flattened into "no results".
- **It says what it cannot see.** This is a name-based block: a client that dials a hard-coded address never asks a resolver anything, so it is never refused and never appears here. An empty list does not mean nothing was attempted, and the screen says so above the list rather than in this file.

**Where it lives.** A top-level entry in the console's rail, between *Allowlist* and *Settings*, and the same here — but only when the server reports `dnsFilterConfigured`. The console hides its own nav item on that field for a good reason: a list of refused names with no resolver behind it has nothing to say. On the phone the entry is a push onto the Firewall tab, which is already the tab that answers *what is being blocked*; it is the same question one layer down.

### Navigation: the console's rail on a phone

The web console and the desktop carry the same menu, so the app carries it too. Their rail reads **Dashboard · Live Connections · Remote Computers · Break-in Attempts · Open Ports · Firewall & Block** (with *Firewall Config* and *Allowlist* indented under it) **· Settings** (with *Help* under it) — ten entries, which is four more than a tab bar holds. 0.7.15 adds an eleventh, *Blocked Sites*, on the servers that have a filtering resolver.

The app's answer used to be that the other five were somewhere sensible: Open Ports and Allowlist a row inside the Firewall tab, Remote Computers a segment of the Connections picker, Help a row under Settings. Sensible, and not the same menu — someone who knows where *Allowlist* is in the console knew nothing here.

So **the rail comes over whole.** The button in the leading slot of every navigation bar (and in the Dashboard's own header, which draws no navigation bar) opens it: all ten entries in the console's order, under the console's names, the two sub-entries indented under their parent with the console's tooltips as their subtitles, the checked one carrying the same ringed dot, and each entry showing what its screen holds — 41 connections, 4 rules, 2 allowlist entries. Under it sits the rail's own **status block**, as on the desktop: what the monitor is doing, whether the firewall can be written, and the auto-block switch with the server's own summary of what it will do.

The tab bar stays. It is the fast path to the five screens a phone lives in, and the rail is the map — the same relationship the desktop has between its toolbar and its rail. The mapping:

| Console rail | In the app |
|---|---|
| Dashboard | **Dashboard** tab |
| Break-in Attempts | **Break-ins** tab — the screen is titled *Break-in Attempts* |
| Live Connections · Remote Computers | One **Connections** tab, switched by the picker in its navigation bar; each side keeps the console's title |
| Firewall Config | **Firewall** tab — the whole host firewall is what the tab opens on |
| Firewall & Block · Open Ports · Allowlist | Rows at the top of it, in that order |
| Settings | **Settings** tab |
| Blocked Sites (0.7.15+) | A push onto the **Firewall** tab, and only on a server that reports a filtering resolver — as the console only shows the entry there |
| Help | A row under Settings, and a rail entry that opens the console's Help page as a sheet |

Every one of these is reachable directly from the rail, including the four that are a push inside a tab: choosing *Open Ports* switches to the Firewall tab **and** pushes Open Ports onto it, and choosing *Live Connections* switches to the Connections tab **and** sets its picker, rather than landing you one tap short.

Three decisions worth stating. **Live Connections and Remote Computers share a tab** because they are two readings of one question — a host is the actor, a connection is what it is doing right now — and spending two of five slots on that distinction is what would leave the firewall without one. **Open Ports moved into the firewall group** rather than staying beside the settings, because a listening port is something you decide about: the console keeps it immediately above Firewall & Block, and every row there is one tap from a block.

And the group is entered from the **opposite end to the console's**. The rail indents Firewall Config under Firewall & Block; the tab opens on Firewall Config, with Firewall & Block a row inside it. A phone has one tab for the group and the whole host firewall is the bigger reading — the console's page shows this app's own blocks, and on a UFW box that is a fraction of the rules the kernel is evaluating. The blocks are still there, one tap in, which is the list you want during an incident. On a server older than 0.7 there is no Firewall Config page in the console either, so the tab opens on Firewall & Block instead.

Tab labels are shortened where the bar would clip them (*Break-ins*, *Connections*, *Firewall*); every screen carries the console's own name in its title, so the vocabulary you learn in the browser is the vocabulary on the phone.

### Sleep / Wake

The web console's header **Sleep ⇄ Wake** button, in the Dashboard controls and again under Settings → Monitoring.

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
| **Critical alerts on this device** (Settings → Alerts) | On the iPhone, stored locally | Local notifications and in-app popups from this app, foreground and via Background App Refresh |
| **Critical alerts on server** (Status → Detection) | On the server, web 0.3.5+ | Desktop notification from the server's GUI, tab badge + browser notification in its web console |

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

### The console's own vocabulary

The web console, the desktop window and this app are one product, and for a long time only
the palette said so — `NSTheme` is `WebApp.cs`'s `:root` block, value for value, and has been
since the first release. But a palette is not a look. Every surface the console draws has a
*shape* as well as a colour: a panel is an 18px card with a heading, a line of context under
it and its one action pinned to the right of that row; a setting is a title, the sentence
that says what it does, and a control at the far end; a group of settings carries a tracked
uppercase caption; a command you cannot run from here sits in a selectable monospace block.

Those shapes are what make the console recognisable, and `Views/Components/ConsoleKit.swift`
ports them: the panel and its heading row, the five button kinds (ghost, the accent-gradient
primary, the outlined danger, the filled Remove, the amber Wake), the 44×24 gradient switch,
the setting row and its group caption, the explanatory note, the stat card, the threat-
intensity pulse and month panel the console gained in 0.7.8, the amber elevation banner, the
chip, the status dot, and the dropdown. Sizes are the console's rem values converted at 16px,
so a row that is `.92rem` there is 15pt here.

Two palette tokens came over with them. The console draws `--text2` (#8a94a6) and `--muted`
(#636b78) at genuinely different weights — a panel's sub-line against a setting's description
— and the app had collapsed both into one, which flattened every screen that has both.

Liquid Glass is still the app's, and still where it belongs: floating chrome, the tab bar,
the alert banners, the sleep notice. A hundred glass rows in a scroll view is both wrong and
slow, and the console's flat card is what a settings page is made of.

### Severity drives the surface

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

**Settings → Remote access** and **Dynamic DNS & certificate** mirror the web console's own settings, because a console you reach from outside the LAN is exactly the one you cannot walk over to and fix.

The group leads with **This connection**, which reports `httpsActive` — what the server is serving right now. Everything below it is configuration: TLS endpoints are bound when the console starts, so the HTTPS switch, port, redirect and certificate/key paths are saved immediately and take effect at the next restart. The server validates a path as soon as it arrives and tries to load the pair, so a bad one is reported here rather than as a console that fails to come back up.

**Issue certificate** starts Let's Encrypt issuance through DuckDNS. It waits on DNS propagation and runs for minutes, so its progress arrives in the state poll rather than in the action's reply — the button disables itself while issuance is running and the outcome appears under it. The DuckDNS token is write-only: the server reports only whether one is stored and never sends it back, so the field always starts empty and saving it empty clears it.

**HTTPS only** (0.7.6) is the last switch in the group, and the strictest: it skips the plain-HTTP listener entirely so the master password can only cross the wire encrypted. It needs HTTPS on with a working certificate, and if the certificate fails to load at startup the server keeps plain HTTP on rather than lock the console out.

### Changing the master password

**Settings → Master password** calls the 0.3.2+ endpoint. The server keeps this device signed in and revokes every other session; if you saved the password on this device, the Keychain copy is updated so background refresh keeps working.

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

### Transport security

The web UI typically serves **plain HTTP** on the LAN, and the app allows exactly that — App Transport Security is scoped to local networking (`NSAllowsLocalNetworking`), so private addresses (`192.168.x.x`, `10.x.x.x`, CGNAT/Tailscale ranges, `.local` names) work over http.

A **public hostname is different**: the master password and session token would cross the internet with it, so a scheme-less public hostname (say a DuckDNS domain) normalizes to `https://`, and ATS refuses cleartext to public hosts outright. For remote access, enable HTTPS on the server first — **Settings → Remote access** in the app configures it, including Let's Encrypt issuance through DuckDNS.

A console served under a reverse-proxy subpath (e.g. `https://host/sentinel`) is supported — the path is kept when building API requests.

## First launch

1. **Add server** — name + base URL (`http://host:port`)
2. **Setup or sign in** — create master password (first visit) or enter existing one
3. Optionally **Remember on this device** (Keychain)
4. Use tabs: Dashboard · Break-ins · Connections · Firewall · Settings — see [Navigation](#navigation-the-consoles-rail-on-a-phone)

## Project layout

```
NetworkSentinel-iOS/
  project.yml                 # XcodeGen spec
  NetworkSentinel/
    NetworkSentinelApp.swift
    NetworkSentinel.entitlements   # Time Sensitive Notifications
    Theme.swift               # Palette, ambient field, glass surfaces
    Models/
    Services/                 # API client, server store, Keychain, app model, alerts
    Views/
      Components/             # ConsoleKit (the console's shapes), NavigationRail, charts
      Servers/                # Onboarding, auth, server list
      Dashboard/              # Tabs & detail lists
```

## Privacy

- Server list is stored in `UserDefaults` on device only, alongside already-notified threat IDs so alerts are not repeated.
- Passwords/session tokens live in the Keychain (`AfterFirstUnlockThisDeviceOnly`).
- No analytics or third-party network calls from this app.

## License

Matches the parent [NetworkSentinel](https://github.com/davidfweiser/NetworkSentinel) project.
