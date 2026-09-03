# Third-party notices

Network Sentinel for iOS is licensed under the MIT License — see [`LICENSE`](LICENSE).

**This app redistributes no third-party code.** That is unusual enough to be
worth stating outright rather than leaving a reader to infer it from an absent
file: there are no Swift Package Manager dependencies, no vendored sources, no
`.xcframework` or static libraries, and no bundled fonts. `project.yml` declares
no package requirements, and the app builds from its own ~11k lines of Swift
against the iOS SDK alone.

So there is no third-party licence text that has to accompany a build of this
app. The rest of this file records what the app *does* rely on, and why none of
it creates an obligation.

---

## Apple frameworks

`SwiftUI`, `Foundation`, `UIKit`, `Charts` (Apple's Swift Charts — not the
similarly named third-party library), `BackgroundTasks`, `Observation`,
`UserNotifications` and `Security` are all part of the iOS SDK. They are linked
against, not redistributed, and are covered by the Apple Developer Program
agreement you accept to build and ship an iOS app — not by this project's
licence.

---

## Network services

The app talks to **one** kind of endpoint: Network Sentinel web consoles that
you run, at addresses you enter yourself. It makes no analytics calls and
contacts no third-party service of its own.

Several settings screens name outside providers — ipwho.is and ipapi.co for
geolocation, FireHOL level1 and Spamhaus DROP for threat intel, ntfy/Slack/
Discord for webhooks. Those are **server-side** settings this app toggles
remotely over the console API; the requests are made by the server, under the
terms that server accepted, and are documented in the notices file of the
edition running there ([Linux](https://github.com/davidfweiser/NetworkSentinel),
[macOS](https://github.com/davidfweiser/NetworkSentinel-mac)). Nothing in this
list is reached from the device.

---

## First-party assets

| Asset | Origin |
|---|---|
| `NetworkSentinel/Assets.xcassets/AppIcon.appiconset/AppIcon-1024.png` | Generated with Anthropic's Claude for this project |
| `AccentColor.colorset` | Defined for this project |

No third party holds rights in these files, neither originates from an icon
pack, stock library or another project, and no attribution to Anthropic is
required or implied — under Anthropic's terms of service Anthropic claims no
ownership of the output its models produce. They are covered by this project's
own MIT licence along with the rest of the repository.
