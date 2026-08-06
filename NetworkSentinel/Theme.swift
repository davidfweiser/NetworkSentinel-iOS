import SwiftUI

// MARK: - Tokens

/// The palette is a signal system, not decoration: every colour here means one thing about
/// the network, and severity is what drives the app's tint. Calm reads cool and still,
/// trouble warms the whole surface.
enum NSTheme {
    /// Deep slate rather than navy — keeps the glass panels from turning blue.
    static let ink = Color(red: 0.039, green: 0.055, blue: 0.078)
    static let text = Color(red: 0.929, green: 0.945, blue: 0.969)
    static let muted = Color(red: 0.541, green: 0.580, blue: 0.651)
    /// Secondary text that sits on a tinted glass panel. Plain `muted` loses too much
    /// contrast once the surface behind it is carrying a severity colour.
    static let mutedOnTint = Color(red: 0.780, green: 0.800, blue: 0.835)
    static let border = Color.white.opacity(0.10)

    /// Interactive blue — controls, links, anything you can press.
    static let accent = Color(red: 0.290, green: 0.620, blue: 1.0)
    /// "Everything is fine" teal. Reserved for healthy state, never for chrome.
    static let signal = Color(red: 0.231, green: 0.784, blue: 0.706)
    static let success = Color(red: 0.30, green: 0.82, blue: 0.55)
    static let warning = Color(red: 0.961, green: 0.725, blue: 0.231)
    static let danger = Color(red: 1.0, green: 0.365, blue: 0.471)
    static let cyan = Color(red: 0.30, green: 0.85, blue: 0.90)
    /// Threat marker on the activity chart — matches the web console and desktop GUI.
    static let threatMarker = Color(red: 1.0, green: 0.365, blue: 0.471)

    /// Base fill. Glass and list rows sit on the ambient field, so this is only the floor.
    static let bg = ink
    /// List rows stay translucent rather than glass — glass belongs to floating chrome, and
    /// a hundred glass rows in a scroll view is both wrong and slow.
    static let row = Color.white.opacity(0.05)
    static let card = Color(red: 0.086, green: 0.106, blue: 0.149)
    static let cardElevated = Color(red: 0.118, green: 0.145, blue: 0.204)
    static let accentSoft = accent.opacity(0.15)
}

extension Font {
    /// Instrument readout. Compressed width so a five-digit connection count still fits a
    /// tile without shrinking, and so the numerals read as measurements rather than prose.
    static func readout(_ size: CGFloat, weight: Font.Weight = .semibold) -> Font {
        .system(size: size, weight: weight).width(.compressed)
    }

    /// Small tracked label above a value or section.
    static var eyebrow: Font { .system(size: 11, weight: .semibold) }
}

// MARK: - Ambient field

/// The background is the data. A cool wash at rest, brightening with connection volume, and
/// breathing in the severity colour once something is actually wrong — so the state of the
/// network is readable from across the room, before you focus on a single number.
///
/// Motion only runs while a High or Critical threat is live. At rest this is a static
/// gradient, which keeps a 2.5s poll loop from also paying for a 20fps animation.
struct AmbientField: View {
    var severity: ThreatSeverity = .none
    /// 0…1, current connections as a share of the window's peak.
    var load: Double = 0

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var alarming: Bool { severity >= .high }

    var body: some View {
        ZStack {
            NSTheme.ink

            RadialGradient(
                colors: [NSTheme.signal.opacity(0.14 + 0.10 * load), .clear],
                center: UnitPoint(x: 0.12, y: 0.02),
                startRadius: 0,
                endRadius: 520
            )
            RadialGradient(
                colors: [NSTheme.accent.opacity(0.10 + 0.08 * load), .clear],
                center: UnitPoint(x: 0.96, y: 0.30),
                startRadius: 0,
                endRadius: 460
            )

            if alarming { alarmWash }
        }
        .ignoresSafeArea()
        .animation(.easeInOut(duration: 1.2), value: load)
        .animation(.easeInOut(duration: 0.9), value: severity)
    }

    @ViewBuilder
    private var alarmWash: some View {
        let tint = severity.color
        if reduceMotion {
            RadialGradient(
                colors: [tint.opacity(0.24), .clear],
                center: UnitPoint(x: 0.5, y: 1.04),
                startRadius: 0,
                endRadius: 600
            )
        } else {
            TimelineView(.animation(minimumInterval: 1.0 / 20.0)) { ctx in
                // ~4.5s breath — slow enough to read as alarm, not as a loading spinner.
                let t = ctx.date.timeIntervalSinceReferenceDate
                let phase = (sin(t * 2 * .pi / 4.5) + 1) / 2
                RadialGradient(
                    colors: [tint.opacity(0.13 + 0.17 * phase), .clear],
                    center: UnitPoint(x: 0.5, y: 1.04),
                    startRadius: 0,
                    endRadius: 500 + 140 * phase
                )
            }
        }
    }
}

// MARK: - Surfaces

struct GlassCardModifier: ViewModifier {
    var padding: CGFloat
    var tint: Color?

    func body(content: Content) -> some View {
        content
            .padding(padding)
            .glassEffect(
                tint.map { Glass.regular.tint($0.opacity(0.30)) } ?? .regular,
                in: .rect(cornerRadius: 22)
            )
    }
}

extension View {
    func nsCard(padding: CGFloat = 16, tint: Color? = nil) -> some View {
        modifier(GlassCardModifier(padding: padding, tint: tint))
    }

    /// Section label: uppercase, tracked, muted. Used above cards and inside them.
    func nsEyebrow() -> some View {
        self.font(.eyebrow)
            .textCase(.uppercase)
            .tracking(0.8)
            .foregroundStyle(NSTheme.muted)
    }
}

// MARK: - Components

struct StatTile: View {
    let title: String
    let value: Int
    let icon: String
    var tint: Color = NSTheme.accent
    var subtitle: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 26, height: 26)
                .background(tint.opacity(0.16), in: .rect(cornerRadius: 8))

            Text("\(value)")
                .font(.readout(34))
                .foregroundStyle(NSTheme.text)
                .contentTransition(.numericText(value: Double(value)))
                .animation(.snappy(duration: 0.35), value: value)
                .lineLimit(1)
                .minimumScaleFactor(0.6)

            Text(title)
                .nsEyebrow()

            if let subtitle {
                Text(subtitle)
                    .font(.caption2)
                    .foregroundStyle(tint.opacity(0.9))
                    .lineLimit(1)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .nsCard()
    }
}

struct SeverityBadge: View {
    let level: String
    let levelNum: Int?

    private var severity: ThreatSeverity {
        ThreatSeverity.from(level: level, levelNum: levelNum)
    }

    var body: some View {
        Text(level.uppercased())
            .font(.system(size: 10, weight: .bold))
            .tracking(0.6)
            .foregroundStyle(severity.color)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(severity.color.opacity(0.16), in: .capsule)
            .overlay(
                Capsule().stroke(severity.color.opacity(0.35), lineWidth: 0.5)
            )
    }
}

// MARK: - Sleep

/// What the console is doing while asleep, and the one control worth pressing. Carries its
/// own Wake button for the same reason the web console's banner does: the tab you are
/// looking at is rarely the one holding the sleep toggle.
struct SleepBanner: View {
    var onWake: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "moon.zzz.fill")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(NSTheme.warning)
                .padding(.top, 1)

            VStack(alignment: .leading, spacing: 3) {
                Text("Asleep")
                    .font(.eyebrow)
                    .textCase(.uppercase)
                    .tracking(0.8)
                    .foregroundStyle(NSTheme.warning)
                Text("Monitoring is stopped — no connections, ports, or threats are being watched. Firewall blocks stay in force.")
                    .font(.caption)
                    .foregroundStyle(NSTheme.mutedOnTint)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 4)

            Button("Wake", action: onWake)
                .font(.caption.weight(.bold))
                .buttonStyle(.glassProminent)
                .tint(NSTheme.warning)
        }
        .padding(14)
        .glassEffect(Glass.regular.tint(NSTheme.warning.opacity(0.22)), in: .rect(cornerRadius: 20))
    }
}

extension View {
    /// Live data steps back while the console is asleep. The numbers on screen are the last
    /// ones observed, not current traffic, and at full strength a stale table reads as live.
    /// Still interactive — a firewall block is as valid asleep as awake.
    func nsAsleepDimmed(_ asleep: Bool) -> some View {
        self
            .opacity(asleep ? 0.42 : 1)
            .saturation(asleep ? 0.45 : 1)
            .animation(.easeInOut(duration: 0.3), value: asleep)
    }

    /// Everything a tab of live server data needs while the console is asleep: the banner
    /// on top, the stale data dimmed underneath.
    func nsSleepAware(_ asleep: Bool, onWake: @escaping () -> Void) -> some View {
        self
            .nsAsleepDimmed(asleep)
            .safeAreaInset(edge: .top, spacing: 0) {
                if asleep {
                    SleepBanner(onWake: onWake)
                        .padding(.horizontal, 12)
                        .padding(.bottom, 8)
                        .transition(.move(edge: .top).combined(with: .opacity))
                }
            }
            .animation(.easeInOut(duration: 0.25), value: asleep)
    }
}

struct EmptyStateView: View {
    let icon: String
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: icon)
                .font(.system(size: 38, weight: .light))
                .foregroundStyle(NSTheme.muted)
            Text(title)
                .font(.headline)
                .foregroundStyle(NSTheme.text)
            Text(message)
                .font(.subheadline)
                .foregroundStyle(NSTheme.muted)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(.vertical, 48)
    }
}
