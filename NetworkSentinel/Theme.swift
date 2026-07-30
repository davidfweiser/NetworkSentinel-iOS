import SwiftUI

enum NSTheme {
    static let bg = Color(red: 0.06, green: 0.08, blue: 0.12)
    static let card = Color(red: 0.10, green: 0.13, blue: 0.19)
    static let cardElevated = Color(red: 0.13, green: 0.16, blue: 0.24)
    static let border = Color.white.opacity(0.08)
    static let muted = Color(red: 0.55, green: 0.60, blue: 0.70)
    static let text = Color(red: 0.93, green: 0.95, blue: 0.98)
    static let accent = Color(red: 0.29, green: 0.62, blue: 0.98)
    static let accentSoft = Color(red: 0.29, green: 0.62, blue: 0.98).opacity(0.15)
    static let success = Color(red: 0.30, green: 0.82, blue: 0.55)
    static let warning = Color(red: 0.95, green: 0.75, blue: 0.25)
    static let danger = Color(red: 0.95, green: 0.30, blue: 0.40)
    static let cyan = Color(red: 0.30, green: 0.85, blue: 0.90)
    /// Threat marker on the activity chart — the web console's and desktop GUI's #FF5D78.
    static let threatMarker = Color(red: 1.0, green: 0.365, blue: 0.471)

    static let gradient = LinearGradient(
        colors: [
            Color(red: 0.08, green: 0.12, blue: 0.22),
            Color(red: 0.05, green: 0.07, blue: 0.11)
        ],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
}

struct CardModifier: ViewModifier {
    var padding: CGFloat = 16

    func body(content: Content) -> some View {
        content
            .padding(padding)
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(NSTheme.card)
                    .overlay(
                        RoundedRectangle(cornerRadius: 16, style: .continuous)
                            .stroke(NSTheme.border, lineWidth: 1)
                    )
            )
    }
}

extension View {
    func nsCard(padding: CGFloat = 16) -> some View {
        modifier(CardModifier(padding: padding))
    }
}

struct StatTile: View {
    let title: String
    let value: String
    let icon: String
    var tint: Color = NSTheme.accent
    var subtitle: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: icon)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(tint)
                    .frame(width: 28, height: 28)
                    .background(tint.opacity(0.15), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                Spacer()
            }
            Text(value)
                .font(.system(size: 26, weight: .bold, design: .rounded))
                .foregroundStyle(NSTheme.text)
                .minimumScaleFactor(0.6)
                .lineLimit(1)
            Text(title)
                .font(.caption.weight(.medium))
                .foregroundStyle(NSTheme.muted)
            if let subtitle {
                Text(subtitle)
                    .font(.caption2)
                    .foregroundStyle(NSTheme.muted.opacity(0.8))
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
            .font(.system(size: 10, weight: .bold, design: .rounded))
            .tracking(0.5)
            .foregroundStyle(severity.color)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(severity.color.opacity(0.15), in: Capsule())
    }
}

struct EmptyStateView: View {
    let icon: String
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: icon)
                .font(.system(size: 40, weight: .light))
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

/// Connection-count area/line with a translucent red column on every sample that
/// carried a threat — the same reading as the web console's inline-SVG chart and the
/// desktop GUI's Sparkline control (same #FF5D78 marker, 4pt wide, full plot height).
struct ActivitySparkline: View {
    let points: [ActivityPoint]

    /// Matches the web chart's padT / padB so the line never clips against the card.
    private let padTop: CGFloat = 6
    private let padBottom: CGFloat = 3

    var body: some View {
        GeometryReader { geo in
            let values = points.map { Double($0.connections ?? 0) }
            let maxV = max(values.max() ?? 1, 1)
            let w = geo.size.width
            let h = geo.size.height
            let innerH = max(h - padTop - padBottom, 1)
            let n = max(values.count, 1)

            let xPos: (Int) -> CGFloat = { i in
                n == 1 ? w / 2 : CGFloat(i) / CGFloat(n - 1) * w
            }
            let yPos: (Double) -> CGFloat = { v in
                padTop + innerH * (1 - CGFloat(v / maxV))
            }

            ZStack {
                // Grid lines at 25 / 50 / 75%, as on the web chart.
                Path { path in
                    for f in [0.25, 0.5, 0.75] {
                        let y = padTop + innerH * CGFloat(f)
                        path.move(to: CGPoint(x: 0, y: y))
                        path.addLine(to: CGPoint(x: w, y: y))
                    }
                }
                .stroke(Color.white.opacity(0.07), lineWidth: 1)

                // Fill under curve
                Path { path in
                    guard !values.isEmpty else { return }
                    path.move(to: CGPoint(x: xPos(0), y: h - padBottom))
                    for (i, v) in values.enumerated() {
                        path.addLine(to: CGPoint(x: xPos(i), y: yPos(v)))
                    }
                    path.addLine(to: CGPoint(x: xPos(values.count - 1), y: h - padBottom))
                    path.closeSubpath()
                }
                .fill(
                    LinearGradient(
                        colors: [NSTheme.accent.opacity(0.25), NSTheme.accent.opacity(0.02)],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )

                // Threat markers sit under the line so a spike never hides the trend.
                ForEach(threatMarkerIndices, id: \.self) { i in
                    RoundedRectangle(cornerRadius: 2, style: .continuous)
                        .fill(NSTheme.threatMarker.opacity(0.30))
                        .frame(width: 4, height: innerH)
                        .position(x: xPos(i), y: padTop + innerH / 2)
                }

                Path { path in
                    for (i, v) in values.enumerated() {
                        let p = CGPoint(x: xPos(i), y: yPos(v))
                        if i == 0 { path.move(to: p) } else { path.addLine(to: p) }
                    }
                }
                .stroke(
                    LinearGradient(colors: [NSTheme.accent, NSTheme.cyan], startPoint: .leading, endPoint: .trailing),
                    style: StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round)
                )

                // Current-value dot on the newest sample.
                if let lastValue = values.last {
                    Circle()
                        .fill(NSTheme.cyan)
                        .frame(width: 7, height: 7)
                        .position(x: xPos(values.count - 1), y: yPos(lastValue))
                }
            }
        }
    }

    private var threatMarkerIndices: [Int] {
        points.enumerated().compactMap { (i, p) in (p.threats ?? 0) > 0 ? i : nil }
    }
}
