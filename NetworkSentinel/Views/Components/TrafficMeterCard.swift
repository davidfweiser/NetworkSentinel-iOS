import Charts
import SwiftUI

/// How much is moving, for the Status screen — web 0.7's bandwidth meter.
///
/// It sits beside the instrument panel because it answers the question that panel cannot:
/// the connection count says how many peers are talking, and one connection pulling a disk
/// image at line rate does not move it at all. Rate first because that is the reading that
/// changes while you are looking at it; the month total under it is context, not news.
///
/// The card is a summary — the full series, the daily bars and the year live one tap away in
/// `DataFlowView`, because a card that tried to hold three charts would push the thing you
/// opened Status for off the screen.
struct TrafficMeterCard: View {
    let traffic: TrafficInfo

    private var samples: [Sample] {
        (traffic.live ?? []).enumerated().map { i, s in
            Sample(id: i, inBps: s.inBps ?? 0, outBps: s.outBps ?? 0)
        }
    }

    struct Sample: Identifiable {
        let id: Int
        let inBps: Double
        let outBps: Double
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            if traffic.hasReading {
                rates
                Sparkline(samples: samples)
                    .frame(height: 40)
                monthLine
            } else {
                idleLine
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 13)
        .background(NSTheme.row, in: .rect(cornerRadius: 18))
        .overlay(
            RoundedRectangle(cornerRadius: 18).stroke(NSTheme.border, lineWidth: 0.5)
        )
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            Text("Data flow").nsEyebrow()
            Spacer(minLength: 8)
            // The series carries no timestamps, so this is the only x-axis there is.
            Text(traffic.window ?? "")
                .font(.system(size: 10).monospaced())
                .foregroundStyle(NSTheme.muted)
                .lineLimit(1)
            Image(systemName: "chevron.right")
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(NSTheme.muted)
        }
    }

    private var rates: some View {
        HStack(alignment: .firstTextBaseline, spacing: 0) {
            rate(traffic.inRate, direction: "In", icon: "arrow.down", tint: NSTheme.cyan)
            rate(traffic.outRate, direction: "Out", icon: "arrow.up", tint: NSTheme.signal)
        }
    }

    private func rate(_ value: String?, direction: String, icon: String, tint: Color) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            HStack(spacing: 4) {
                Image(systemName: icon)
                    .font(.system(size: 11, weight: .bold))
                    .foregroundStyle(tint)
                // The server's own formatting — it settled the byte convention once (SI, the
                // one link speeds and data caps use) and a second opinion here would
                // eventually disagree with the console about the same number.
                Text(value ?? "—")
                    .font(.readout(20, weight: .bold))
                    .foregroundStyle(NSTheme.text)
                    .contentTransition(.numericText())
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
            }
            Text(direction)
                .font(.system(size: 9, weight: .medium))
                .textCase(.uppercase)
                .tracking(0.9)
                .foregroundStyle(NSTheme.muted)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(direction) \(value ?? "no reading")")
    }

    @ViewBuilder
    private var monthLine: some View {
        let parts = [traffic.monthLabel, traffic.monthTotal, traffic.monthDailyAverage]
            .compactMap { $0 }
            .filter { !$0.isEmpty }
        if !parts.isEmpty {
            Text(parts.joined(separator: " · "))
                .font(.system(size: 10).monospaced())
                .foregroundStyle(NSTheme.muted)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
        }
    }

    /// The meter reports being on separately from having anything to report: it starts
    /// counting from the moment it is switched on and needs two samples to subtract, so
    /// "on but empty" is a real and temporary state that should not read as broken.
    private var idleLine: some View {
        Text(traffic.enabled == true
             ? "Measuring — the meter needs a moment before it can report a rate."
             : "Meter off — the server is not counting bytes on its interfaces.")
            .font(.system(size: 12))
            .foregroundStyle(NSTheme.muted)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// In and out over the live window, without axes or labels — at 40 points high the shape is
/// the whole message, and gridlines would cost more room than they explain. The full,
/// scrubbable version is in `DataFlowView`.
struct Sparkline: View {
    let samples: [TrafficMeterCard.Sample]

    /// One scale for both directions, so the asymmetry between them is the thing you see.
    /// Scaling each to its own maximum would draw a trickle of upload the same height as a
    /// saturated download.
    private var upperBound: Double {
        max(samples.flatMap { [$0.inBps, $0.outBps] }.max() ?? 1, 1)
    }

    var body: some View {
        Chart {
            ForEach(samples) { s in
                AreaMark(
                    x: .value("Sample", s.id),
                    y: .value("In", s.inBps)
                )
                .interpolationMethod(.catmullRom)
                .foregroundStyle(
                    LinearGradient(
                        colors: [NSTheme.cyan.opacity(0.32), NSTheme.cyan.opacity(0.02)],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
            }
            ForEach(samples) { s in
                LineMark(
                    x: .value("Sample", s.id),
                    y: .value("Out", s.outBps)
                )
                .interpolationMethod(.catmullRom)
                .lineStyle(StrokeStyle(lineWidth: 1.5, lineCap: .round))
                .foregroundStyle(NSTheme.signal)
            }
        }
        .chartYScale(domain: 0...upperBound)
        .chartXAxis(.hidden)
        .chartYAxis(.hidden)
        .chartLegend(.hidden)
        .accessibilityHidden(true)
    }
}
