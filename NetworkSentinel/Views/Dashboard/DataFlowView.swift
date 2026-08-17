import Charts
import SwiftUI

/// The bandwidth meter in full — web 0.7's data-flow charts, ported from the console's
/// dashboard card.
///
/// Three time bases, coarsening downward: the live rate over the last few minutes, then this
/// month a day at a time, then a year a month at a time. They are separate charts rather than
/// one zoomable one because they answer separate questions — *is something happening now*,
/// *was yesterday unusual*, *are we going to blow through the cap* — and the middle one is
/// unreadable at either of the other two scales.
struct DataFlowView: View {
    @Environment(AppModel.self) private var model

    private var traffic: TrafficInfo? { model.state?.traffic }
    private var settings: SettingsInfo? { model.state?.settings }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                if let traffic {
                    liveSection(traffic)
                    monthSection(traffic)
                    yearSection(traffic)
                    meterControl
                    if let status = traffic.status ?? settings?.trafficStatus, !status.isEmpty {
                        Text(status)
                            .font(.system(size: 11))
                            .foregroundStyle(NSTheme.muted)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } else {
                    // Only reachable if the server drops the field between the Status card
                    // appearing and this screen opening — the card is what links here, and it
                    // is not drawn without one.
                    Text("This server does not report a bandwidth meter.")
                        .font(.system(size: 13))
                        .foregroundStyle(NSTheme.muted)
                }
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 28)
        }
        .background { AmbientField() }
        .navigationTitle("Data flow")
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await model.refresh(silent: false) }
    }

    // MARK: - Live

    @ViewBuilder
    private func liveSection(_ traffic: TrafficInfo) -> some View {
        let samples = (traffic.live ?? []).enumerated().map { i, s in
            TrafficMeterCard.Sample(id: i, inBps: s.inBps ?? 0, outBps: s.outBps ?? 0)
        }
        panel {
            HStack(alignment: .firstTextBaseline) {
                Text("Now").nsEyebrow()
                Spacer()
                Text(traffic.window ?? "")
                    .font(.system(size: 10).monospaced())
                    .foregroundStyle(NSTheme.muted)
            }

            HStack(spacing: 18) {
                readout(traffic.inRate ?? "—", label: "in", tint: NSTheme.cyan, icon: "arrow.down")
                readout(traffic.outRate ?? "—", label: "out", tint: NSTheme.signal, icon: "arrow.up")
            }

            if samples.isEmpty {
                emptyLine(traffic.enabled == true
                          ? "Measuring — the meter needs a moment before it can report a rate."
                          : "The meter is off, so nothing is being counted.")
            } else {
                Sparkline(samples: samples)
                    .frame(height: 120)
                legend
            }
        }
    }

    private var legend: some View {
        HStack(spacing: 14) {
            legendKey("In", tint: NSTheme.cyan, filled: true)
            legendKey("Out", tint: NSTheme.signal, filled: false)
            Spacer()
        }
    }

    private func legendKey(_ text: String, tint: Color, filled: Bool) -> some View {
        HStack(spacing: 5) {
            RoundedRectangle(cornerRadius: 1)
                .fill(filled ? tint.opacity(0.45) : tint)
                .frame(width: 12, height: filled ? 8 : 2)
            Text(text)
                .font(.system(size: 10))
                .foregroundStyle(NSTheme.muted)
        }
    }

    // MARK: - This month, a day at a time

    @ViewBuilder
    private func monthSection(_ traffic: TrafficInfo) -> some View {
        let days = (traffic.days ?? []).filter { $0.total > 0 }
        panel {
            HStack(alignment: .firstTextBaseline) {
                Text(traffic.monthLabel ?? "This month").nsEyebrow()
                Spacer()
                Text(traffic.monthTotal ?? "")
                    .font(.readout(15, weight: .bold))
                    .foregroundStyle(NSTheme.text)
            }

            if let average = traffic.monthDailyAverage, !average.isEmpty {
                Text(average)
                    .font(.system(size: 11))
                    .foregroundStyle(NSTheme.muted)
            }

            if days.isEmpty {
                emptyLine("No days recorded this month yet.")
            } else {
                BytesBarChart(buckets: days)
                    .frame(height: 130)
                HStack(spacing: 14) {
                    total("in", traffic.monthIn, tint: NSTheme.cyan)
                    total("out", traffic.monthOut, tint: NSTheme.signal)
                    Spacer()
                }
            }
        }
    }

    // MARK: - The year, a month at a time

    @ViewBuilder
    private func yearSection(_ traffic: TrafficInfo) -> some View {
        let months = (traffic.months ?? []).filter { $0.total > 0 }
        if !months.isEmpty {
            panel {
                Text("Last 12 months").nsEyebrow()
                BytesBarChart(buckets: months)
                    .frame(height: 130)
            }
        }
    }

    // MARK: - The switch

    private var meterControl: some View {
        Toggle(isOn: Binding(
            get: { settings?.trafficMeterEnabled ?? false },
            set: { on in Task { await model.setTrafficMeter(on) } }
        )) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Count bytes")
                    .font(.system(size: 15))
                    .foregroundStyle(NSTheme.text)
                // Worth saying before the switch is thrown: the history does not appear
                // retroactively, so turning it on to answer a question about last week
                // cannot work and the empty chart afterwards looks like a fault.
                Text("Counters start from zero — there is no history before the meter is switched on.")
                    .font(.caption2)
                    .foregroundStyle(NSTheme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .tint(NSTheme.accent)
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .background(NSTheme.row, in: .rect(cornerRadius: 18))
        .overlay(
            RoundedRectangle(cornerRadius: 18).stroke(NSTheme.border, lineWidth: 0.5)
        )
    }

    // MARK: - Furniture

    private func panel<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 14)
        .padding(.vertical, 13)
        .background(NSTheme.row, in: .rect(cornerRadius: 18))
        .overlay(
            RoundedRectangle(cornerRadius: 18).stroke(NSTheme.border, lineWidth: 0.5)
        )
    }

    private func readout(_ value: String, label: String, tint: Color, icon: String) -> some View {
        HStack(spacing: 5) {
            Image(systemName: icon)
                .font(.system(size: 12, weight: .bold))
                .foregroundStyle(tint)
            Text(value)
                .font(.readout(22, weight: .bold))
                .foregroundStyle(NSTheme.text)
                .contentTransition(.numericText())
                .lineLimit(1)
                .minimumScaleFactor(0.6)
            Text(label)
                .font(.system(size: 10))
                .foregroundStyle(NSTheme.muted)
        }
        .accessibilityElement(children: .combine)
    }

    private func total(_ label: String, _ value: String?, tint: Color) -> some View {
        HStack(spacing: 4) {
            Circle().fill(tint).frame(width: 6, height: 6)
            Text(value ?? "—")
                .font(.system(size: 12, weight: .semibold).monospaced())
                .foregroundStyle(NSTheme.text)
            Text(label)
                .font(.system(size: 10))
                .foregroundStyle(NSTheme.muted)
        }
        .accessibilityElement(children: .combine)
    }

    private func emptyLine(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 12))
            .foregroundStyle(NSTheme.muted)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// In and out per bucket, stacked, with the bucket under the finger called out above the
/// chart. Stacked rather than side-by-side because the question these charts are usually
/// opened for is the total against a cap, and paired bars make the reader add.
struct BytesBarChart: View {
    let buckets: [TrafficBucket]

    @State private var selectedLabel: String?

    private var selected: TrafficBucket? {
        guard let selectedLabel else { return nil }
        return buckets.first { $0.label == selectedLabel }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            // Reserve the line whether or not anything is pinned, so scrubbing does not
            // shove the chart up and down under the finger doing the scrubbing.
            HStack(spacing: 8) {
                if let selected {
                    Text(selected.label)
                        .font(.system(size: 11, weight: .semibold).monospaced())
                        .foregroundStyle(NSTheme.text)
                    Text(selected.inText ?? "—")
                        .font(.system(size: 11).monospaced())
                        .foregroundStyle(NSTheme.cyan)
                    Text(selected.outText ?? "—")
                        .font(.system(size: 11).monospaced())
                        .foregroundStyle(NSTheme.signal)
                } else {
                    Text("Touch a bar for its totals")
                        .font(.system(size: 11))
                        .foregroundStyle(NSTheme.muted)
                }
                Spacer()
            }
            .frame(height: 14)
            .animation(.snappy(duration: 0.2), value: selectedLabel)

            Chart {
                ForEach(buckets) { b in
                    BarMark(
                        x: .value("Span", b.label),
                        y: .value("In", b.bytesIn ?? 0)
                    )
                    .foregroundStyle(NSTheme.cyan.opacity(selectedLabel == nil || selectedLabel == b.label ? 0.85 : 0.3))

                    BarMark(
                        x: .value("Span", b.label),
                        y: .value("Out", b.bytesOut ?? 0)
                    )
                    .foregroundStyle(NSTheme.signal.opacity(selectedLabel == nil || selectedLabel == b.label ? 0.85 : 0.3))
                }
            }
            .chartXAxis {
                // Every label is unreadable at 31 days on a phone, so mark the ends and let
                // the scrub readout name the rest.
                AxisMarks(values: [buckets.first?.label, buckets.last?.label].compactMap { $0 }) {
                    AxisValueLabel()
                        .font(.system(size: 9))
                        .foregroundStyle(NSTheme.muted)
                }
            }
            .chartYAxis(.hidden)
            .chartLegend(.hidden)
            .chartXSelection(value: $selectedLabel)
        }
    }
}
