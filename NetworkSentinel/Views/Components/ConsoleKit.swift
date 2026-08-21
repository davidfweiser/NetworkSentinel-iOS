import SwiftUI

// MARK: - The console's own vocabulary
//
// The web console, the desktop window and this app are one product, and until now only the
// palette said so. Every surface the console draws has a shape as well as a colour — a panel
// is an 18px card with a heading, a line of context under it and its one action pinned to the
// right of that row; a setting is a title, a sentence of explanation and a control at the far
// end; a group of settings carries a tracked uppercase caption. Those shapes are what make
// the console recognisable, and they are what this file ports.
//
// The tokens below are `Web/WebApp.cs`'s `:root` block, value for value. Where `NSTheme`
// already carried the same colour under a different name it is aliased rather than
// redefined, so there is one palette and not two that drift.

extension NSTheme {
    /// `--bg-panel` — under a table, which sits *inside* a card rather than being one.
    static let panel = Color(red: 0.063, green: 0.078, blue: 0.110)
    /// `--text2` — secondary prose: a panel's sub-line, a status line, a table header.
    static var text2: Color { muted }
    /// `--muted` — quieter still: a setting's description, a group caption, a placeholder.
    /// The console draws these two at genuinely different weights and collapsing them into
    /// one flattens every screen that has both.
    static let dim = Color(red: 0.388, green: 0.420, blue: 0.471)
    /// `--stroke-strong` — the border of something raised over the page.
    static let strokeStrong = Color(red: 0.290, green: 0.620, blue: 1.0).opacity(0.40)
    /// `--bg-hover`, and the fill of an unchecked switch.
    static var hover: Color { cardElevated }

    /// `--accent-grad` — the one press on a screen that does something.
    static let accentGradient = LinearGradient(
        colors: [signal, accent],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
    /// `--danger-grad` — Remove, and nothing else.
    static let dangerGradient = LinearGradient(
        colors: [danger, Color(red: 0.980, green: 0.451, blue: 0.251)],
        startPoint: .leading,
        endPoint: .trailing
    )
    /// Wake, which is the one thing worth pressing while the console is asleep.
    static let wakeGradient = LinearGradient(
        colors: [warning, Color(red: 0.961, green: 0.518, blue: 0.231)],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
}

// MARK: - Panels

/// `.panel` — a titled card holding a list or a table. 18pt radius, 18pt padding, a hairline
/// stroke, and the card fill rather than the page fill, exactly as the console draws it.
struct ConsolePanel<Content: View>: View {
    var title: String?
    var subtitle: String?
    /// The action for this section, pinned to the right of the heading row.
    var action: AnyView?
    @ViewBuilder var content: Content

    init(
        _ title: String? = nil,
        subtitle: String? = nil,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.subtitle = subtitle
        self.action = nil
        self.content = content()
    }

    init<A: View>(
        _ title: String? = nil,
        subtitle: String? = nil,
        @ViewBuilder action: () -> A,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.subtitle = subtitle
        self.action = AnyView(action())
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if title != nil || subtitle != nil || action != nil {
                HStack(alignment: .top, spacing: 12) {
                    VStack(alignment: .leading, spacing: 3) {
                        if let title {
                            Text(title)
                                .font(.system(size: 15, weight: .bold))
                                .foregroundStyle(NSTheme.text)
                        }
                        if let subtitle, !subtitle.isEmpty {
                            Text(subtitle)
                                .font(.system(size: 13))
                                .foregroundStyle(NSTheme.text2)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    Spacer(minLength: 0)
                    if let action { action }
                }
            }
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(18)
        .background(NSTheme.card, in: .rect(cornerRadius: 18))
        .overlay(
            RoundedRectangle(cornerRadius: 18).stroke(NSTheme.border, lineWidth: 1)
        )
    }
}

// MARK: - Buttons

/// The console's button set. Everything the header row, a toolbar and a panel heading press
/// is one of these five, and they differ the way the console's do: only `primary` and `wake`
/// carry a gradient, only `remove` is filled red, and `danger` is an outline.
enum ConsoleButtonKind {
    case ghost, primary, danger, remove, wake
}

struct ConsoleButtonStyle: ButtonStyle {
    var kind: ConsoleButtonKind = .ghost
    /// Row buttons are the desktop's mini-ghost: smaller, 10pt radius, and a shared minimum
    /// width so an Edit and a Delete line up down a column.
    var compact: Bool = false

    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: compact ? 12.5 : 13, weight: weight))
            .foregroundStyle(foreground)
            .lineLimit(1)
            .fixedSize(horizontal: true, vertical: false)
            .padding(.horizontal, compact ? 10 : 12)
            .padding(.vertical, compact ? 6 : 8)
            .frame(minWidth: compact ? 72 : nil)
            .background(background)
            .clipShape(.rect(cornerRadius: compact ? 10 : 12))
            .overlay(
                RoundedRectangle(cornerRadius: compact ? 10 : 12)
                    .stroke(stroke, lineWidth: hasStroke ? 1 : 0)
            )
            .opacity(isEnabled ? (configuration.isPressed ? 0.75 : 1) : 0.55)
            .animation(.easeOut(duration: 0.15), value: configuration.isPressed)
    }

    private var weight: Font.Weight {
        switch kind {
        case .ghost, .danger: return .semibold
        case .primary: return .bold
        case .remove, .wake: return .semibold
        }
    }

    private var hasStroke: Bool {
        switch kind {
        case .ghost, .danger: return true
        case .primary, .remove, .wake: return false
        }
    }

    private var stroke: Color {
        kind == .danger ? NSTheme.danger.opacity(0.4) : NSTheme.border
    }

    private var foreground: Color {
        switch kind {
        case .ghost: return NSTheme.text
        case .primary, .wake: return NSTheme.ink
        case .danger: return Color(red: 1.0, green: 0.659, blue: 0.714)
        case .remove: return .white
        }
    }

    @ViewBuilder
    private var background: some View {
        switch kind {
        case .ghost, .danger: Color.white.opacity(0.10)
        case .primary: NSTheme.accentGradient
        case .remove: NSTheme.dangerGradient
        case .wake: NSTheme.wakeGradient
        }
    }
}

extension ButtonStyle where Self == ConsoleButtonStyle {
    static var console: ConsoleButtonStyle { ConsoleButtonStyle() }
    static func console(_ kind: ConsoleButtonKind, compact: Bool = false) -> ConsoleButtonStyle {
        ConsoleButtonStyle(kind: kind, compact: compact)
    }
}

// MARK: - Switch

/// `.switch` — 44×24, the accent gradient when on, and a knob that slides rather than snaps.
/// SwiftUI's own `Toggle` tint is a flat fill, and the console's is a gradient; on a screen
/// that is mostly switches the difference is the screen.
struct ConsoleSwitch: View {
    @Binding var isOn: Bool
    var enabled: Bool = true

    var body: some View {
        ZStack(alignment: isOn ? .trailing : .leading) {
            Capsule()
                .fill(isOn ? AnyShapeStyle(NSTheme.accentGradient) : AnyShapeStyle(NSTheme.hover))
                .overlay(Capsule().stroke(isOn ? .clear : NSTheme.border, lineWidth: 1))
                .frame(width: 44, height: 24)

            Circle()
                .fill(isOn ? Color.white : NSTheme.dim)
                .frame(width: 18, height: 18)
                .padding(.horizontal, 3)
        }
        .frame(width: 44, height: 24)
        .contentShape(.capsule)
        .opacity(enabled ? 1 : 0.5)
        .animation(.spring(response: 0.28, dampingFraction: 0.8), value: isOn)
        .onTapGesture {
            guard enabled else { return }
            isOn.toggle()
        }
        .accessibilityRepresentation {
            Toggle(isOn: $isOn) { EmptyView() }.disabled(!enabled)
        }
    }
}

// MARK: - Settings

/// `.settings-group h3` — a tracked uppercase caption over a run of setting rows.
struct ConsoleSettingsGroup<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.system(size: 13, weight: .semibold))
                .textCase(.uppercase)
                .tracking(1.1)
                .foregroundStyle(NSTheme.dim)
                .padding(.bottom, 0)
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// `.setting-row` — a title, the sentence that says what it does, and the control at the far
/// end. The description is not optional in the console and it is not optional here: a switch
/// labelled "Kernel flow events" and nothing else is a switch nobody will touch.
struct ConsoleSettingRow<Control: View>: View {
    let title: String
    let detail: String
    /// The server's own status line, appended after the description the way the console
    /// appends it — "on" and "running" are different claims and only the server makes the
    /// second. Drawn in amber when the server is reporting a problem.
    var status: String?
    var statusIsWarning: Bool = false
    @ViewBuilder var control: Control

    var body: some View {
        HStack(alignment: .center, spacing: 16) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(NSTheme.text)
                    .fixedSize(horizontal: false, vertical: true)
                Text(detail)
                    .font(.system(size: 13))
                    .foregroundStyle(NSTheme.dim)
                    .fixedSize(horizontal: false, vertical: true)
                if let status, !status.isEmpty {
                    Text(status)
                        .font(.system(size: 13))
                        .foregroundStyle(statusIsWarning ? NSTheme.warning : NSTheme.text2)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            // The sentence is what makes the row usable, so it wins the width and the
            // control gives way. Without this a 15-character value squeezed the text into a
            // six-line ribbon beside a mostly empty half-row.
            .layoutPriority(1)

            Spacer(minLength: 8)
            control
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(NSTheme.card, in: .rect(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(NSTheme.border, lineWidth: 1))
    }
}

/// The control end of a row that holds a value rather than a switch: what is stored, and a
/// tap to change it. The console puts a text box here; a phone puts the value and an editor
/// behind it, because a 180px input inside a list row is unusable on a 390pt screen.
struct ConsoleValueControl: View {
    let value: String
    var placeholder: String = "Not set"
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Text(value.isEmpty ? placeholder : value)
                    .font(.system(size: 13).monospaced())
                    .foregroundStyle(value.isEmpty ? NSTheme.dim : NSTheme.signal)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Image(systemName: "square.and.pencil")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(NSTheme.dim)
            }
            // A floor as well as a ceiling: the sentence beside it has layout priority, and
            // without a minimum the value was squeezed to nothing and the row showed a
            // chevron pointing at empty space.
            .frame(minWidth: 96, maxWidth: 130, alignment: .trailing)
        }
        .buttonStyle(.plain)
    }
}

/// `.settings-note` — the paragraph above a group that explains why the group exists at all.
/// DNS hygiene, WireGuard and Suricata each open with one, and without it those groups are
/// three switches nobody can weigh.
struct ConsoleNote: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(size: 13))
            .foregroundStyle(NSTheme.dim)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .background(NSTheme.card, in: .rect(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(NSTheme.border, lineWidth: 1))
    }
}

// MARK: - Cards and side panels

/// `.card` — an uppercase label over one number. The dashboard's row of four.
struct ConsoleStatCard: View {
    let label: String
    let value: String
    var tint: Color = NSTheme.text
    var action: (() -> Void)?

    var body: some View {
        let card = VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.system(size: 12, weight: .regular))
                .textCase(.uppercase)
                .tracking(0.9)
                .foregroundStyle(NSTheme.dim)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
            Text(value)
                .font(.system(size: 25, weight: .semibold))
                .monospacedDigit()
                .foregroundStyle(tint)
                .lineLimit(1)
                .minimumScaleFactor(0.5)
                .contentTransition(.numericText())
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        .background(NSTheme.card, in: .rect(cornerRadius: 18))
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(NSTheme.border, lineWidth: 1))

        if let action {
            Button(action: action) { card }.buttonStyle(.plain)
        } else {
            card
        }
    }
}

/// `.side-panel.intensity` — the desktop's threat-intensity hero, which the web console
/// gained in 0.7.8: the high-severity count on its own, away from the tiles it otherwise
/// hides among, with a pulse that says whether the number is live or the last one seen.
struct ConsoleIntensityPanel: View {
    let count: Int
    let live: Bool

    var body: some View {
        VStack(spacing: 6) {
            Text(live ? "LIVE" : "IDLE")
                .font(.system(size: 15, weight: .bold))
                .tracking(0.6)
                .foregroundStyle(live ? NSTheme.signal : NSTheme.dim)
                .frame(width: 72, height: 72)
                .background(
                    Circle().fill(live ? NSTheme.signal.opacity(0.15) : Color.white.opacity(0.04))
                )
                .overlay(
                    Circle().stroke(live ? NSTheme.signal : NSTheme.dim, lineWidth: 2)
                )
                .padding(.bottom, 6)

            Text("Threat intensity")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(NSTheme.text)
            Text("\(count)")
                .font(.system(size: 28, weight: .bold))
                .monospacedDigit()
                .foregroundStyle(NSTheme.danger)
                .contentTransition(.numericText())
            Text("high-severity signals")
                .font(.system(size: 12.5))
                .foregroundStyle(NSTheme.text2)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 18)
        .padding(.horizontal, 16)
        .background(
            LinearGradient(
                colors: [
                    NSTheme.signal.opacity(0.10),
                    NSTheme.accent.opacity(0.05),
                    .clear
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            ),
            in: .rect(cornerRadius: 12)
        )
        .background(NSTheme.panel, in: .rect(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(NSTheme.border, lineWidth: 1))
    }
}

/// `.side-panel` — the running month's totals, which the data-flow footer states in a
/// sentence too long to read at a glance.
struct ConsoleMonthPanel: View {
    let month: String
    let dataIn: String
    let dataOut: String
    var total: String?
    var average: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("This month")
                .font(.system(size: 11, weight: .bold))
                .textCase(.uppercase)
                .tracking(1.0)
                .foregroundStyle(NSTheme.dim)
            Text(month)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(NSTheme.text)
                .padding(.bottom, 4)

            Text("Data in")
                .font(.system(size: 12.5))
                .foregroundStyle(NSTheme.text2)
            Text(dataIn)
                .font(.system(size: 28, weight: .bold))
                .monospacedDigit()
                .foregroundStyle(NSTheme.accent)

            Text("Data out")
                .font(.system(size: 12.5))
                .foregroundStyle(NSTheme.text2)
                .padding(.top, 6)
            Text(dataOut)
                .font(.system(size: 28, weight: .bold))
                .monospacedDigit()
                .foregroundStyle(NSTheme.signal)

            if let total {
                Text(total)
                    .font(.system(size: 12))
                    .foregroundStyle(NSTheme.text2)
                    .padding(.top, 10)
            }
            if let average {
                Text(average)
                    .font(.system(size: 12))
                    .foregroundStyle(NSTheme.dim)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(NSTheme.panel, in: .rect(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(NSTheme.border, lineWidth: 1))
    }
}

// MARK: - Banners

/// `.elev-banner` — Firewall Config's read-only notice, ported from web 0.7.10. Amber, not
/// red: the page is working, it just cannot write, and the commands that fix it are in it.
///
/// The console draws two remedies, capability first, each with its own command block. A
/// phone cannot run either, so every block is selectable and carries a copy button — the
/// point of showing them is getting them onto the machine that can.
struct ConsoleElevationBanner: View {
    let title: String
    var lead: String?
    var capabilityCommands: String?
    var alternative: String?
    var sudoCommands: String?
    var tail: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.system(size: 12, weight: .bold))
                .textCase(.uppercase)
                .tracking(0.6)
                .foregroundStyle(NSTheme.warning)

            if let lead, !lead.isEmpty { paragraph(lead) }
            if let capabilityCommands, !capabilityCommands.isEmpty { commands(capabilityCommands) }
            if let alternative, !alternative.isEmpty { paragraph(alternative) }
            if let sudoCommands, !sudoCommands.isEmpty { commands(sudoCommands) }
            if let tail, !tail.isEmpty {
                paragraph(tail).opacity(0.85)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(NSTheme.warning.opacity(0.08), in: .rect(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10).stroke(NSTheme.warning.opacity(0.45), lineWidth: 1)
        )
    }

    private func paragraph(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 13.5))
            .foregroundStyle(Color(red: 0.965, green: 0.816, blue: 0.537))
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func commands(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            ScrollView(.horizontal, showsIndicators: false) {
                Text(text)
                    .font(.system(size: 12).monospaced())
                    .foregroundStyle(NSTheme.text2)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: true, vertical: true)
            }
            Button {
                UIPasteboard.general.string = text
            } label: {
                Image(systemName: "doc.on.doc")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(NSTheme.text2)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Copy commands")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.black.opacity(0.28), in: .rect(cornerRadius: 8))
    }
}

// MARK: - Small parts

/// `.chip` — a blue pill carrying one short fact beside a row.
struct ConsoleChip: View {
    let text: String
    var tint: Color = NSTheme.accent

    var body: some View {
        Text(text)
            .font(.system(size: 11.5, weight: .semibold))
            .foregroundStyle(tint)
            .padding(.horizontal, 8)
            .padding(.vertical, 2)
            .background(tint.opacity(0.16), in: .capsule)
            .overlay(Capsule().stroke(tint.opacity(0.25), lineWidth: 1))
    }
}

/// `.dot` — the state light in the rail's status block: green running, amber stopped.
struct ConsoleDot: View {
    var on: Bool

    var body: some View {
        Circle()
            .fill(on ? NSTheme.success : NSTheme.warning)
            .frame(width: 7, height: 7)
            .shadow(color: on ? NSTheme.success.opacity(0.6) : .clear, radius: 4)
    }
}

/// The console's table, as far as a phone can carry one: a sticky header row of tracked
/// labels over rows on the panel fill. Used where the console uses a real table and the
/// content is genuinely columnar — the WireGuard peer list is the case that forced it.
struct ConsoleTable<Row: Identifiable, Cells: View>: View {
    let headers: [String]
    let rows: [Row]
    /// Fractional widths, one per column, summing to roughly 1.
    let widths: [CGFloat]
    @ViewBuilder var cells: (Row) -> Cells

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            VStack(spacing: 0) {
                HStack(spacing: 0) {
                    ForEach(Array(headers.enumerated()), id: \.offset) { index, header in
                        Text(header)
                            .font(.system(size: 12.5, weight: .semibold))
                            .foregroundStyle(NSTheme.text2)
                            .frame(width: columnWidth(index), alignment: .leading)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 8)
                    }
                }
                .background(Color(red: 0.110, green: 0.125, blue: 0.153))

                ForEach(rows) { row in
                    HStack(spacing: 0) {
                        cells(row)
                    }
                    .font(.system(size: 13))
                    .foregroundStyle(NSTheme.text)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 8)
                    .overlay(alignment: .bottom) {
                        Rectangle()
                            .fill(Color.white.opacity(0.08))
                            .frame(height: 1)
                    }
                }
            }
            .frame(width: totalWidth, alignment: .leading)
        }
        .background(NSTheme.panel, in: .rect(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(NSTheme.border, lineWidth: 1))
        .clipShape(.rect(cornerRadius: 12))
    }

    private var totalWidth: CGFloat { widths.reduce(0) { $0 + $1 } }
    private func columnWidth(_ index: Int) -> CGFloat {
        index < widths.count ? widths[index] : 100
    }
}

// MARK: - Screen scaffolding

/// The scrolling column every console screen is: the ambient field behind it, the console's
/// own 18pt gutter, and 12pt between blocks.
struct ConsoleScreen<Content: View>: View {
    var severity: ThreatSeverity = .none
    var load: Double = 0
    @ViewBuilder var content: Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                content
            }
            .padding(.horizontal, 16)
            .padding(.top, 4)
            .padding(.bottom, 32)
        }
        .background { AmbientField(severity: severity, load: load) }
        .scrollEdgeEffectStyle(.soft, for: .top)
    }
}

/// `.setting-row select` — the console's dropdown: page fill rather than card fill, so it
/// reads as a control sitting *in* the row rather than a second panel beside it.
struct ConsoleSelect<Value: Hashable>: View {
    let options: [Value]
    @Binding var selection: Value
    let label: (Value) -> String

    var body: some View {
        Menu {
            Picker("", selection: $selection) {
                ForEach(options, id: \.self) { option in
                    Text(label(option)).tag(option)
                }
            }
            .labelsHidden()
        } label: {
            HStack(spacing: 6) {
                Text(label(selection))
                    .font(.system(size: 13.5))
                    .foregroundStyle(NSTheme.text)
                    .lineLimit(1)
                Image(systemName: "chevron.up.chevron.down")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(NSTheme.dim)
            }
            .fixedSize(horizontal: true, vertical: false)
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(NSTheme.ink, in: .rect(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(NSTheme.border, lineWidth: 1))
        }
    }
}

/// `.toolbar input` — the filter box above a long list. The console puts one over every
/// table it draws; the Settings page has no need of one on a 1400px desktop and every need
/// of one on a phone, where its forty-odd rows are a long scroll rather than a glance.
struct ConsoleSearchField: View {
    @Binding var text: String
    var placeholder: String

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(NSTheme.dim)
            TextField(placeholder, text: $text)
                .font(.system(size: 14))
                .foregroundStyle(NSTheme.text)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.search)
            if !text.isEmpty {
                Button {
                    text = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .font(.system(size: 14))
                        .foregroundStyle(NSTheme.dim)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .background(Color.white.opacity(0.05), in: .rect(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(NSTheme.border, lineWidth: 1))
    }
}
