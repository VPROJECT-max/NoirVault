import SwiftUI
import UIKit

struct TOTPCodeView: View {
    let configuration: TOTPConfiguration
    @EnvironmentObject private var session: VaultSession
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var copied = false
    @State private var revealed = false

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let code = TOTPGenerator.code(configuration: configuration, at: context.date)
            let remaining = TOTPGenerator.remainingSeconds(configuration: configuration, at: context.date)
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(session.requireBiometricsToCopy && !revealed ? "••• •••" : code.chunkedCode)
                        .font(.system(.largeTitle, design: .rounded, weight: .bold))
                        .monospacedDigit()
                        .contentTransition(.numericText())
                        .animation(reduceMotion ? nil : .easeInOut(duration: 0.2), value: code)
                        .minimumScaleFactor(0.7).lineLimit(1)
                    Spacer()
                    ZStack {
                        Circle().stroke(NoirTheme.elevated, lineWidth: 4)
                        Circle().trim(from: 0, to: remaining / Double(configuration.period))
                            .stroke(remaining <= 5 ? .orange : NoirTheme.mint, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                            .rotationEffect(.degrees(-90))
                        Text("\(max(1, Int(ceil(remaining))))").font(.caption.bold()).monospacedDigit()
                    }
                    .frame(width: 44, height: 44)
                    .accessibilityLabel("Refreshes in \(Int(ceil(remaining))) seconds")
                }
                if session.requireBiometricsToCopy {
                    Button(revealed ? "Hide code" : "Reveal code", systemImage: revealed ? "eye.slash" : "eye") {
                        if revealed { revealed = false }
                        else { Task { revealed = await session.authorizeSecretAccess() } }
                    }
                }
                Button {
                    Task {
                        guard await session.authorizeSecretAccess() else { return }
                        // Generate after authentication so a rollover during Face ID cannot copy an expired code.
                        SecureClipboard.copy(TOTPGenerator.code(configuration: configuration))
                        UINotificationFeedbackGenerator().notificationOccurred(.success)
                        copied = true
                        try? await Task.sleep(for: .seconds(2))
                        copied = false
                    }
                } label: {
                    Label(copied ? "Copied" : "Copy rotating code", systemImage: copied ? "checkmark.circle.fill" : "doc.on.doc")
                }
                .buttonStyle(.borderedProminent)
                .tint(copied ? NoirTheme.mint : NoirTheme.violet)
            }
        }
        .onChange(of: session.requireBiometricsToCopy) { _, _ in revealed = false }
    }
}

private extension String {
    var chunkedCode: String {
        guard count > 3 else { return self }
        let middle = index(startIndex, offsetBy: count / 2)
        return String(self[..<middle]) + " " + String(self[middle...])
    }
}
