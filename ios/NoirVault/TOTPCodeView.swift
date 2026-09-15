import SwiftUI
import UIKit

struct TOTPCodeView: View {
    let configuration: TOTPConfiguration
    @State private var copied = false

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let code = TOTPGenerator.code(configuration: configuration, at: context.date)
            let remaining = TOTPGenerator.remainingSeconds(configuration: configuration, at: context.date)
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(code.chunkedCode)
                        .font(.system(size: 32, weight: .bold, design: .rounded))
                        .monospacedDigit()
                    Spacer()
                    ZStack {
                        Circle().stroke(NoirTheme.elevated, lineWidth: 4)
                        Circle().trim(from: 0, to: remaining / Double(configuration.period))
                            .stroke(NoirTheme.mint, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                            .rotationEffect(.degrees(-90))
                        Text("\(max(1, Int(ceil(remaining))))").font(.caption.bold()).monospacedDigit()
                    }
                    .frame(width: 44, height: 44)
                }
                Button {
                    UIPasteboard.general.string = code
                    copied = true
                    UINotificationFeedbackGenerator().notificationOccurred(.success)
                    Task {
                        try? await Task.sleep(for: .seconds(15))
                        if UIPasteboard.general.string == code { UIPasteboard.general.string = "" }
                        copied = false
                    }
                } label: {
                    Label(copied ? "Copied" : "Copy rotating code", systemImage: copied ? "checkmark.circle.fill" : "doc.on.doc")
                }
                .buttonStyle(.borderedProminent)
                .tint(copied ? NoirTheme.mint : NoirTheme.violet)
            }
        }
    }
}

private extension String {
    var chunkedCode: String {
        guard count > 3 else { return self }
        let middle = index(startIndex, offsetBy: count / 2)
        return String(self[..<middle]) + " " + String(self[middle...])
    }
}
