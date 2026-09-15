import SwiftUI

enum NoirTheme {
    static let ink = Color(red: 0.035, green: 0.039, blue: 0.055)
    static let panel = Color(red: 0.075, green: 0.082, blue: 0.112)
    static let elevated = Color(red: 0.115, green: 0.125, blue: 0.165)
    static let violet = Color(red: 0.60, green: 0.47, blue: 1.0)
    static let mint = Color(red: 0.28, green: 0.88, blue: 0.72)
    static let muted = Color.white.opacity(0.58)
}

struct NoirCard: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding(16)
            .background(NoirTheme.panel, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 22, style: .continuous)
                    .stroke(Color.white.opacity(0.08), lineWidth: 1)
            }
    }
}

extension View {
    func noirCard() -> some View { modifier(NoirCard()) }
}
