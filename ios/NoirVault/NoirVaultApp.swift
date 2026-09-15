import SwiftUI

@main
struct NoirVaultApp: App {
    @StateObject private var session = VaultSession()
    private let store = VaultStore()

    var body: some Scene {
        WindowGroup {
            RootView(store: store)
                .environmentObject(session)
                .preferredColorScheme(.dark)
        }
    }
}
