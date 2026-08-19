import BackgroundTasks
import SwiftUI

@main
struct NetworkSentinelApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase

    init() {
        // The bridge must be live before any BGTask fires. A background relaunch never
        // builds a scene, so `.onAppear` would leave it nil and every wake would no-op.
        let model = AppModel()
        _model = State(initialValue: model)
        AppModelBridge.shared = model
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .preferredColorScheme(.dark)
                .onChange(of: scenePhase) { _, phase in
                    model.handleScenePhase(phase)
                }
        }
    }
}

/// Holds the live AppModel for BGTask callbacks registered at launch.
@MainActor
enum AppModelBridge {
    static weak var shared: AppModel?
}

final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        BackgroundRefresh.register { task in
            Task { @MainActor in
                if let model = AppModelBridge.shared {
                    await model.handleBackgroundRefresh(task)
                } else {
                    // App model not ready — still reschedule.
                    BackgroundRefresh.schedule()
                    task.setTaskCompleted(success: false)
                }
            }
        }
        BackgroundRefresh.schedule()
        return true
    }
}
