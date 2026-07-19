import BackgroundTasks
import UIKit

/// System-scheduled background wake-ups to poll Network Sentinel and post Critical alerts.
enum BackgroundRefresh {
    static let taskId = "com.davidfweiser.NetworkSentinel.refresh"

    /// Call once at launch (before app finishes launching).
    static func register(handler: @escaping (BGAppRefreshTask) -> Void) {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: taskId, using: nil) { task in
            guard let refresh = task as? BGAppRefreshTask else {
                task.setTaskCompleted(success: false)
                return
            }
            handler(refresh)
        }
    }

    /// Ask iOS to wake us later. System chooses the real time (often 15–60+ min).
    static func schedule(earliest: TimeInterval = 15 * 60) {
        let request = BGAppRefreshTaskRequest(identifier: taskId)
        request.earliestBeginDate = Date(timeIntervalSinceNow: earliest)
        do {
            try BGTaskScheduler.shared.submit(request)
        } catch {
            // Non-fatal: low power mode, permission, or simulator limits
            #if DEBUG
            print("BG schedule failed: \(error.localizedDescription)")
            #endif
        }
    }
}
