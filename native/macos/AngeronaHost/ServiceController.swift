import Foundation
import ServiceManagement
import SystemExtensions

/// Native lifecycle owner for the macOS sensor.
///
/// The Python GUI must never install a launch daemon or system extension by
/// writing privileged files itself. The signed host asks macOS to perform those
/// actions through supported frameworks and surfaces the OS approval state.
final class ServiceController: NSObject, OSSystemExtensionRequestDelegate {
    static let extensionIdentifier = "org.angerona.EndpointSecurityExtension"

    @available(macOS 13.0, *)
    func registerBackgroundService(plistName: String) throws {
        let service = SMAppService.daemon(plistName: plistName)
        if service.status != .enabled {
            try service.register()
        }
    }

    func activateEndpointSecurityExtension() {
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        return ext.bundleShortVersion > existing.bundleShortVersion
            ? .replace
            : .cancel
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        NotificationCenter.default.post(
            name: .angeronaSystemExtensionNeedsApproval,
            object: nil
        )
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        NotificationCenter.default.post(
            name: .angeronaSystemExtensionStateChanged,
            object: result.rawValue
        )
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        NotificationCenter.default.post(
            name: .angeronaSystemExtensionFailed,
            object: error.localizedDescription
        )
    }
}

extension Notification.Name {
    static let angeronaSystemExtensionNeedsApproval =
        Notification.Name("AngeronaSystemExtensionNeedsApproval")
    static let angeronaSystemExtensionStateChanged =
        Notification.Name("AngeronaSystemExtensionStateChanged")
    static let angeronaSystemExtensionFailed =
        Notification.Name("AngeronaSystemExtensionFailed")
}
