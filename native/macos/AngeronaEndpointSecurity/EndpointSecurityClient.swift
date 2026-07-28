import EndpointSecurity
import Foundation

/// Observe-only Endpoint Security client.
///
/// Keep this subscription list on NOTIFY events. AUTH events require a separate
/// enforcement design, latency budget, fail-open/fail-closed policy, and review.
final class EndpointSecurityClient {
    enum ClientError: Error {
        case creation(es_new_client_result_t)
        case subscription(es_return_t)
    }

    private var client: OpaquePointer?
    private let sink: (UnsafePointer<es_message_t>) -> Void

    init(sink: @escaping (UnsafePointer<es_message_t>) -> Void) {
        self.sink = sink
    }

    deinit {
        stop()
    }

    func start() throws {
        guard client == nil else { return }
        var created: OpaquePointer?
        let result = es_new_client(&created) { _, message in
            ObserveEventRouter.shared.route(message)
        }
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let created else {
            throw ClientError.creation(result)
        }
        client = created
        ObserveEventRouter.shared.handler = sink

        var events: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_CREATE,
            ES_EVENT_TYPE_NOTIFY_WRITE,
            ES_EVENT_TYPE_NOTIFY_RENAME,
            ES_EVENT_TYPE_NOTIFY_UNLINK,
        ]
        let subscribed = events.withUnsafeMutableBufferPointer {
            es_subscribe(created, $0.baseAddress, UInt32($0.count))
        }
        guard subscribed == ES_RETURN_SUCCESS else {
            es_delete_client(created)
            client = nil
            throw ClientError.subscription(subscribed)
        }
    }

    func stop() {
        guard let client else { return }
        es_unsubscribe_all(client)
        es_delete_client(client)
        self.client = nil
        ObserveEventRouter.shared.handler = nil
    }
}

/// `es_new_client` requires a C-compatible callback. This router keeps the
/// callback non-blocking; the production sink must copy only the required
/// fields and hand work to a bounded serial queue before returning.
private final class ObserveEventRouter {
    static let shared = ObserveEventRouter()
    var handler: ((UnsafePointer<es_message_t>) -> Void)?

    func route(_ message: UnsafePointer<es_message_t>) {
        handler?(message)
    }
}
