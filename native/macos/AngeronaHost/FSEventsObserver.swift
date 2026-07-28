import CoreServices
import Foundation

/// File-system observation for the macOS Observe edition.
///
/// FSEvents is asynchronous and lossy by design. Flags such as MustScanSubDirs
/// and EventIdsWrapped are preserved so the shared core can mark a coverage gap
/// and request a bounded rescan instead of pretending no change occurred.
final class FSEventsObserver {
    struct Observation {
        let path: String
        let flags: FSEventStreamEventFlags
        let eventID: FSEventStreamEventId
    }

    private final class CallbackBox {
        let sink: ([Observation]) -> Void

        init(sink: @escaping ([Observation]) -> Void) {
            self.sink = sink
        }
    }

    private var stream: FSEventStreamRef?
    private var callbackBox: CallbackBox?
    private let queue = DispatchQueue(
        label: "org.angerona.macos.fsevents",
        qos: .utility
    )

    func start(
        paths: [String],
        latency: CFTimeInterval = 1.5,
        sink: @escaping ([Observation]) -> Void
    ) -> Bool {
        stop()
        let normalized = Array(Set(paths.filter { !$0.isEmpty })).sorted()
        guard !normalized.isEmpty else { return false }

        let box = CallbackBox(sink: sink)
        callbackBox = box
        var context = FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(box).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        let callback: FSEventStreamCallback = {
            _, contextInfo, count, rawPaths, flags, eventIDs in
            guard
                let contextInfo,
                let flags,
                let eventIDs
            else { return }
            let owner = Unmanaged<CallbackBox>
                .fromOpaque(contextInfo)
                .takeUnretainedValue()
            let paths = unsafeBitCast(rawPaths, to: NSArray.self) as? [String] ?? []
            let available = min(Int(count), paths.count)
            var observations: [Observation] = []
            observations.reserveCapacity(available)
            for index in 0..<available {
                observations.append(Observation(
                    path: paths[index],
                    flags: flags[index],
                    eventID: eventIDs[index]
                ))
            }
            if !observations.isEmpty {
                owner.sink(observations)
            }
        }
        let createFlags =
            FSEventStreamCreateFlags(kFSEventStreamCreateFlagUseCFTypes)
            | FSEventStreamCreateFlags(kFSEventStreamCreateFlagFileEvents)
            | FSEventStreamCreateFlags(kFSEventStreamCreateFlagWatchRoot)
            | FSEventStreamCreateFlags(kFSEventStreamCreateFlagNoDefer)
        guard let created = FSEventStreamCreate(
            kCFAllocatorDefault,
            callback,
            &context,
            normalized as CFArray,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            latency,
            createFlags
        ) else {
            callbackBox = nil
            return false
        }
        stream = created
        FSEventStreamSetDispatchQueue(created, queue)
        if !FSEventStreamStart(created) {
            stop()
            return false
        }
        return true
    }

    func stop() {
        guard let stream else {
            callbackBox = nil
            return
        }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
        self.stream = nil
        callbackBox = nil
    }

    deinit {
        stop()
    }
}
