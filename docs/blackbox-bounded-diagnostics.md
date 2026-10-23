# Black Box bounded diagnostic reads

Black Box reads current status and historical self-test reports through end of file in requests of at most 64 KiB. Each source has an independent 4 MiB admission limit. Failed or oversized reads never admit a partially read JSON prefix. Original diagnostics remain untouched.

Historical self-test evidence is advisory. Missing, denied, oversized, malformed or unsupported history appears as unavailable evidence; it does not become a healthy result or hide current process-bound module failures. History display retains bounded rows and plain-text presentation. Existing process identity, heartbeat freshness and current health decisions are unchanged.

The isolated public checkout passed **128 selected Black Box regression tests with zero skips**. Both the launcher and executing interpreter retired normally, all retained native handles closed, and Qt and worker cleanup completed before exit.

This validates the selected diagnostic-read and Black Box regression scenarios. It is not a full-suite or live-host endurance result, a detection-coverage claim, or proof that local diagnostic files are independently authenticated.
