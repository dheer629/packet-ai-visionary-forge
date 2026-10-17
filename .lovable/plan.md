# NetTracer Pro production upgrade

## Outcome
Deliver the broadest practical, maintained decoder coverage while keeping offline captures local, packet evidence accurate, and unsupported details explicit. This is a phased release—not a claim that every internet decoder or every possible record has been tested.

## 1. Close release blockers first
- Remove fabricated AI findings and all fallback analysis. Report unavailable analysis instead of invented security conclusions.
- Remove capture bytes, addresses, and credentials from production diagnostic logging.
- Require verified users and usage limits for funded AI actions; retain account-free offline analysis and existing external-provider choices.
- Add centralized redaction, bounded evidence sharing, cancellation, and safe error handling for AI.
- Validate saved-analysis schemas and handle failed storage deletion without silently deleting the capture listing.
- Clearly report malformed containers, truncated records, partial decoding, and capture completeness.

## 2. Establish a scalable local capture engine
- Move parsing and heavy analysis into an isolated Web Worker with bounded queues, cancellation, progress and pause/resume.
- Retain original capture bytes locally and index frame offsets; load packet details and hex bytes on demand rather than duplicating every payload in memory.
- Preserve checkpoint resume, detected profiles, saved views, filtering, packet selection, and JSON/CSV exports.
- Publish measured capture-size and memory limits; do not advertise 500 MB support until tested on representative devices.

## 3. Expand decoder breadth through a maintained engine
- Evaluate a pinned browser-local Wireshark-compatible WebAssembly engine before integration; verify its actual protocol list, license/source-distribution obligations, asset loading, memory behavior and maintenance status.
- Run it inside the worker behind a common decoder interface, rather than downloading arbitrary internet dissectors or executing uploaded plugins.
- Keep the current byte decoder as an explicit selectable engine where needed, not a silent substitute when the comprehensive engine fails.
- Discover capabilities from the shipped engine and show full/partial/unavailable support, including version and limits.
- Integrate packet trees, display filters, protocol suggestions, stream following, expert events and statistics only where supported by actual engine results.
- Encrypted contents remain unavailable without supported user-supplied session keys; session keys stay local and out of saved captures, exports and AI requests.

## 4. Build a real-capture validation corpus
- Obtain redistributable captures from authoritative public sample repositories; record source, license, checksum, expected packet counts and reference-tool version.
- Test PCAP microsecond/nanosecond and endian variants; PCAPNG sections, interfaces, timestamp resolutions and supported packet-block types; CAP by actual file signature, not extension alone.
- Include Ethernet/VLAN, cooked Linux, raw IP, loopback and supported additional link types; preserve unsupported records with an explicit status.
- Cover DNS, HTTP/TLS, IPv4/IPv6, transport/stream edge cases, tunnelling, voice, databases/messaging and telecom families where suitable licensed samples exist.
- Pair real captures with generated malformed/truncated/segmented fixtures; label generated fixtures separately from real traffic.
- Compare counts, timestamps, lengths, selected fields and display-filter results against a pinned tshark reference. Maintain a tested/untested/unavailable matrix rather than asserting universal coverage.

## 5. Verify release workflows end to end
- Browser checks: upload, packet count, profile/filter suggestions, packet tree/hex selection, stream/expert/statistics views, exports, cancellation and refresh/resume.
- Authenticated checks: save, reopen, view restoration, delete, expired-session handling and owner isolation with authorized test accounts.
- Security checks: AI authorization/limits, redaction, credential leakage, malformed input, capture retention and private storage. Basic backend scans supplement rather than replace these tests.
- Performance checks: increasing real capture sizes, UI responsiveness, worker crashes, memory pressure and predictable failure/recovery.
- Produce a release coverage report with measured limits, engine version, passing checks, known exclusions and remaining blockers. Publishing is a separate explicit user action.

## Technical approach
- Retain React/Vite, the current design system and cloud services; no persistent server is added to the SPA.
- Version the worker contracts, engine results and saved analysis; migrate older saved views.
- Pin executable dependencies and verify downloadable engine artifacts. Review copyleft obligations before shipping a Wireshark-derived runtime.
- Do not mark a family fully decoded just because its protocol name exists in a catalog.
- An optional tshark agent can provide device/live capture later; it is not required for private offline analysis or used to send raw captures to a server automatically.

## Baseline established
- All 65 existing tests passed with bounded test parallelism; an unrestricted run hit a saved-view test timeout, which passed independently.
- Basic backend security checks found no issues; deep code review still identified the AI and capture-lifecycle blockers above.
- Real-capture end-to-end coverage and maximum-size performance are not yet established. The original failing `superdam_etdp2.pcap` is still unavailable.