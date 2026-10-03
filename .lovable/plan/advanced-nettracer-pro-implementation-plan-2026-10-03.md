# Advanced NetTracer Pro implementation plan

## Goal
Deliver the requested Wireshark-class analysis features without weakening local-first capture privacy or inventing protocol fields, statistics, anomalies, topology, or AI findings. Existing upload, checkpoint, export, saved-capture, profile, and API-key workflows remain compatible.

## Prerequisite — Correctness, scale, and security baseline
- Move capture parsing and stateful analysis behind a Web Worker contract before adding stream-heavy dissectors, while preserving pause, cancel, checkpoint resume, and selected-packet byte evidence.
- Add a typed dissector registry and fixture harness; remove the disconnected legacy decoder path so one tested decoder determines capability labels and UI fields.
- Require authenticated access and per-user limits for built-in AI before exposing new AI actions; keep vendor-key validation available without persisting keys server-side.
- Replace the current fixed-timeout AI transport with explicit cancellation and gateway-compliant streaming/error handling.

## Milestone 1 — Stateful traffic engine and analyst controls
- Add normalized flow keys and TCP sequence-space tracking for both directions, including retransmissions, out-of-order segments, duplicate ACKs, zero-window events, handshake/close state, RTT samples, and incomplete-stream warnings.
- Implement safe TCP payload reassembly with overlap handling, memory limits, gap markers, text/hex views, direction controls, search, and downloadable Follow Stream output.
- Derive Expert Info entries from explicit packet/flow evidence with severity, packet references, and filter actions.
- Add a versioned coloring-rules editor with ordered rules, enable/disable, preview, validation, local persistence, import/export, and semantic row styles.
- Add unit tests and byte-built PCAP fixtures for handshake, retransmission, gaps, duplicate ACK, reset, and zero-window cases.

## Milestone 2 — Application dissectors
- Extend the worker-safe byte decoder with bounded parsers for HTTP/2 frames and settings, gRPC message envelopes and metadata, QUIC long headers, WebSocket frames, Kafka request/response headers, Redis RESP, PostgreSQL startup/query/response messages, and MySQL handshake/command/result headers.
- Use stream reassembly where a protocol spans TCP segments; expose exact byte offsets only when bytes map to one captured frame and mark reassembled fields separately.
- Add each protocol to the capability registry at its truthful coverage level and include positive, truncated, malformed, segmented, and wrong-port tests using generated wire-format captures committed as fixtures.
- Treat encrypted HTTP/2, gRPC, QUIC, WebSocket, database, and messaging payloads as unavailable unless the capture contains cleartext or supported session-key material; never infer hidden fields.

## Milestone 3 — Statistics and visual analysis
- Add a Statistics menu containing Protocol Hierarchy, Conversations, Endpoints, I/O Graph, Service Response Time, and Flow/Sequence views.
- Compute all counts, bytes, rates, request/response latency, and hierarchy relationships from decoded packets and flow state, with “Unavailable” where correlation is impossible.
- Add protocol/endpoint drill-down filters, CSV/JSON exports, graph export, time-range selection, and scalable sequence rendering.
- Replace remaining dashboard approximations with shared statistics selectors so every view uses one evidence-backed source of truth.

## Milestone 4 — Telecom packet-core analysis
- Expand SCTP chunks and DATA metadata; add bounded multi-chunk association state.
- Walk Diameter AVPs with vendor/application dictionaries, grouped AVPs, command names, request/answer pairing, and result-code display.
- Walk GTPv2-C and PFCP information elements, enrich GTP-U tunnel/session correlation, and preserve inner packet decoding.
- Add NGAP ASN.1 PER support through a vetted browser-compatible decoder path, with an explicit unsupported state for messages outside the bundled schema.
- Decode cleartext 5G SBI HTTP/2/gRPC-style service metadata where present; never claim to decode encrypted TLS payloads without user-supplied session keys.
- Build subscriber/session/call-flow ladders from correlated SCTP, Diameter, GTP, PFCP, NGAP, SIP, and SBI events, with packet links and incomplete-flow notices.
- Validate against protocol-specific capture fixtures and reference field expectations.

## Milestone 5 — Privacy-first AI workflows
- Replace mock AI insights with real server-side streaming through the built-in gateway using `openai/gpt-6-astra`; preserve user-selected external providers as an optional existing path.
- Add a deterministic redaction/minimization pipeline before every request: payloads excluded by default, secrets/tokens/cookies/user identifiers masked, bounded packet evidence, and a visible payload-sharing opt-in.
- Add Explain Packet from selected decoded fields, Analyze Capture reports with clickable packet evidence, natural-language-to-filter generation with parser validation before apply, and capture-scoped chat with Stop.
- Surface exact safe gateway errors and terminal credit/access states; do not fabricate an answer or silently retry denied requests.
- Add redaction, prompt-bounds, filter-validation, abort, and AI response integration tests, then verify one real gateway request.

## Milestone 6 — NetTracer Agent and authenticated live capture
- Add a separate distributable Python agent using tshark JSON streaming, strict capture/interface/BPF allowlists, bounded queues, reconnect backoff, health telemetry, and no embedded credentials.
- Add a versioned authenticated live-session control protocol with ownership checks, packet batching, backpressure, expiration, and audit metadata; use a transport designed for sustained streams rather than writing every packet through request/response functions or database rows.
- Add live-capture UI for agent status, host/interface selection, BPF, start/stop, packets-per-second, dropped packets, and the same packet/detail/statistics tools used offline.
- Supply Kubernetes DaemonSet, ServiceAccount, least-privilege RBAC, Secret references, security context, network policy guidance, and an explicit-consent ephemeral-container capture script; separate packet-capture capabilities from metadata-only Kubernetes API permissions.
- Add agent unit tests, manifest validation, malformed-event tests, reconnect tests, and an authenticated live-session end-to-end test.

## Milestone 7 — Kubernetes intelligence, playbooks, and capture comparison
- Ingest optional pod/service/node/namespace metadata from the authenticated agent and attach it only through observed IP/workload mappings with timestamps and confidence.
- Add namespace/service filters and a dependency map whose edges show observed protocol, packet/byte totals, first/last seen, and drill-down.
- Add evidence-based troubleshooting playbooks that run named checks and link every result to packets, flows, expert events, or an explicit unavailable state.
- Add capture diff for protocol hierarchy, endpoints, conversations, expert events, response times, and dependency edges with normalized time windows and clear added/removed/changed states.

## Technical approach
- Split the monolithic decoder behind a typed dissector registry while retaining current behavior during migration; stateful reassembly and analytics live in independent worker-safe modules.
- Keep raw offline captures in the browser. Only explicitly minimized/redacted evidence crosses the AI boundary; live traffic requires authentication and short-lived session authorization.
- Keep packet summaries compact, derive heavy flow/statistics views on demand, and place large-capture work behind a Web Worker before enabling full stream and protocol analysis at scale.
- Version persisted coloring rules, analysis state, live-session metadata, and saved-capture additions with migrations for older captures.
- Store no agent or vendor secrets in source, browser persistence, capture exports, logs, or database rows.

## Validation and delivery
- Each milestone lands with unit fixtures, malformed/truncated cases, and browser-level workflows before the next protocol family is marked available.
- Compare decoded fields and counts against tshark for representative sample captures while treating tshark output as test reference only, not runtime fallback.
- Run the configured test suite, typecheck, build, lint delta, browser console/network checks, owner-isolation checks, and desktop/mobile interaction checks.
- Deliver the agent, manifests, scripts, sample configuration, and operations guide as a separate package from the browser application.

## Acceptance criteria
- Follow Stream reconstructs both directions without hiding gaps or duplicate bytes, and every expert event links to source packets.
- Requested protocols appear only when decoded from captured bytes, with accurate capability labels and passing fixture assertions.
- Every statistic, ladder, dependency edge, comparison, report citation, and AI input is traceable to packet or enrichment evidence.
- AI sends redacted bounded context by default, streams results, stops cleanly, and shows provider errors without fake fallback content.
- Live capture requires an authenticated owner session, rejects unauthorized agents, tolerates reconnects, and reports capture drops honestly.