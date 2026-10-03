# NetTracer Pro implementation plan

## Goal
Upgrade the existing analyzer in place into the requested Wireshark-class NetTracer Pro experience without regressing accounts, saved captures, AI providers, exports, checkpointing, or existing protocol support. All packet values and statistics will come from captured bytes; no fallback or demo values will be presented as real analysis.

## Phase 1 — Reliable offline analyzer foundation
- Reproduce and fix the current “no packets observed” path across PCAP, PCAPNG, and CAP variants, including endian, timestamp-resolution, interface/link-type, truncated-block, and filter-state cases.
- Replace whole-file main-thread parsing with a streaming Web Worker pipeline that sends packet summaries first and lazily decodes a selected packet in detail.
- Preserve pause, cancel, refresh-safe checkpoint resume, progress, and full packet counts while avoiding UI freezes on large files.
- Virtualize the packet list and remove placeholder normalization that turns malformed or unsupported frames into fabricated “Unknown” packets.
- Add real parser fixtures and regression tests for Ethernet, Linux cooked capture, raw IP, mixed-interface PCAPNG, zero/invalid timestamps, truncation, and large captures.

## Phase 2 — Wireshark-familiar workspace
- Recompose the analysis screen as a dense, resizable three-pane workspace: packet list, expandable protocol tree, and synchronized hex/ASCII bytes.
- Add absolute, relative, and delta time modes; keyboard navigation; go-to-packet; command palette; and user-editable packet coloring rules.
- Keep the existing trace-profile detection and ready-made filters, but never auto-hide all packets; reopening a saved capture restores the exact versioned view.
- Replace remaining invented dashboard metrics with calculations derived from decoded packets, or an explicit unavailable state.

## Phase 3 — Display filters and dissector plugins
- Implement a typed display-filter lexer/parser/evaluator for the requested Wireshark-style expressions, with syntax status, autocomplete, history, saved filters, and clickable “Apply as filter / Prepare as filter” field actions.
- Refactor protocol decoding behind a common plugin registry (`detect`, `dissect`, declared fields/capability) while retaining the proven byte decoder during migration.
- Complete core Ethernet/VLAN/ARP/IPv4/IPv6/ICMP/TCP/UDP/DNS/HTTP/TLS behavior first, then expand protocol families in the brief with honest full/partial/unavailable reporting.
- Add TCP flow state for retransmission, duplicate ACK, out-of-order, zero-window, RTT, and stream following; add Decode As for heuristic/port overrides.

## Phase 4 — Analysis, exports, and saved work
- Add protocol hierarchy, endpoints, conversations, I/O graph, response-time views, TCP graphs, flow diagrams, and severity-grouped expert information from actual decoded evidence.
- Add follow-stream views and exports for filtered PCAP, packet CSV/JSON, HTTP objects, graph PNG, and shareable saved sessions.
- Persist saved filters, coloring rules, annotations, capture view state, and retention settings with owner-only access.
- Keep capture storage private and enforce account isolation for every saved object and record.

## Phase 5 — Live agent and cloud-native intelligence
- Deliver a separate downloadable Python NetTracer Agent using tshark/pyshark, plus Kubernetes DaemonSet YAML and an ephemeral-container recipe.
- Add authenticated live streaming through the existing cloud backend, including host/pod/interface/BPF status and packets-per-second telemetry.
- Add Kubernetes mapping enrichment, namespace/service filters, dependency mapping, troubleshooting playbooks, and before/after capture comparison.

## Phase 6 — AI, security, and release validation
- Keep raw payloads local by default; send only bounded summaries and selected decoded fields, with sensitive-data redaction enabled by default.
- Add explain-packet, capture root-cause reports with clickable evidence, natural-language filters, capture-scoped chat, anomaly flags, and incident-summary export.
- Validate authentication, owner-only storage, API-key handling, retention, input bounds, worker cancellation, and live-agent authentication.
- Run automated unit/integration/end-to-end coverage against real HTTP, DNS, TLS, gRPC, Diameter, GTP/PFCP, malformed, mixed-link, and large-capture fixtures; verify desktop and mobile layouts and current build/runtime logs.

## Technical approach
- Stay on the existing React, TypeScript, Tailwind, shadcn, and cloud backend stack.
- Introduce worker-safe parser/dissector modules and packet-summary/detail message contracts rather than a second parser implementation.
- Use a virtualized list for million-packet navigation and IndexedDB for local packet/checkpoint storage; keep only the active window and selected detail in React state.
- Apply database structure changes through migrations with explicit grants and row-level policies; use private object storage for captures.
- Add architecture rules to `AGENTS.md` as each structural decision lands.

## Acceptance criteria
- An upload never completes with an empty packet view unless the capture truly contains zero packet records; active filters are visibly resettable.
- Packet count, bytes, timestamps, fields, summaries, and exports match the source capture and reference dissector results for tested fixtures.
- A large capture remains interactive during parse, can pause/cancel/resume after refresh, and scrolls smoothly without rendering every row.
- Selecting a tree field highlights the exact bytes in both hex and ASCII; selecting bytes identifies the field.
- Saved and live workflows are authenticated, isolated per user, and verified end to end with real data.