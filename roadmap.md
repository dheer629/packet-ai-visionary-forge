# Roadmap

## Enhanced protocol auto-detection
- [x] Add strict byte-signature recognition on nonstandard ports, validate standard-port payloads, and retain transport labels for ambiguous data. Bound parsing to IP/UDP lengths and complete SCTP DATA chunks.
- [x] Add evidence-backed partial recognition for cleartext HTTP/2, Redis, PostgreSQL and MySQL handshakes; rank profiles by observed frame counts, avoid SCTP-only telecom claims and expose detection evidence.
- [x] Verify positive, malformed, truncated, wrong-port and encrypted cases: 57 tests pass; eight-frame binary capture verified nonstandard-port labels, database filtering and JSON evidence export without browser errors.

## Protocols and filter suggestions
- [x] Expose every observed protocol, including nested protocol layers, with per-frame counts and a searchable capability catalog; unavailable entries stay explicit.
- [x] Suggest filters for all matching trace families, not just the dominant profile; 20 regression tests pass. Binary DNS/GTP capture verified queries, signalling, nested UDP selection, and JSON export with no browser errors.

## Current empty-capture report
- [x] Repair Analyze PCAP so it decodes the selected file instead of reopening the picker; support actual drag-and-drop.
- [x] Display offline packets independently of AI/network availability and surface persistent processing errors.
- [x] Verify selection, analysis, repeat analysis, and JSON exports in the browser with AI requests blocked; 16 regression tests pass.
- [ ] Validate the original failing capture: blocked on attachment of superdam_etdp2.pcap (only its screenshot is available).

## NetTracer Pro brief (new)
- [ ] Restore reliable packet visibility for real PCAP, PCAPNG, and CAP inputs; never substitute fabricated rows or statistics.
- [ ] Move offline parsing into a streaming Web Worker and virtualize the packet table for large captures.
- [ ] Build the dense, resizable three-pane analyzer with filter bar, packet tree, and synchronized hex highlighting.
- [ ] Add a validated Wireshark-style display-filter engine with autocomplete, history, saved filters, and field actions.
- [ ] Convert decoding to a protocol-plugin registry and complete the brief's phased protocol, stream, expert, and statistics coverage.
- [ ] Add live-agent delivery artifacts and authenticated live-capture status/streaming.
- [ ] Add annotations, retention, filtered PCAP/object/graph exports, shareable sessions, K8s enrichment, comparisons, and AI workflows.
- [ ] Validate with real sample captures, large-capture tests, security checks, and end-to-end saved/live workflows.

## Requested advanced analyzer expansion
- [ ] TCP stream state, anomaly detection, Follow Stream, Expert Info, and editable coloring rules. (Stream/Expert foundation implemented; coloring rules and advanced state remain.)
- [ ] Tested HTTP/2, gRPC, QUIC, WebSocket, Kafka, Redis, PostgreSQL, and MySQL dissectors.
- [ ] Statistics workspace: hierarchy, conversations, endpoints, I/O, service response time, and sequence flows.
- [ ] Tested SCTP, Diameter AVPs, GTPv2-C, GTP-U, PFCP, NGAP, 5G SBI, and telecom call-flow ladders.
- [ ] Privacy-first AI: redacted evidence, Explain Packet, capture report, natural-language filters, and scoped chat.
- [ ] NetTracer Agent package: tshark streamer, authenticated live ingest, DaemonSet/RBAC, and ephemeral capture.
- [ ] Kubernetes enrichment, dependency map, guided playbooks, and evidence-based capture comparison.

## Scope agreed with user
- Fix AI provider connectivity ("Failed to fetch") by moving vendor calls server-side. No authentication work.
- Broaden protocol decoder coverage ("cover all"), with honest capability reporting.

## Done
- [x] Audit: confirmed Vite React SPA (no Next.js/FastAPI/Supabase auth), root-caused "Failed to fetch" as browser->vendor CORS preflight rejection in `modelProviders.ts` / `aiService.ts`.
- [x] Enabled Lovable Cloud for serverless functions (no auth added).
- [x] `supabase/functions/ai-proxy/index.ts`: server-side adapters for OpenAI, Anthropic, Google, Cohere, DeepSeek, Groq, xAI, Mistral, OpenRouter, Together, plus built-in AI. Actions: test / models / chat. Keys used once, never logged or stored.
- [x] `modelProviders.ts` rewritten: live model discovery per key via the proxy.
- [x] `aiService.ts` rewritten: single proxied chat path with real vendor errors.
- [x] `aiEnhancement.ts`: falls back to built-in AI when no key is configured.

## In progress
- [x] Verified the proxy end to end (built-in chat + invalid-key error path).
- [x] Provider/model status and real vendor error text surfaced in `ApiKeySettings.tsx`.

## Decoder coverage
- [x] Decoder capability registry (Available / Partial / Unavailable) + "Decoders" tab.
- [x] Deep byte-level decoder (`src/utils/decoders/deepDecoder.ts`): link types, VLAN/QinQ/MPLS/PPPoE/GRE/VXLAN/GENEVE, IPv4/IPv6/frags, TCP/UDP/SCTP/ICMP/IGMP/ARP, DNS/DHCP/HTTP/TLS/NTP/SNMP/SIP/RTP/RADIUS/MQTT/CoAP/Modbus, GTP-U/GTPv2-C/PFCP/Diameter.
- [x] Both PCAP and PCAP-NG parsers now route every frame through the deep decoder.
- [x] Removed the 10,000-packet display cap; packet count matches the capture.
- [x] Headers tab shows only captured values ("Unavailable" when a field is absent).
- [x] PacketDetails shows real decoded layers with byte offsets; fabricated placeholder values removed.
- [x] Decode progress bar with pause / resume / cancel for large captures (`decodeControl.ts`, cooperative gate in both parsers).
- [x] Progress now tracks real file offset instead of a fixed packet estimate.
- [x] Packets carry their link type; JSON export of decoded summaries with byte offsets and layer fields (`exportPackets.ts`).
- [x] Protocol + link-type facet filters in the packet list (counts from decoded packets only).
- [x] CSV export of the filtered decoded summaries (same fields as JSON, one row per packet).
- [x] Decode checkpointing in IndexedDB: byte offset + decoded packets are saved every 1000 packets, so a refresh/reconnect can resume from the last checkpoint after the same file is re-selected (name + size + modified time verified). Cleared on completion and on cancel.
- [x] Per-field byte highlighting in the hex view (`HexView.tsx`, `fieldOffsets` on Ethernet/VLAN/IPv4/IPv6/ARP/ICMP/TCP/UDP).

## Accounts & saved captures
- [x] Email + password and Google sign-in (`/auth`, `useAuth` provider, header sign-in/out).
- [x] `profiles` + `captures` tables with owner-only access; private `captures` storage bucket with per-user folder policies.
- [x] Save / open / delete decoded analyses from the header ("My captures").
- [x] API key settings UI (own AI credentials, validated live, kept in the browser only).

## Validation (6,000-packet real PCAP, headless browser)
- [x] Decode + display: 6,000/6,000 packets, 253 IPs, 1,000 conversations, DNS/TCP/NTP decoded from captured bytes.
- [x] Pause → refresh → re-select file: banner showed "3,000 packets decoded (50%)", resume finished at 6,000.
- [x] JSON and CSV exports: 6,000 rows, byte offsets and every decoded layer field, named after the capture.
- [x] Protocol / link-type filter chips, Decoders tab (31 full / 12 partial / 2 not decoded), no console errors.
- Known gaps: no user accounts/auth; vendor AI providers still need the user's own API key (built-in AI works keyless).

