# Architecture rules

- Packet data, timestamps, statistics, and exports must be derived from captured bytes; never create synthetic fallback packets or metrics, because this is an evidence-driven analyzer.
- Offline capture parsing must remain browser-local and evolve through worker-safe parser/dissector modules, because large captures must not block the interface.
- Keep decoder capability claims explicit as full, partial, or unavailable, because unsupported protocol details must never be implied.
- Derive TCP flow and expert events from decoded headers plus retained captured payload bytes; omit truncated frames from reassembly to avoid unsupported conclusions.
- Publish offline capture results without invoking AI; explicit AI actions remain separate so connectivity and credentials cannot delay packet visibility.