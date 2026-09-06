# Roadmap

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
- [ ] Optional: per-field byte highlighting in the hex view.

