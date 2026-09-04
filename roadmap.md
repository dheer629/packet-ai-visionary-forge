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
- [ ] Verify the proxy end to end (built-in chat + an invalid-key error path).
- [ ] Surface provider/model status and real error text in `ApiKeySettings.tsx`.

## Next: decoder coverage
- [ ] Decoder capability registry reporting Available / Partial / Unavailable per protocol (no fabricated support claims).
- [ ] Link/encapsulation: VLAN 802.1Q, QinQ, MPLS, PPPoE, GRE, VXLAN, GENEVE, SLL2, raw IP, loopback.
- [ ] Network/transport: SCTP, IGMP, IP fragmentation, TCP stream reassembly.
- [ ] Application: DNS/mDNS/LLMNR, DHCP/DHCPv6, HTTP/1.1, TLS handshake metadata, NTP, SNMP, SIP/SDP, RTP/RTCP, RADIUS, MQTT, CoAP, Modbus/TCP.
- [ ] Telecom: GTPv1-U, GTPv2-C, PFCP, Diameter, SCTP-carried SIGTRAN (M3UA/SCCP) where genuinely decodable in TypeScript.
- [ ] Decoder configuration UI + per-field evidence (packet number, byte offset).
