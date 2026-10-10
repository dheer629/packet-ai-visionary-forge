import { describe, expect, it } from 'vitest';
import { protocolCounts, matchesProtocolFilter, protocolChoices } from './protocolFilters';
import { captureFilterSuggestions } from './traceProfile';

const packets = [
  { protocol: 'DNS', protocolStack: ['Ethernet', 'IPv4', 'UDP', 'DNS', 'DNS'], info: 'Standard Query A example.test' },
  { protocol: 'TLS', protocolStack: ['Ethernet', 'IPv4', 'TCP', 'TLS'], info: 'Client Hello' },
  { protocol: 'GTPv2-C', decodedLayers: [{ name: 'UDP' }, { name: 'GTPv2-C' }], info: 'Create Session Request' },
];

describe('capture-derived protocol filters', () => {
  it('counts all nested protocols once per frame', () => {
    expect(new Map(protocolCounts(packets)).get('DNS')).toBe(1);
    expect(new Map(protocolCounts(packets)).get('UDP')).toBe(2);
    expect(matchesProtocolFilter(packets[0], ['udp'])).toBe(true);
    expect(matchesProtocolFilter(packets[1], ['UDP'])).toBe(false);
  });
  it('offers suggestions from every observed family and counts exactly the matched frames', () => {
    const suggestions = captureFilterSuggestions(packets);
    expect(suggestions.find((filter) => filter.id === 'dns-queries')?.count).toBe(1);
    expect(suggestions.find((filter) => filter.id === 'web-tls')?.count).toBe(1);
    expect(suggestions.find((filter) => filter.id === 'gtp-control')?.count).toBe(1);
    expect(suggestions.some((filter) => filter.id === 'dns-answers')).toBe(false);
    expect(suggestions.some((filter) => filter.id === 'gtp-user')).toBe(false);
    for (const filter of suggestions) expect(filter.count).toBe(packets.filter((packet) => matchesProtocolFilter(packet, filter.protocols, filter.text)).length);
  });
  it('does not infer protocols from ports or advertise unimplemented decoders', () => {
    const choices = protocolChoices([{ protocol: 'TCP', info: '6379 → 12345' }]);
    expect(choices.find((choice) => choice.name === 'Redis')).toMatchObject({ count: 0, level: 'Partial' });
    expect(choices.find((choice) => choice.name === 'TCP')).toMatchObject({ count: 1, level: 'Available' });
  });
  it('includes previously uncatalogued protocols from actual decoded layers', () => {
    expect(protocolChoices([{ protocol: 'Custom', decodedLayers: [{ name: 'Custom inner' }] }])).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: 'Custom inner', count: 1, level: 'Unregistered' }),
    ]));
  });
});