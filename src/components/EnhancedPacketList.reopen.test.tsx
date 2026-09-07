import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, within, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import EnhancedPacketList from './EnhancedPacketList';
import { VIEW_STATE_VERSION, type PacketViewState } from '@/utils/viewState';

/** A small, realistic DNS + TCP capture (decoded shape used by the app). */
const packets = [
  {
    number: 1, time: '0.000000', source: '192.168.1.10', destination: '192.168.1.1',
    protocol: 'DNS', length: 74, info: 'Standard query 0x1a2b A example.com',
    protocolStack: ['Ethernet', 'IPv4', 'UDP', 'DNS'], linkType: 1, linkTypeName: 'Ethernet',
  },
  {
    number: 2, time: '0.012000', source: '192.168.1.1', destination: '192.168.1.10',
    protocol: 'DNS', length: 90, info: 'Standard query response 0x1a2b A 93.184.216.34',
    protocolStack: ['Ethernet', 'IPv4', 'UDP', 'DNS'], linkType: 1, linkTypeName: 'Ethernet',
  },
  {
    number: 3, time: '0.050000', source: '192.168.1.10', destination: '93.184.216.34',
    protocol: 'TCP', length: 66, info: '49152 > 443 [SYN] Seq=0',
    protocolStack: ['Ethernet', 'IPv4', 'TCP'], linkType: 1, linkTypeName: 'Ethernet',
  },
  {
    number: 4, time: '0.060000', source: '93.184.216.34', destination: '192.168.1.10',
    protocol: 'TCP', length: 66, info: '443 > 49152 [SYN, ACK] Seq=0 Ack=1',
    protocolStack: ['Ethernet', 'IPv4', 'TCP'], linkType: 1, linkTypeName: 'Ethernet',
  },
];

const rowProtocols = () =>
  screen
    .getAllByRole('row')
    .slice(1) // skip header
    .map((r) => within(r).getAllByRole('cell')[4]?.textContent?.trim())
    .filter(Boolean);

const renderList = (
  viewState: PacketViewState | null,
  onChange: (s: PacketViewState) => void = () => {},
) =>
  render(
    <EnhancedPacketList
      packets={packets}
      filename="dns-web.pcap"
      captureSize={1024}
      viewState={viewState}
      onViewStateChange={onChange}
    />,
  );

describe('reopening a saved capture', () => {
  beforeEach(() => cleanup());

  it('restores the detected profile, active filter and override selection', async () => {
    const user = userEvent.setup();

    // --- First session: user overrides the view and applies a ready-made filter.
    let saved: PacketViewState | null = null;
    renderList(null, (s) => {
      saved = s;
    });

    const select = screen.getByLabelText('Trace view') as HTMLSelectElement;
    await user.selectOptions(select, 'Name resolution (DNS)');
    await user.click(screen.getByRole('button', { name: /Queries only/i }));

    expect(saved).toBeTruthy();
    expect(saved!.version).toBe(VIEW_STATE_VERSION);
    expect(saved!.profileOverride).toBe('Name resolution (DNS)');
    expect(saved!.appliedFilterId).toBe('dns-queries');
    expect(saved!.search).toBe('Query');

    // --- Second session: the stored capture is reopened.
    cleanup();
    renderList(saved);

    const reopened = screen.getByLabelText('Trace view') as HTMLSelectElement;
    expect(reopened.value).toBe('Name resolution (DNS)');
    expect(screen.getByText(/Trace view \(manual\):/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Queries only/i })).toHaveClass('bg-primary');
    // Only the DNS frames whose info contains "Query" remain visible.
    expect(rowProtocols()).toEqual(['DNS', 'DNS']);
  });

  it('reopens an older capture saved without a schema version', async () => {
    const legacy = {
      profileOverride: 'Name resolution (DNS)',
      appliedFilterId: 'dns-answers',
      selectedProtocols: ['DNS'],
      selectedLinkTypes: [],
      search: 'response',
    } as PacketViewState;

    const onChange = vi.fn();
    renderList(legacy, onChange);

    const select = screen.getByLabelText('Trace view') as HTMLSelectElement;
    expect(select.value).toBe('Name resolution (DNS)');
    expect(screen.getByRole('button', { name: /Responses only/i })).toHaveClass('bg-primary');
    expect(rowProtocols()).toEqual(['DNS']);

    // Re-saving upgrades it to the current schema version.
    const latest = onChange.mock.calls.at(-1)?.[0] as PacketViewState;
    expect(latest.version).toBe(VIEW_STATE_VERSION);
    expect(latest.appliedFilterId).toBe('dns-answers');
  });

  it('falls back to auto-detection when no view was saved', () => {
    renderList(null);
    const select = screen.getByLabelText('Trace view') as HTMLSelectElement;
    expect(select.value).toBe('__auto__');
    expect(screen.getByText(/Detected trace type:/)).toBeInTheDocument();
  });
});
