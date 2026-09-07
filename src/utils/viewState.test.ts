import { describe, it, expect } from 'vitest';
import {
  VIEW_STATE_VERSION,
  migrateViewState,
  hasStoredView,
  withViewStateVersion,
} from './viewState';

describe('saved capture view state versioning', () => {
  it('returns null for missing or invalid input', () => {
    expect(migrateViewState(null)).toBeNull();
    expect(migrateViewState(undefined)).toBeNull();
    expect(migrateViewState('nope')).toBeNull();
  });

  it('migrates an unversioned (v1) view to the current schema', () => {
    const legacy = {
      profileOverride: 'Name resolution (DNS)',
      appliedFilterId: 'dns-queries',
      selectedProtocols: ['DNS'],
      selectedLinkTypes: ['Ethernet'],
      search: 'Query',
    };
    expect(migrateViewState(legacy)).toEqual({
      version: VIEW_STATE_VERSION,
      profileOverride: 'Name resolution (DNS)',
      appliedFilterId: 'dns-queries',
      selectedProtocols: ['DNS'],
      selectedLinkTypes: ['Ethernet'],
      search: 'Query',
    });
  });

  it('accepts the earliest legacy field names', () => {
    const oldest = { profile: 'Voice / SIP', filterId: 'voice-sip', protocols: ['SIP'], query: 'INVITE' };
    expect(migrateViewState(oldest)).toEqual({
      version: VIEW_STATE_VERSION,
      profileOverride: 'Voice / SIP',
      appliedFilterId: 'voice-sip',
      selectedProtocols: ['SIP'],
      selectedLinkTypes: [],
      search: 'INVITE',
    });
  });

  it('keeps a view saved by a newer build usable', () => {
    const future = { version: 99, selectedProtocols: ['GTPv1-U'], somethingNew: { a: 1 } };
    const migrated = migrateViewState(future);
    expect(migrated?.version).toBe(VIEW_STATE_VERSION);
    expect(migrated?.selectedProtocols).toEqual(['GTPv1-U']);
  });

  it('detects whether anything was actually stored', () => {
    expect(hasStoredView(migrateViewState({}))).toBe(false);
    expect(hasStoredView(migrateViewState({ appliedFilterId: 'dns-queries' }))).toBe(true);
  });

  it('stamps the current version when saving', () => {
    expect(withViewStateVersion({ search: 'DNS' }).version).toBe(VIEW_STATE_VERSION);
  });
});
