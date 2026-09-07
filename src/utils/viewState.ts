/**
 * Versioned view state stored alongside a saved capture.
 *
 * Older captures were saved without a version field (v1). Migrations run when a
 * capture is reopened so an outdated stored view still restores correctly.
 */

export const VIEW_STATE_VERSION = 2;

export interface PacketViewState {
  /** Schema version of this stored view. */
  version?: number;
  profileOverride?: string | null;
  appliedFilterId?: string | null;
  selectedProtocols?: string[];
  selectedLinkTypes?: string[];
  search?: string;
}

const toStringArray = (value: unknown): string[] =>
  Array.isArray(value) ? value.map((v) => String(v)).filter((v) => v.length > 0) : [];

const toNullableString = (value: unknown): string | null =>
  typeof value === 'string' && value.length > 0 ? value : null;

/**
 * Normalises any stored view (versioned or legacy) into the current schema.
 * Returns null when there is nothing usable to restore.
 */
export const migrateViewState = (raw: unknown): PacketViewState | null => {
  if (!raw || typeof raw !== 'object') return null;
  const input = raw as Record<string, unknown>;
  const version = typeof input.version === 'number' ? input.version : 1;

  // v1 captures used `protocols` / `linkTypes` / `query` in the earliest builds
  // and later the current names without a version marker. Accept both.
  const selectedProtocols = toStringArray(
    input.selectedProtocols ?? input.protocols,
  );
  const selectedLinkTypes = toStringArray(
    input.selectedLinkTypes ?? input.linkTypes,
  );
  const search =
    typeof input.search === 'string'
      ? input.search
      : typeof input.query === 'string'
        ? input.query
        : '';

  const migrated: PacketViewState = {
    version: VIEW_STATE_VERSION,
    profileOverride: toNullableString(input.profileOverride ?? input.profile),
    appliedFilterId: toNullableString(input.appliedFilterId ?? input.filterId),
    selectedProtocols,
    selectedLinkTypes,
    search,
  };

  // A view saved by a newer build: keep only the fields this build understands.
  if (version > VIEW_STATE_VERSION) {
    return { ...migrated, version: VIEW_STATE_VERSION };
  }

  return migrated;
};

/** True when the stored view actually changes anything from the defaults. */
export const hasStoredView = (state: PacketViewState | null | undefined): boolean =>
  Boolean(
    state &&
      (state.profileOverride ||
        state.appliedFilterId ||
        (state.selectedProtocols?.length ?? 0) > 0 ||
        (state.selectedLinkTypes?.length ?? 0) > 0 ||
        state.search),
  );

/** Stamps the current schema version onto a view before it is saved. */
export const withViewStateVersion = (state: PacketViewState): PacketViewState => ({
  ...state,
  version: VIEW_STATE_VERSION,
});
