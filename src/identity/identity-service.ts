import type { ActorAssertion, Principal } from "../types.ts";
import { createMemoryMap, type DurableMap } from "../persistence/durable-map.ts";
import { personKey } from "../directory/person.ts";

interface IdentityProvider {
  resolve(actor: ActorAssertion): Principal;
  classify(externalId: string, isExternalGuest?: boolean): Principal;
}

type DeactivationSource = "manual" | "directory-sync";

export interface DeactivationRecord {
  principalId: string;
  source: DeactivationSource;
  at: number;
}

interface DirectorySyncOutcome {
  deactivated: string[];
  reactivated: string[];
}

export interface IdentityService extends IdentityProvider {
  isInternal(p: Principal): boolean;
  audienceIsAllInternal(audience: Principal[]): boolean;
  deactivate(externalId: string, source?: DeactivationSource): Promise<void>;
  reactivate(externalId: string): Promise<void>;
  recordDirectorySync(removedIds: string[], presentIds: string[]): Promise<DirectorySyncOutcome>;
  hydrate(): Promise<void>;
  refresh(): Promise<void>;
  /**
   * Classify from the durable record rather than the cache.
   *
   * `refresh()` is throttled by `REFRESH_TTL_MS` and each replica caches
   * separately, so for up to that interval a replica can still classify a
   * principal another replica just deactivated as internal. That is tolerable
   * where classification decorates a request, and not tolerable where it is
   * the decision to admit someone. An admission path calls this instead: one
   * keyed durable read, no cache, and a store that cannot answer throws rather
   * than returning a stale answer.
   */
  classifyFresh(externalId: string, isExternalGuest?: boolean): Promise<Principal>;
}

export function createIdentityService(
  backing?: DurableMap<DeactivationRecord>,
  opts: { directorySyncProtected?: readonly string[] } = {},
): IdentityService {
  const store = backing ?? createMemoryMap<DeactivationRecord>();
  const deactivated = new Map<string, DeactivationRecord>();
  const directorySyncProtected = new Set((opts.directorySyncProtected ?? []).map(personKey).filter(Boolean));
  const REFRESH_TTL_MS = 10_000;
  let refreshedAt = 0;
  let refreshP: Promise<void> | null = null;
  let hydrateP: Promise<void> | null = null;

  function classify(externalId: string, isExternalGuest?: boolean): Principal {
    const record = deactivated.get(personKey(externalId));
    const inactive =
      record?.source === "manual" ||
      (record?.source === "directory-sync" && !directorySyncProtected.has(personKey(externalId)));
    const type: Principal["type"] = inactive || isExternalGuest ? "guest" : "internal";
    return { id: externalId, type };
  }

  async function deactivate(externalId: string, source: DeactivationSource = "manual"): Promise<void> {
    const key = personKey(externalId);
    const existing = deactivated.get(key);
    if (existing && (existing.source === "manual" || existing.source === source)) return;
    const record: DeactivationRecord = { principalId: externalId, source, at: Date.now() };
    deactivated.set(key, record);
    await store.put(key, record);
  }

  async function reactivate(externalId: string): Promise<void> {
    const key = personKey(externalId);
    deactivated.delete(key);
    await store.delete(key);
  }

  return {
    classify,
    async classifyFresh(externalId, isExternalGuest) {
      const key = personKey(externalId);
      const record = await store.get(key);
      if (record) deactivated.set(key, record);
      else deactivated.delete(key);
      const inactive =
        record?.source === "manual" || (record?.source === "directory-sync" && !directorySyncProtected.has(key));
      const type: Principal["type"] = inactive || isExternalGuest ? "guest" : "internal";
      return { id: externalId, type };
    },
    deactivate,
    reactivate,
    async recordDirectorySync(removedIds: string[], presentIds: string[]): Promise<DirectorySyncOutcome> {
      const outcome: DirectorySyncOutcome = { deactivated: [], reactivated: [] };
      for (const id of removedIds) {
        if (directorySyncProtected.has(personKey(id)) || deactivated.has(personKey(id))) continue;
        await deactivate(id, "directory-sync");
        outcome.deactivated.push(id);
      }
      for (const id of presentIds) {
        if (deactivated.get(personKey(id))?.source !== "directory-sync") continue;
        await reactivate(id);
        outcome.reactivated.push(id);
      }
      return outcome;
    },
    hydrate(): Promise<void> {
      if (!hydrateP) {
        hydrateP = store.all().then((records) => {
          for (const r of records) {
            const key = personKey(r.principalId);
            if (!deactivated.has(key)) deactivated.set(key, r);
          }
        });
      }
      return hydrateP;
    },
    async refresh(): Promise<void> {
      const now = Date.now();
      if (refreshP) return refreshP;
      if (now - refreshedAt < REFRESH_TTL_MS) return;
      refreshP = store
        .all()
        .then((records) => {
          deactivated.clear();
          for (const record of records) deactivated.set(personKey(record.principalId), record);
          refreshedAt = Date.now();
        })
        .finally(() => {
          refreshP = null;
        });
      return refreshP;
    },
    resolve(actor: ActorAssertion): Principal {
      const p = classify(actor.externalId, actor.isExternalGuest);
      return {
        ...p,
        ...(actor.teamIds ? { teamIds: actor.teamIds } : {}),
        ...(actor.displayName ? { displayName: actor.displayName } : {}),
      };
    },
    isInternal(p: Principal): boolean {
      return p.type === "internal";
    },
    audienceIsAllInternal(audience: Principal[]): boolean {
      return audience.length > 0 && audience.every((p) => p.type === "internal");
    },
  };
}
