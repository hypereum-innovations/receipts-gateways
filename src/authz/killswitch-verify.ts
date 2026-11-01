// SPDX-License-Identifier: Apache-2.0
/**
 * Open-source (Apache-2.0) pure verification half of the Hivemind Receipts
 * kill-switch, break-glass, and revocation feed:
 *  - `verifyHaltStatement`: verify a COSE_Sign1 revocation or break-glass statement
 *  - `verifyHaltFeed`: verify a revocation/halt feed snapshot (freshness + signatures)
 *  - `isScopeHaltedInFeed` / `matchHaltedScopeInFeed`: pure scope check against a `HaltFeed`
 *
 * Zero server state, zero database or mutable revocation custody.
 */
import { createPublicKey, type KeyObject } from 'node:crypto';
import { cborDecode, cborEncode, cborToPlain } from '../core/cbor.js';
import { parseSign1, verifySign1 } from '../core/cose.js';
import { digestOf } from '../core/capsule.js';
import type { ReceiptSigner } from '../core/keys.js';

export type HaltScope =
  | { kind: 'global' }
  | { kind: 'issuer'; issuer: string }
  | { kind: 'agent'; agent: string }
  | { kind: 'workspace'; workspace: string }
  | { kind: 'key'; key: string };

export interface HaltRecord {
  scopeKey: string;
  scope: HaltScope;
  reason: string;
  haltedBy: string;
  atSeconds: number;
  statementDigest?: string | undefined;
}

export interface BreakGlassRecord {
  id: string;
  reason: string;
  openedBy: string;
  startsAtSeconds: number;
  expiresAtSeconds: number;
  reviewDue: true;
  statementDigest?: string | undefined;
}

export interface HaltFeed {
  version: number;
  halts: HaltRecord[];
  breakGlass: BreakGlassRecord[];
  issuedAtSeconds?: number;
  maxStalenessSeconds?: number;
  signedStatements?: Array<Buffer | Uint8Array>;
}

export function scopeKeyFor(s: HaltScope): string {
  switch (s.kind) {
    case 'global':
      return 'global';
    case 'issuer':
      return `issuer:${s.issuer}`;
    case 'agent':
      return `agent:${s.agent}`;
    case 'workspace':
      return `workspace:${s.workspace}`;
    case 'key':
      return `key:${s.key}`;
  }
}

function resolvePublicKey(key: KeyObject | string | ReceiptSigner): KeyObject {
  if (typeof key === 'object' && key !== null && 'publicKeyObject' in key) {
    return key.publicKeyObject();
  }
  if (typeof key === 'string') {
    return createPublicKey(key);
  }
  return key.type === 'public' ? key : createPublicKey(key);
}

export interface VerifiedHaltStatement {
  valid: boolean;
  kind: 'halt' | 'resume' | 'break-glass' | null;
  profile: string | null;
  scopeKey: string | null;
  reason?: string;
  actor?: string;
  atSeconds?: number;
  expiresAtSeconds?: number;
  statementDigest: string | null;
  kid: string | null;
  errors: string[];
}

/**
 * Pure offline verifier for a COSE_Sign1 revocation or break-glass statement.
 */
export function verifyHaltStatement(
  statementBytes: Buffer | Uint8Array,
  verifierKey: KeyObject | string | ReceiptSigner,
): VerifiedHaltStatement {
  const errors: string[] = [];
  const buf = Buffer.from(statementBytes);
  let parsed;
  try {
    parsed = parseSign1(buf);
  } catch (e) {
    return {
      valid: false,
      kind: null,
      profile: null,
      scopeKey: null,
      statementDigest: null,
      kid: null,
      errors: [`cose_parse_failed: ${(e as Error).message}`],
    };
  }

  if (!parsed.payload) {
    return {
      valid: false,
      kind: null,
      profile: null,
      scopeKey: null,
      statementDigest: null,
      kid: parsed.kid,
      errors: ['missing_statement_payload'],
    };
  }

  const pubKey = resolvePublicKey(verifierKey);
  if (!verifySign1(parsed, pubKey)) {
    errors.push('cose_signature_invalid');
  }

  const statementDigest = digestOf(parsed.payload);
  let plain: Record<string, unknown>;
  try {
    plain = cborToPlain(cborDecode(parsed.payload)) as Record<string, unknown>;
  } catch (e) {
    return {
      valid: false,
      kind: null,
      profile: null,
      scopeKey: null,
      statementDigest,
      kid: parsed.kid,
      errors: [...errors, `cbor_decode_failed: ${(e as Error).message}`],
    };
  }

  const profile = typeof plain['profile'] === 'string' ? plain['profile'] : null;
  if (profile === 'urn:hivemind:receipts:revocation:1') {
    const scopeKey = typeof plain['scope'] === 'string' ? plain['scope'] : null;
    if (!scopeKey) errors.push('missing_revocation_scope');
    const isResume = typeof plain['resumed_by'] === 'string';
    const isHalt = typeof plain['halted_by'] === 'string';
    if (!isResume && !isHalt) errors.push('missing_halted_by_or_resumed_by');
    return {
      valid: errors.length === 0,
      kind: isResume ? 'resume' : 'halt',
      profile,
      scopeKey,
      ...(typeof plain['reason'] === 'string' ? { reason: plain['reason'] } : {}),
      actor: String(plain['halted_by'] ?? plain['resumed_by'] ?? ''),
      ...(typeof plain['at'] === 'number' ? { atSeconds: plain['at'] } : {}),
      statementDigest,
      kid: parsed.kid,
      errors,
    };
  }

  if (profile === 'urn:hivemind:receipts:break-glass:1') {
    const id = typeof plain['id'] === 'string' ? plain['id'] : null;
    if (!id) errors.push('missing_break_glass_id');
    return {
      valid: errors.length === 0,
      kind: 'break-glass',
      profile,
      scopeKey: id,
      ...(typeof plain['reason'] === 'string' ? { reason: plain['reason'] } : {}),
      ...(typeof plain['opened_by'] === 'string' ? { actor: plain['opened_by'] } : {}),
      ...(typeof plain['expires'] === 'number' ? { expiresAtSeconds: plain['expires'] } : {}),
      statementDigest,
      kid: parsed.kid,
      errors,
    };
  }

  errors.push(`unsupported_halt_profile: ${String(profile)}`);
  return {
    valid: false,
    kind: null,
    profile,
    scopeKey: null,
    statementDigest,
    kid: parsed.kid,
    errors,
  };
}

export interface VerifyHaltFeedOptions {
  verifierKey?: KeyObject | string | ReceiptSigner;
  nowSeconds?: number;
  maxStalenessSeconds?: number;
}

export interface VerifiedHaltFeedReport {
  valid: boolean;
  stale: boolean;
  version: number;
  activeHaltScopes: string[];
  activeBreakGlassIds: string[];
  verifiedStatements: number;
  errors: string[];
}

/**
 * Pure offline verifier for a `HaltFeed` snapshot.
 * Enforcement points MUST treat a stale revocation feed older than their bound as halted.
 */
export function verifyHaltFeed(
  feed: HaltFeed,
  opts: VerifyHaltFeedOptions = {},
): VerifiedHaltFeedReport {
  const errors: string[] = [];
  const now = opts.nowSeconds ?? Math.floor(Date.now() / 1000);

  if (!feed || typeof feed !== 'object' || typeof feed.version !== 'number' || feed.version < 0) {
    return {
      valid: false,
      stale: false,
      version: -1,
      activeHaltScopes: [],
      activeBreakGlassIds: [],
      verifiedStatements: 0,
      errors: ['malformed_halt_feed'],
    };
  }
  if (!Array.isArray(feed.halts) || !Array.isArray(feed.breakGlass)) {
    return {
      valid: false,
      stale: false,
      version: feed.version,
      activeHaltScopes: [],
      activeBreakGlassIds: [],
      verifiedStatements: 0,
      errors: ['missing_halts_or_break_glass_arrays'],
    };
  }

  let stale = false;
  const maxStaleness = opts.maxStalenessSeconds ?? feed.maxStalenessSeconds;
  if (maxStaleness !== undefined && feed.issuedAtSeconds !== undefined) {
    if (now - feed.issuedAtSeconds > maxStaleness) {
      stale = true;
      errors.push('halt_feed_stale');
    }
  }

  const activeHaltScopes: string[] = [];
  for (const h of feed.halts) {
    if (!h || typeof h.scopeKey !== 'string' || !h.scopeKey) {
      errors.push('invalid_halt_record');
      continue;
    }
    activeHaltScopes.push(h.scopeKey);
  }

  const activeBreakGlassIds: string[] = [];
  for (const bg of feed.breakGlass) {
    if (!bg || typeof bg.id !== 'string') {
      errors.push('invalid_break_glass_record');
      continue;
    }
    if (now >= bg.startsAtSeconds && now < bg.expiresAtSeconds) {
      activeBreakGlassIds.push(bg.id);
    }
  }

  let verifiedStatements = 0;
  if (opts.verifierKey && feed.signedStatements && feed.signedStatements.length > 0) {
    for (const stmt of feed.signedStatements) {
      const res = verifyHaltStatement(stmt, opts.verifierKey);
      if (!res.valid) {
        errors.push(...res.errors);
      } else {
        verifiedStatements++;
      }
    }
  }

  return {
    valid: errors.length === 0,
    stale,
    version: feed.version,
    activeHaltScopes,
    activeBreakGlassIds,
    verifiedStatements,
    errors,
  };
}

export interface HaltScopeQuery {
  issuer?: string | undefined;
  agent?: string | undefined;
  workspace?: string | undefined;
  key?: string | undefined;
  keyId?: string | undefined;
  breakGlassId?: string | undefined;
  nowSeconds?: number | undefined;
  maxStalenessSeconds?: number | undefined;
}

export interface HaltMatchResult {
  halted: boolean;
  scopeKey?: string;
  matchedScope?: string;
  reason?: string;
  breakGlassBypassed?: boolean;
  stale?: boolean;
}

export type HaltStatementVerificationResult = VerifiedHaltStatement;
export type HaltFeedVerificationResult = VerifiedHaltFeedReport;

/**
 * Detailed scope matching against a `HaltFeed` (returns structured match + reason).
 * Fail-closed if the feed is malformed or exceeds its staleness bound.
 */
export function matchHaltedScopeInFeed(
  feed: HaltFeed,
  scopeOrQuery: HaltScope | HaltScopeQuery | string,
): HaltMatchResult {
  if (!feed || !Array.isArray(feed.halts)) {
    return {
      halted: true,
      scopeKey: 'global',
      matchedScope: 'global',
      reason: 'fail-closed: malformed halt feed',
    };
  }

  const queryObj: HaltScopeQuery =
    typeof scopeOrQuery === 'string'
      ? {}
      : 'kind' in scopeOrQuery
        ? {}
        : scopeOrQuery;

  const now = queryObj.nowSeconds ?? Math.floor(Date.now() / 1000);
  const maxStaleness = queryObj.maxStalenessSeconds ?? feed.maxStalenessSeconds;
  if (maxStaleness !== undefined && feed.issuedAtSeconds !== undefined && now - feed.issuedAtSeconds > maxStaleness) {
    return {
      halted: true,
      scopeKey: 'global',
      matchedScope: 'global',
      reason: 'halt feed is stale beyond maxStalenessSeconds bound',
      stale: true,
    };
  }

  if (queryObj.breakGlassId && Array.isArray(feed.breakGlass)) {
    const activeBg = feed.breakGlass.find(
      (bg) => bg.id === queryObj.breakGlassId && now >= bg.startsAtSeconds && now < bg.expiresAtSeconds,
    );
    if (activeBg) {
      return { halted: false, breakGlassBypassed: true };
    }
  }

  const candidateKeys = new Set<string>(['global']);
  if (typeof scopeOrQuery === 'string') {
    candidateKeys.add(scopeOrQuery);
    candidateKeys.add(`agent:${scopeOrQuery}`);
    candidateKeys.add(`issuer:${scopeOrQuery}`);
    candidateKeys.add(`workspace:${scopeOrQuery}`);
    candidateKeys.add(`key:${scopeOrQuery}`);
  } else if ('kind' in scopeOrQuery) {
    candidateKeys.add(scopeKeyFor(scopeOrQuery));
  } else {
    if (scopeOrQuery.issuer) {
      candidateKeys.add(scopeOrQuery.issuer);
      candidateKeys.add(`issuer:${scopeOrQuery.issuer}`);
    }
    if (scopeOrQuery.agent) {
      candidateKeys.add(scopeOrQuery.agent);
      candidateKeys.add(`agent:${scopeOrQuery.agent}`);
    }
    if (scopeOrQuery.workspace) {
      candidateKeys.add(scopeOrQuery.workspace);
      candidateKeys.add(`workspace:${scopeOrQuery.workspace}`);
    }
    const keyVal = scopeOrQuery.key ?? scopeOrQuery.keyId;
    if (keyVal) {
      candidateKeys.add(keyVal);
      candidateKeys.add(`key:${keyVal}`);
    }
  }

  const hit = feed.halts.find((h) => candidateKeys.has(h.scopeKey));
  if (hit) {
    return {
      halted: true,
      scopeKey: hit.scopeKey,
      matchedScope: hit.scopeKey,
      reason: hit.reason,
    };
  }
  return { halted: false };
}

/**
 * Pure boolean check for whether an agent, issuer, workspace, key, or global
 * scope is halted in `feed`.
 */
export function isScopeHaltedInFeed(
  feed: HaltFeed,
  scopeOrQuery: HaltScope | HaltScopeQuery | string,
): boolean {
  return matchHaltedScopeInFeed(feed, scopeOrQuery).halted;
}

/** Tool schema pinning: a changed schema blocks until re-approved. */
export class SchemaPinStore {
  private pins = new Map<string, string>();
  pin(tool: string, schemaDigestValue: string): void {
    this.pins.set(tool, schemaDigestValue);
  }
  assertPinned(tool: string, observedSchema: unknown): string {
    const observed = digestOf(cborEncode(observedSchema as never));
    const pinned = this.pins.get(tool);
    if (pinned && pinned !== observed) {
      const err = new Error(
        `tool schema for ${tool} changed (pinned ${pinned}, observed ${observed}); re-approval required`,
      );
      (err as Error & { code?: string }).code = 'SCHEMA_PIN_MISMATCH';
      throw err;
    }
    if (!pinned) this.pins.set(tool, observed);
    return observed;
  }
}
