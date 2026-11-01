// SPDX-License-Identifier: Apache-2.0
/**
 * Agent Action Capsule payload profile (`urn:hivemind:receipts:capsule:1`),
 * carried as the payload of a SCITT Signed Statement. Invariants (binding):
 *  1. A capsule exists for EVERY verdict — executed, blocked, denied,
 *     errored, engine_failure, timed_out. No survivorship bias.
 *  2. A confirmed effect always carries response_digest over the observed
 *     response. An attempt can never be presented as a completion.
 *  3. assurance.ledger_mode === 'anchored' is claimable only with a verified
 *     SCITT receipt (enforced by the verifier, not by trust in this field).
 *  4. Class-1 verification consults no model, no network, no clock heuristics.
 * Sensitive fields enter the payload as salted HMAC commitments only; the
 * salt and disclosed values travel off-log (see commitments in this file).
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { cborDecode, cborEncode, cborToPlain, jcsStringify } from './cbor.js';
import { sha256, ulid, ULID_RE } from './keys.js';

export const CAPSULE_PROFILE_URI = 'urn:hivemind:receipts:capsule:1';
export const CAPSULE_MEDIA_TYPE = 'application/vnd.hivemind.agent-action-capsule+cbor';

/**
 * Profile versioning: breaking changes mint a new URI; verifiers accept
 * every version they know. A capsule from an unknown *newer* version of
 * this family still parses (signature and inclusion are version-agnostic)
 * but its invariants are reported as unchecked — never silently trusted.
 */
export const KNOWN_CAPSULE_PROFILES = new Set([CAPSULE_PROFILE_URI]);
const PROFILE_FAMILY_RE = /^urn:hivemind:receipts:capsule:(\d+)$/;

export function capsuleProfileVersion(uri: string): number | null {
  const m = PROFILE_FAMILY_RE.exec(uri);
  return m ? Number(m[1]) : null;
}

export function isKnownCapsuleProfile(uri: string): boolean {
  return KNOWN_CAPSULE_PROFILES.has(uri);
}

export const VERDICT_CLASSES = [
  'executed',
  'blocked',
  'denied',
  'errored',
  'engine_failure',
  'timed_out',
] as const;
export type VerdictClass = (typeof VERDICT_CLASSES)[number];

export const RISK_TIERS = ['read', 'write', 'destructive', 'financial', 'external_communication'] as const;
export type RiskTier = (typeof RISK_TIERS)[number];

export const LEDGER_MODES = ['standalone', 'chained', 'anchored'] as const;
export type LedgerMode = (typeof LEDGER_MODES)[number];

export type Digest = string; // "sha256:<hex>"

export function digestOf(data: Uint8Array | string): Digest {
  return `sha256:${sha256(data).toString('hex')}`;
}
export function isDigest(v: unknown): v is Digest {
  return typeof v === 'string' && /^sha256:[0-9a-f]{64}$/.test(v);
}

/** Salted commitment: HMAC-SHA-256(salt, fieldName || 0x00 || canonical CBOR(value)). */
export function saltedCommitment(salt: Uint8Array, field: string, value: unknown): Digest {
  const mac = createHmac('sha256', Buffer.from(salt));
  mac.update(Buffer.from(field, 'utf8'));
  mac.update(Buffer.from([0]));
  mac.update(cborEncode(value as never));
  return `sha256:${mac.digest('hex')}`;
}

export function verifyCommitment(
  commitment: Digest,
  salt: Uint8Array,
  field: string,
  value: unknown,
): boolean {
  const expected = saltedCommitment(salt, field, value);
  const a = Buffer.from(expected);
  const b = Buffer.from(String(commitment));
  return a.length === b.length && timingSafeEqual(a, b);
}

export type ConfirmationLevelTag = 'W0' | 'W1' | 'W2' | 'W3';

export type CapsulePhase = 'intent' | 'outcome' | 'confirmation';
export const CAPSULE_PHASES = ['intent', 'outcome', 'confirmation'] as const;

export interface CrossOrgRef {
  origin: string;
  leaf_index: number;
  statement_digest: Digest;
}

export interface AgentIdentity {
  spiffe_id?: string;
  agent_card_digest?: Digest;
  key_thumbprint?: string;
  config_epoch?: string;
  framework?: string;
  model_id?: string;
}

export interface CapsuleCore {
  profile: typeof CAPSULE_PROFILE_URI;
  action_id: string;
  retry_of?: string;
  phase?: CapsulePhase;
  sequence_number?: number;
  session_id?: string;
  intent_capsule_id?: string;
  intent_digest?: Digest;
  prev_capsule_hash?: Digest;
  parent_capsule_hashes?: Digest[];
  cross_org_refs?: CrossOrgRef[];
  confirmation_level?: ConfirmationLevelTag;
  evidence_digest?: Digest;
  outcome_capsule_id?: Digest;
  agent: AgentIdentity;
  principal: { subject_commitment: Digest; delegation_chain_digest?: Digest; token_issuer?: string; token_scopes?: string[] };
  operation: {
    kind: 'mcp' | 'a2a' | 'http' | 'tool' | 'other';
    method: string;
    target_commitment?: Digest;
    tool_schema_digest?: Digest;
    risk_tier: RiskTier;
  };
  request_digest: Digest;
  verdict_class: VerdictClass;
  effect?: { status: 'confirmed' | 'asserted' | 'none'; response_digest?: Digest; summary_commitment?: Digest };
  disposition: { authority?: string; decision_digest?: Digest; approval_digest?: Digest; break_glass?: boolean };
  criteria_ref?: Digest;
  model?: { provider?: string; model_id?: string; model_version?: string; region?: string; provider_request_id?: string };
  runtime?: { image_digest?: Digest; attestation_ref?: string };
  causality: {
    parent_capsule_ids?: Digest[];
    dag_root?: Digest;
    trace_id?: string;
    span_id?: string;
    a2a_task_id?: string;
    mcp_request_id?: string;
  };
  assurance: { ledger_mode: LedgerMode; attestation_mode: 'none' | 'nitro' | 'sev-snp' | 'tdx' | 'gpu' };
  privacy: { disclosure_policy_id: string; salt_commitment: Digest };
  issued_at: string; // issuer clock, informative only
  extensions?: Record<string, unknown>; // io.hivemind.* and other namespaced keys
}

export interface Capsule extends CapsuleCore {
  capsule_id: Digest;
}

export interface Disclosure {
  capsule_id: Digest;
  salt: string; // base64url, 32 bytes
  fields: Record<string, unknown>; // field name -> disclosed value
}

export interface BuildCapsuleInput {
  actionId?: string;
  salt?: Buffer;
  phase?: CapsulePhase;
  sequence_number?: number;
  sequenceNumber?: number;
  session_id?: string;
  sessionId?: string;
  intent_capsule_id?: string;
  intentCapsuleId?: string;
  intent_digest?: Digest;
  intentDigest?: Digest;
  prev_capsule_hash?: Digest;
  prevCapsuleHash?: Digest;
  parent_capsule_hashes?: Digest[];
  parentCapsuleHashes?: Digest[];
  cross_org_refs?: CrossOrgRef[];
  crossOrgRefs?: CrossOrgRef[];
  confirmation_level?: ConfirmationLevelTag;
  confirmationLevel?: ConfirmationLevelTag;
  evidence_digest?: Digest;
  evidenceDigest?: Digest;
  outcome_capsule_id?: Digest;
  outcomeCapsuleId?: Digest;
  agent: CapsuleCore['agent'];
  principalSubject: unknown;
  delegationChainDigest?: Digest;
  tokenIssuer?: string;
  tokenScopes?: string[];
  operation: Omit<CapsuleCore['operation'], 'target_commitment'> & { target?: unknown };
  requestArgs: unknown;
  verdict: VerdictClass;
  observedResponse?: unknown;
  effectSummary?: unknown;
  disposition: CapsuleCore['disposition'];
  criteriaRef?: Digest;
  model?: CapsuleCore['model'];
  runtime?: CapsuleCore['runtime'];
  causality?: CapsuleCore['causality'];
  ledgerMode?: LedgerMode;
  attestationMode?: CapsuleCore['assurance']['attestation_mode'];
  disclosurePolicyId?: string;
  issuedAt?: string;
  retryOf?: string;
  extensions?: Record<string, unknown>;
}

const EXT_KEY_RE = /^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)+$/;

export function validateCapsuleCore(c: CapsuleCore): string[] {
  const errs: string[] = [];
  if (!isKnownCapsuleProfile(c.profile)) errs.push(`unknown profile ${String(c.profile)}`);
  if (!ULID_RE.test(c.action_id ?? '')) errs.push('action_id must be a ULID');
  if (c.retry_of !== undefined && !ULID_RE.test(c.retry_of)) errs.push('retry_of must be a ULID');
  if (c.phase !== undefined && !CAPSULE_PHASES.includes(c.phase))
    errs.push(`bad phase ${String(c.phase)}`);
  if (
    c.sequence_number !== undefined &&
    (!Number.isSafeInteger(c.sequence_number) || c.sequence_number < 0)
  )
    errs.push('sequence_number must be a non-negative integer');
  if (c.intent_digest !== undefined && !isDigest(c.intent_digest))
    errs.push('intent_digest must be sha256:<hex>');
  if (c.prev_capsule_hash !== undefined && !isDigest(c.prev_capsule_hash))
    errs.push('prev_capsule_hash must be sha256:<hex>');
  if (
    c.parent_capsule_hashes !== undefined &&
    (!Array.isArray(c.parent_capsule_hashes) || !c.parent_capsule_hashes.every(isDigest))
  )
    errs.push('parent_capsule_hashes must be an array of sha256:<hex>');
  if (c.cross_org_refs !== undefined) {
    if (!Array.isArray(c.cross_org_refs)) {
      errs.push('cross_org_refs must be an array');
    } else {
      for (const ref of c.cross_org_refs) {
        if (!ref?.origin || typeof ref.origin !== 'string')
          errs.push('cross_org_refs.origin is required');
        if (!Number.isSafeInteger(ref?.leaf_index) || ref.leaf_index < 0)
          errs.push('cross_org_refs.leaf_index must be a non-negative integer');
        if (!isDigest(ref?.statement_digest))
          errs.push('cross_org_refs.statement_digest must be sha256:<hex>');
      }
    }
  }
  if (c.evidence_digest !== undefined && !isDigest(c.evidence_digest))
    errs.push('evidence_digest must be sha256:<hex>');
  if (c.outcome_capsule_id !== undefined && !isDigest(c.outcome_capsule_id))
    errs.push('outcome_capsule_id must be sha256:<hex>');
  if (!isDigest(c.request_digest)) errs.push('request_digest must be sha256:<hex>');
  if (!VERDICT_CLASSES.includes(c.verdict_class)) errs.push(`bad verdict_class ${String(c.verdict_class)}`);
  if (c.effect?.status === 'confirmed' && !isDigest(c.effect.response_digest))
    errs.push('invariant 2: a confirmed effect must carry response_digest');
  if (c.verdict_class !== 'executed' && c.effect?.status === 'confirmed')
    errs.push('a non-executed verdict cannot claim a confirmed effect');
  if (!RISK_TIERS.includes(c.operation?.risk_tier)) errs.push('bad operation.risk_tier');
  if (!c.operation?.method) errs.push('operation.method is required');
  if (!LEDGER_MODES.includes(c.assurance?.ledger_mode)) errs.push('bad assurance.ledger_mode');
  if (!isDigest(c.privacy?.salt_commitment)) errs.push('privacy.salt_commitment must be a digest');
  if (!c.privacy?.disclosure_policy_id) errs.push('privacy.disclosure_policy_id is required');
  if (c.extensions)
    for (const k of Object.keys(c.extensions))
      if (!EXT_KEY_RE.test(k)) errs.push(`extension key ${k} must be namespaced (e.g. io.hivemind.x)`);
  return errs;
}

/**
 * Build a capsule from action inputs. The salt never enters the payload; only
 * its digest does, so a later disclosure is bound to THIS salt. request_digest
 * and response_digest are salted commitments over the canonical arguments and
 * the observed response — low-entropy values cannot be brute-forced from them.
 */
export function buildCapsule(input: BuildCapsuleInput): {
  capsule: Capsule;
  capsuleBytes: Buffer;
  disclosure: Disclosure;
} {
  const salt = input.salt ?? randomBytes(32);
  if (salt.length !== 32) throw new Error('per-receipt salt must be 256 bits');
  const commit = (field: string, v: unknown) => saltedCommitment(salt, field, v);
  const disclosed: Record<string, unknown> = {
    'principal.subject': input.principalSubject,
    request: input.requestArgs,
  };
  if (input.observedResponse !== undefined) disclosed['response'] = input.observedResponse;
  if (input.effectSummary !== undefined) disclosed['effect.summary'] = input.effectSummary;
  if (input.operation.target !== undefined) disclosed['operation.target'] = input.operation.target;

  const sequenceNumber = input.sequence_number ?? input.sequenceNumber;
  const sessionId = input.session_id ?? input.sessionId;
  const intentCapsuleId = input.intent_capsule_id ?? input.intentCapsuleId;
  const intentDigest = input.intent_digest ?? input.intentDigest;
  const prevCapsuleHash = input.prev_capsule_hash ?? input.prevCapsuleHash;
  const parentCapsuleHashes = input.parent_capsule_hashes ?? input.parentCapsuleHashes;
  const crossOrgRefs = input.cross_org_refs ?? input.crossOrgRefs;
  const confirmationLevel = input.confirmation_level ?? input.confirmationLevel;
  const evidenceDigest = input.evidence_digest ?? input.evidenceDigest;
  const outcomeCapsuleId = input.outcome_capsule_id ?? input.outcomeCapsuleId;

  const core: CapsuleCore = {
    profile: CAPSULE_PROFILE_URI,
    action_id: input.actionId ?? ulid(Date.now(), (n) => randomBytes(n)),
    ...(input.retryOf ? { retry_of: input.retryOf } : {}),
    ...(input.phase !== undefined ? { phase: input.phase } : {}),
    ...(sequenceNumber !== undefined ? { sequence_number: sequenceNumber } : {}),
    ...(sessionId !== undefined ? { session_id: sessionId } : {}),
    ...(intentCapsuleId !== undefined ? { intent_capsule_id: intentCapsuleId } : {}),
    ...(intentDigest !== undefined ? { intent_digest: intentDigest } : {}),
    ...(prevCapsuleHash !== undefined ? { prev_capsule_hash: prevCapsuleHash } : {}),
    ...(parentCapsuleHashes !== undefined ? { parent_capsule_hashes: parentCapsuleHashes } : {}),
    ...(crossOrgRefs !== undefined ? { cross_org_refs: crossOrgRefs } : {}),
    ...(confirmationLevel !== undefined ? { confirmation_level: confirmationLevel } : {}),
    ...(evidenceDigest !== undefined ? { evidence_digest: evidenceDigest } : {}),
    ...(outcomeCapsuleId !== undefined ? { outcome_capsule_id: outcomeCapsuleId } : {}),
    agent: input.agent,
    principal: {
      subject_commitment: commit('principal.subject', input.principalSubject),
      ...(input.delegationChainDigest ? { delegation_chain_digest: input.delegationChainDigest } : {}),
      ...(input.tokenIssuer ? { token_issuer: input.tokenIssuer } : {}),
      ...(input.tokenScopes ? { token_scopes: [...input.tokenScopes].sort() } : {}),
    },
    operation: {
      kind: input.operation.kind,
      method: input.operation.method,
      risk_tier: input.operation.risk_tier,
      ...(input.operation.target !== undefined
        ? { target_commitment: commit('operation.target', input.operation.target) }
        : {}),
      ...(input.operation.tool_schema_digest
        ? { tool_schema_digest: input.operation.tool_schema_digest }
        : {}),
    },
    request_digest: commit('request', input.requestArgs),
    verdict_class: input.verdict,
    ...(input.verdict === 'executed'
      ? {
          effect: {
            status: input.observedResponse !== undefined ? ('confirmed' as const) : ('asserted' as const),
            ...(input.observedResponse !== undefined
              ? { response_digest: commit('response', input.observedResponse) }
              : {}),
            ...(input.effectSummary !== undefined
              ? { summary_commitment: commit('effect.summary', input.effectSummary) }
              : {}),
          },
        }
      : { effect: { status: 'none' as const } }),
    disposition: input.disposition,
    ...(input.criteriaRef ? { criteria_ref: input.criteriaRef } : {}),
    ...(input.model ? { model: input.model } : {}),
    ...(input.runtime ? { runtime: input.runtime } : {}),
    causality: input.causality ?? {},
    assurance: {
      ledger_mode: input.ledgerMode ? input.ledgerMode : 'standalone',
      attestation_mode: input.attestationMode ? input.attestationMode : 'none',
    },
    privacy: {
      disclosure_policy_id: input.disclosurePolicyId ?? 'io.hivemind.disclosure.default',
      salt_commitment: digestOf(salt),
    },
    issued_at: input.issuedAt ?? new Date().toISOString(),
    ...(input.extensions ? { extensions: input.extensions } : {}),
  };
  return finalizeCapsule(core, salt, disclosed);
}

/**
 * Convenience builder for Phase 1 (`intent`) of the 3-phase action capsule lifecycle.
 * Emitted before the tool/action executes, committing to the intended operation and request args.
 */
export function buildIntentCapsule(
  input: Omit<BuildCapsuleInput, 'phase' | 'verdict'> & { verdict?: VerdictClass },
): { capsule: Capsule; capsuleBytes: Buffer; disclosure: Disclosure } {
  return buildCapsule({
    ...input,
    phase: 'intent',
    verdict: input.verdict ?? 'executed',
  });
}

/**
 * Convenience builder for Phase 2 (`outcome`) of the 3-phase action capsule lifecycle.
 * Cryptographically binds to the preceding `intentCapsule` via `intent_capsule_id`,
 * `intent_digest`, `prev_capsule_hash`, and `parent_capsule_hashes`.
 */
export function buildOutcomeCapsule(
  input: Omit<BuildCapsuleInput, 'phase'>,
  intentCapsule: Capsule,
): { capsule: Capsule; capsuleBytes: Buffer; disclosure: Disclosure } {
  const existingParents = input.parent_capsule_hashes ?? input.parentCapsuleHashes ?? [];
  const mergedParents = existingParents.includes(intentCapsule.capsule_id)
    ? existingParents
    : [intentCapsule.capsule_id, ...existingParents];

  const existingCausalityParents = input.causality?.parent_capsule_ids ?? [];
  const mergedCausalityParents = existingCausalityParents.includes(intentCapsule.capsule_id)
    ? existingCausalityParents
    : [intentCapsule.capsule_id, ...existingCausalityParents];

  const seq =
    input.sequence_number ??
    input.sequenceNumber ??
    (intentCapsule.sequence_number !== undefined ? intentCapsule.sequence_number + 1 : undefined);
  const sess = input.session_id ?? input.sessionId ?? intentCapsule.session_id;

  return buildCapsule({
    ...input,
    actionId: input.actionId ?? intentCapsule.action_id,
    phase: 'outcome',
    ...(seq !== undefined ? { sequence_number: seq } : {}),
    ...(sess !== undefined ? { session_id: sess } : {}),
    intent_capsule_id: input.intent_capsule_id ?? input.intentCapsuleId ?? intentCapsule.capsule_id,
    intent_digest: input.intent_digest ?? input.intentDigest ?? intentCapsule.request_digest,
    prev_capsule_hash: input.prev_capsule_hash ?? input.prevCapsuleHash ?? intentCapsule.capsule_id,
    parent_capsule_hashes: mergedParents,
    causality: {
      ...(intentCapsule.causality ?? {}),
      ...(input.causality ?? {}),
      parent_capsule_ids: mergedCausalityParents,
    },
  });
}

/**
 * Convenience builder for Phase 3 (`confirmation`) of the 3-phase action capsule lifecycle.
 * Binds an external outcome confirmation (`W0`..`W3`) and `evidenceDigest` to `outcomeCapsule`.
 */
export function buildConfirmationCapsule(
  input: Partial<Omit<BuildCapsuleInput, 'phase'>>,
  outcomeCapsule: Capsule,
  confirmationLevel: ConfirmationLevelTag,
  evidenceDigest: Digest,
): { capsule: Capsule; capsuleBytes: Buffer; disclosure: Disclosure } {
  const existingParents = input.parent_capsule_hashes ?? input.parentCapsuleHashes ?? [];
  const mergedParents = existingParents.includes(outcomeCapsule.capsule_id)
    ? existingParents
    : [outcomeCapsule.capsule_id, ...existingParents];

  const existingCausalityParents = input.causality?.parent_capsule_ids ?? [];
  const mergedCausalityParents = existingCausalityParents.includes(outcomeCapsule.capsule_id)
    ? existingCausalityParents
    : [outcomeCapsule.capsule_id, ...existingCausalityParents];

  const seq =
    input.sequence_number ??
    input.sequenceNumber ??
    (outcomeCapsule.sequence_number !== undefined ? outcomeCapsule.sequence_number + 1 : undefined);
  const sess = input.session_id ?? input.sessionId ?? outcomeCapsule.session_id;

  return buildCapsule({
    ...input,
    actionId: input.actionId ?? outcomeCapsule.action_id,
    phase: 'confirmation',
    ...(seq !== undefined ? { sequence_number: seq } : {}),
    ...(sess !== undefined ? { session_id: sess } : {}),
    intent_capsule_id:
      input.intent_capsule_id ??
      input.intentCapsuleId ??
      outcomeCapsule.intent_capsule_id ??
      outcomeCapsule.capsule_id,
    intent_digest:
      input.intent_digest ??
      input.intentDigest ??
      outcomeCapsule.intent_digest ??
      outcomeCapsule.request_digest,
    prev_capsule_hash: input.prev_capsule_hash ?? input.prevCapsuleHash ?? outcomeCapsule.capsule_id,
    parent_capsule_hashes: mergedParents,
    confirmation_level: confirmationLevel,
    evidence_digest: evidenceDigest,
    outcome_capsule_id: outcomeCapsule.capsule_id,
    agent: input.agent ?? outcomeCapsule.agent,
    principalSubject: input.principalSubject ?? outcomeCapsule.principal.subject_commitment,
    operation: input.operation ?? {
      kind: outcomeCapsule.operation.kind,
      method: outcomeCapsule.operation.method,
      risk_tier: outcomeCapsule.operation.risk_tier,
      ...(outcomeCapsule.operation.tool_schema_digest
        ? { tool_schema_digest: outcomeCapsule.operation.tool_schema_digest }
        : {}),
    },
    requestArgs: input.requestArgs ?? {
      outcome_capsule_id: outcomeCapsule.capsule_id,
      confirmation_level: confirmationLevel,
      evidence_digest: evidenceDigest,
    },
    verdict: input.verdict ?? 'executed',
    observedResponse: input.observedResponse ?? {
      confirmed: true,
      outcome_capsule_id: outcomeCapsule.capsule_id,
      confirmation_level: confirmationLevel,
      evidence_digest: evidenceDigest,
    },
    disposition: input.disposition ?? outcomeCapsule.disposition,
    causality: {
      ...(outcomeCapsule.causality ?? {}),
      ...(input.causality ?? {}),
      parent_capsule_ids: mergedCausalityParents,
    },
    extensions: {
      ...(input.extensions ?? {}),
      'io.hivemind.confirmation_level': confirmationLevel,
      'io.hivemind.evidence_digest': evidenceDigest,
      'io.hivemind.outcome_capsule_id': outcomeCapsule.capsule_id,
    },
  });
}

function finalizeCapsule(
  core: CapsuleCore,
  salt: Buffer,
  disclosedFields: Record<string, unknown>,
): { capsule: Capsule; capsuleBytes: Buffer; disclosure: Disclosure } {
  const errs = validateCapsuleCore(core);
  if (errs.length) throw new Error(`invalid capsule: ${errs.join('; ')}`);
  const capsuleId = digestOf(cborEncode(core as never));
  const capsule: Capsule = { ...core, capsule_id: capsuleId };
  return {
    capsule,
    capsuleBytes: cborEncode(capsule as never),
    disclosure: {
      capsule_id: capsuleId,
      salt: salt.toString('base64url'),
      fields: disclosedFields,
    },
  };
}

export function parseCapsule(bytes: Uint8Array): Capsule {
  const plain = cborToPlain(cborDecode(bytes)) as Capsule;
  const { capsule_id, ...core } = plain;
  void capsule_id;
  const recomputed = digestOf(cborEncode(core as never));
  if (recomputed !== plain.capsule_id)
    throw new Error('capsule_id does not match the canonical payload bytes');
  const errs = validateCapsuleCore(core as CapsuleCore);
  if (errs.length) throw new Error(`invalid capsule: ${errs.join('; ')}`);
  return plain;
}

export interface ParsedCapsuleEnvelope {
  capsule: Capsule;
  /** True when the profile version is one this verifier knows and fully checked. */
  profileKnown: boolean;
  profile: string;
}

/**
 * Parse any capsule-family payload. Known versions get full invariant
 * validation; unknown newer versions parse with profileKnown=false so
 * signature/inclusion can still be verified while the verifier reports the
 * capsule semantics as unchecked instead of rejecting history outright.
 */
export function parseCapsuleAnyVersion(bytes: Uint8Array): ParsedCapsuleEnvelope {
  const plain = cborToPlain(cborDecode(bytes)) as Capsule;
  const profile = String((plain as { profile?: unknown }).profile ?? '');
  if (isKnownCapsuleProfile(profile)) {
    return { capsule: parseCapsule(bytes), profileKnown: true, profile };
  }
  if (capsuleProfileVersion(profile) === null) {
    throw new Error(`not an agent-action capsule profile: ${profile || '(missing)'}`);
  }
  const { capsule_id, ...core } = plain as Capsule;
  void capsule_id;
  if (digestOf(cborEncode(core as never)) !== plain.capsule_id) {
    throw new Error('capsule_id does not match the canonical payload bytes');
  }
  return { capsule: plain, profileKnown: false, profile };
}

/** Check a disclosure against a capsule: salt digest + every field commitment. */
export function verifyDisclosure(
  capsule: Capsule,
  disclosure: Disclosure,
): { ok: boolean; checked: string[]; failed: string[] } {
  const salt = Buffer.from(disclosure.salt, 'base64url');
  const checked: string[] = [];
  const failed: string[] = [];
  if (disclosure.capsule_id !== capsule.capsule_id) failed.push('capsule_id');
  if (digestOf(salt) !== capsule.privacy.salt_commitment) failed.push('salt');
  const expect: Array<[string, Digest | undefined]> = [
    ['principal.subject', capsule.principal.subject_commitment],
    ['request', capsule.request_digest],
    ['response', capsule.effect?.response_digest],
    ['effect.summary', capsule.effect?.summary_commitment],
    ['operation.target', capsule.operation.target_commitment],
  ];
  for (const [field, commitment] of expect) {
    if (!(field in disclosure.fields)) continue;
    checked.push(field);
    if (!commitment || !verifyCommitment(commitment, salt, field, disclosure.fields[field]))
      failed.push(field);
  }
  return { ok: failed.length === 0, checked, failed };
}

/** Causal-graph root: Merkle root over capsule ids in canonical (sorted) order. */
export function causalGraphRoot(capsuleIds: Digest[]): Digest {
  const sorted = [...capsuleIds].sort();
  return digestOf(cborEncode(sorted as never));
}

export function capsuleJsonView(capsule: Capsule): string {
  return jcsStringify(capsule);
}

/**
 * Compute the RFC 8785 (JCS - JSON Canonicalization Scheme) + SHA-256 digest
 * (`JSON-DIGEST`) of a capsule core (excluding `capsule_id`, mirroring how
 * `capsule_id` is computed over the canonical CBOR of `CapsuleCore`).
 */
export function computeCapsuleJsonDigest(capsule: Capsule | CapsuleCore): Digest {
  const { capsule_id, ...core } = capsule as Capsule;
  void capsule_id;
  const canonicalJson = jcsStringify(core);
  return digestOf(Buffer.from(canonicalJson, 'utf8'));
}

export function verifyCapsuleJsonDigest(
  capsule: Capsule | CapsuleCore,
  expectedJsonDigest: Digest,
): boolean {
  const actual = computeCapsuleJsonDigest(capsule);
  const a = Buffer.from(actual, 'utf8');
  const b = Buffer.from(String(expectedJsonDigest), 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

export interface CapsuleDualDigests {
  capsuleCborDigest: Digest;
  capsuleJsonDigest: Digest;
}

export function computeCapsuleDualDigests(capsule: Capsule | CapsuleCore): CapsuleDualDigests {
  const { capsule_id, ...core } = capsule as Capsule;
  const cborDigest = capsule_id ?? digestOf(cborEncode(core as never));
  const jsonDigest = computeCapsuleJsonDigest(core);
  return {
    capsuleCborDigest: cborDigest,
    capsuleJsonDigest: jsonDigest,
  };
}

/**
 * Bidirectional mapping registry between `capsuleCborDigest` (deterministic
 * CBOR SHA-256 `capsule_id`) and `capsuleJsonDigest` (RFC 8785 JCS SHA-256
 * `JSON-DIGEST`).
 */
export class CapsuleDigestBiMap {
  private readonly cborToJson = new Map<Digest, Digest>();
  private readonly jsonToCbor = new Map<Digest, Digest>();

  register(capsule: Capsule | CapsuleCore): CapsuleDualDigests {
    const pair = computeCapsuleDualDigests(capsule);
    this.cborToJson.set(pair.capsuleCborDigest, pair.capsuleJsonDigest);
    this.jsonToCbor.set(pair.capsuleJsonDigest, pair.capsuleCborDigest);
    return pair;
  }

  toJsonDigest(cborDigest: Digest): Digest | undefined {
    return this.cborToJson.get(cborDigest);
  }

  toCborDigest(jsonDigest: Digest): Digest | undefined {
    return this.jsonToCbor.get(jsonDigest);
  }

  verifyPair(capsule: Capsule, pair: CapsuleDualDigests): boolean {
    const recomputed = computeCapsuleDualDigests(capsule);
    return (
      recomputed.capsuleCborDigest === pair.capsuleCborDigest &&
      recomputed.capsuleJsonDigest === pair.capsuleJsonDigest &&
      this.cborToJson.get(pair.capsuleCborDigest) === pair.capsuleJsonDigest &&
      this.jsonToCbor.get(pair.capsuleJsonDigest) === pair.capsuleCborDigest
    );
  }
}
