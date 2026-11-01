// SPDX-License-Identifier: Apache-2.0
/**
 * Configuration Epochs (`urn:hivemind:receipts:config-epoch:1`) and Portable
 * Agent Passports (`urn:hivemind:receipts:agent-passport:1`).
 *
 * A Configuration Epoch commits deterministically (CBOR + SHA-256) to the
 * complete behavioral posture of an agent at a point in time:
 * `{ system_prompt_digest, tool_manifest_digest, policy_digest, model_id, framework, metadata }`.
 * Any change to prompt, tools, policy, model, or framework produces a new
 * `epoch_digest`, allowing relying parties to pinpoint exact configuration
 * drift across receipts.
 *
 * An Agent Passport is a portable COSE_Sign1-signed credential binding the
 * agent's SPIFFE ID, issuer key & tier, optional TEE attestation summary,
 * federation bindings (SPIFFE/OIDC), configuration epoch history, and
 * observed completeness statistics (`total_receipts`, `completeness_ratio`,
 * `zero_gap_streak`, `confirmations_by_level`).
 */
import type { KeyObject } from 'node:crypto';
import { cborDecode, cborEncode, cborToPlain } from './cbor.js';
import { digestOf, isDigest, type Digest } from './capsule.js';
import { coseSign1, parseSign1, verifySign1 } from './cose.js';
import { decodeCoseKey, publicKeyFromCoseKey, type ReceiptSigner } from './keys.js';

export const CONFIG_EPOCH_PROFILE_URI = 'urn:hivemind:receipts:config-epoch:1';
export const CONFIG_EPOCH_MEDIA_TYPE = 'application/vnd.hivemind.config-epoch+cbor';

export const AGENT_PASSPORT_PROFILE_URI = 'urn:hivemind:receipts:agent-passport:1';
export const AGENT_PASSPORT_MEDIA_TYPE = 'application/vnd.hivemind.agent-passport+cbor';

export interface ConfigurationEpochInput {
  system_prompt_digest?: Digest;
  system_prompt?: string | Uint8Array;
  tool_manifest_digest?: Digest;
  tool_manifest?: unknown;
  policy_digest?: Digest;
  policy?: unknown;
  model_id: string;
  framework: string;
  metadata?: Record<string, unknown>;
  previous_epoch_digest?: Digest;
  created_at?: string;
}

export interface ConfigurationEpoch {
  profile: typeof CONFIG_EPOCH_PROFILE_URI;
  epoch_digest: Digest;
  system_prompt_digest: Digest;
  tool_manifest_digest: Digest;
  policy_digest: Digest;
  model_id: string;
  framework: string;
  metadata: Record<string, unknown>;
  previous_epoch_digest?: Digest;
  created_at?: string;
}

function resolveDigest(explicit: Digest | undefined, raw: unknown, fieldName: string): Digest {
  if (explicit !== undefined) {
    if (!isDigest(explicit)) {
      throw new Error(`${fieldName} must be sha256:<hex>`);
    }
    return explicit;
  }
  if (raw !== undefined) {
    if (typeof raw === 'string' || raw instanceof Uint8Array) {
      return digestOf(raw);
    }
    return digestOf(cborEncode(raw as never));
  }
  throw new Error(`either ${fieldName} or raw value is required`);
}

/**
 * Compute the deterministic CBOR/SHA-256 `epoch_digest` over
 * `{ system_prompt_digest, tool_manifest_digest, policy_digest, model_id, framework, metadata }`.
 */
export function computeEpochDigest(core: {
  system_prompt_digest: Digest;
  tool_manifest_digest: Digest;
  policy_digest: Digest;
  model_id: string;
  framework: string;
  metadata?: Record<string, unknown>;
}): Digest {
  const canonical = {
    system_prompt_digest: core.system_prompt_digest,
    tool_manifest_digest: core.tool_manifest_digest,
    policy_digest: core.policy_digest,
    model_id: core.model_id,
    framework: core.framework,
    metadata: core.metadata ?? {},
  };
  return digestOf(cborEncode(canonical as never));
}

export function buildConfigurationEpoch(input: ConfigurationEpochInput): ConfigurationEpoch {
  const system_prompt_digest = resolveDigest(
    input.system_prompt_digest,
    input.system_prompt,
    'system_prompt_digest',
  );
  const tool_manifest_digest = resolveDigest(
    input.tool_manifest_digest,
    input.tool_manifest,
    'tool_manifest_digest',
  );
  const policy_digest = resolveDigest(input.policy_digest, input.policy, 'policy_digest');
  if (!input.model_id || typeof input.model_id !== 'string') {
    throw new Error('model_id is required');
  }
  if (!input.framework || typeof input.framework !== 'string') {
    throw new Error('framework is required');
  }
  if (
    input.previous_epoch_digest !== undefined &&
    !isDigest(input.previous_epoch_digest)
  ) {
    throw new Error('previous_epoch_digest must be sha256:<hex>');
  }

  const metadata = input.metadata ? structuredClone(input.metadata) : {};
  const epoch_digest = computeEpochDigest({
    system_prompt_digest,
    tool_manifest_digest,
    policy_digest,
    model_id: input.model_id,
    framework: input.framework,
    metadata,
  });

  return {
    profile: CONFIG_EPOCH_PROFILE_URI,
    epoch_digest,
    system_prompt_digest,
    tool_manifest_digest,
    policy_digest,
    model_id: input.model_id,
    framework: input.framework,
    metadata,
    ...(input.previous_epoch_digest ? { previous_epoch_digest: input.previous_epoch_digest } : {}),
    ...(input.created_at ? { created_at: input.created_at } : {}),
  };
}

export const createConfigurationEpoch = buildConfigurationEpoch;
export const computeConfigurationEpoch = buildConfigurationEpoch;

export type EpochChangedField =
  | 'system_prompt_digest'
  | 'tool_manifest_digest'
  | 'policy_digest'
  | 'model_id'
  | 'framework'
  | 'metadata';

export interface ConfigurationEpochDiff {
  identical: boolean;
  epoch_digest_changed: boolean;
  prompt_changed: boolean;
  tools_changed: boolean;
  policy_changed: boolean;
  model_changed: boolean;
  framework_changed: boolean;
  metadata_changed: boolean;
  changed_fields: EpochChangedField[];
}

/**
 * Compare two ConfigurationEpochs and report the exact fields that changed.
 */
export function diffConfigurationEpochs(
  a: ConfigurationEpoch,
  b: ConfigurationEpoch,
): ConfigurationEpochDiff {
  const prompt_changed = a.system_prompt_digest !== b.system_prompt_digest;
  const tools_changed = a.tool_manifest_digest !== b.tool_manifest_digest;
  const policy_changed = a.policy_digest !== b.policy_digest;
  const model_changed = a.model_id !== b.model_id;
  const framework_changed = a.framework !== b.framework;
  const metaA = cborEncode((a.metadata ?? {}) as never);
  const metaB = cborEncode((b.metadata ?? {}) as never);
  const metadata_changed = !metaA.equals(metaB);

  const changed_fields: EpochChangedField[] = [];
  if (prompt_changed) changed_fields.push('system_prompt_digest');
  if (tools_changed) changed_fields.push('tool_manifest_digest');
  if (policy_changed) changed_fields.push('policy_digest');
  if (model_changed) changed_fields.push('model_id');
  if (framework_changed) changed_fields.push('framework');
  if (metadata_changed) changed_fields.push('metadata');

  const epoch_digest_changed = a.epoch_digest !== b.epoch_digest;
  const identical = !epoch_digest_changed && changed_fields.length === 0;

  return {
    identical,
    epoch_digest_changed,
    prompt_changed,
    tools_changed,
    policy_changed,
    model_changed,
    framework_changed,
    metadata_changed,
    changed_fields,
  };
}

const UNPROTECTED_EMBEDDED_KEY_LABEL = -26001;

function resolveVerifyKey(
  expectedKey: KeyObject | ReceiptSigner | Uint8Array | undefined,
  unprotected?: Map<unknown, unknown>,
): KeyObject | null {
  if (!expectedKey) {
    const rawKey = unprotected?.get(UNPROTECTED_EMBEDDED_KEY_LABEL);
    if (rawKey instanceof Uint8Array) {
      return publicKeyFromCoseKey(decodeCoseKey(rawKey)).key;
    }
    return null;
  }
  if ('publicKeyObject' in expectedKey && typeof expectedKey.publicKeyObject === 'function') {
    return expectedKey.publicKeyObject();
  }
  if (expectedKey instanceof Uint8Array) {
    return publicKeyFromCoseKey(decodeCoseKey(expectedKey)).key;
  }
  return expectedKey as KeyObject;
}

export type SignedEpochStatement = Buffer & {
  statement: Buffer;
  statementBytes: Buffer;
  epoch: ConfigurationEpoch;
};

/**
 * Sign a ConfigurationEpoch as a SCITT COSE_Sign1 statement with content-type
 * `'application/vnd.hivemind.config-epoch+cbor'` (`urn:hivemind:receipts:config-epoch:1`).
 */
export async function signConfigEpochStatement(
  signer: ReceiptSigner,
  epochOrInput: ConfigurationEpoch | ConfigurationEpochInput,
  opts: { iss?: string; iat?: number } = {},
): Promise<SignedEpochStatement> {
  const epoch: ConfigurationEpoch =
    'epoch_digest' in epochOrInput && 'profile' in epochOrInput
      ? epochOrInput
      : buildConfigurationEpoch(epochOrInput);
  const payload = cborEncode(epoch as never);
  const coseKeyBytes = cborEncode(signer.publicCoseKey());
  const stmt = await coseSign1(signer, payload, {
    contentType: CONFIG_EPOCH_MEDIA_TYPE,
    cwt: {
      iss: opts.iss ?? signer.kid,
      sub: epoch.epoch_digest,
      iat: opts.iat ?? Math.floor(Date.now() / 1000),
    },
    extraUnprotected: new Map<number, unknown>([[UNPROTECTED_EMBEDDED_KEY_LABEL, coseKeyBytes]]),
  });
  return Object.assign(stmt, {
    statement: stmt,
    statementBytes: stmt,
    epoch,
  });
}

export interface VerifyConfigEpochResult {
  valid: boolean;
  ok: boolean;
  epoch: ConfigurationEpoch | null;
  kid: string;
  alg: number;
  content_type: string;
  error?: string;
}

export function verifyConfigEpochStatement(
  statementInput:
    | Uint8Array
    | { statement?: Uint8Array; statementBytes?: Uint8Array },
  expectedKey?: KeyObject | ReceiptSigner | Uint8Array,
): VerifyConfigEpochResult {
  const bytes =
    statementInput instanceof Uint8Array
      ? Buffer.from(statementInput)
      : Buffer.from(statementInput.statementBytes ?? statementInput.statement ?? []);
  try {
    const parsed = parseSign1(bytes);
    const ct = String(parsed.protectedHeader.get(3) ?? '');
    if (ct !== CONFIG_EPOCH_MEDIA_TYPE) {
      return {
        valid: false,
        ok: false,
        epoch: null,
        kid: parsed.kid,
        alg: parsed.alg,
        content_type: ct,
        error: `unexpected content-type ${ct}`,
      };
    }
    if (!parsed.payload) {
      return {
        valid: false,
        ok: false,
        epoch: null,
        kid: parsed.kid,
        alg: parsed.alg,
        content_type: ct,
        error: 'missing payload',
      };
    }
    const plain = cborToPlain(cborDecode(parsed.payload)) as ConfigurationEpoch;
    if (plain.profile !== CONFIG_EPOCH_PROFILE_URI) {
      return {
        valid: false,
        ok: false,
        epoch: null,
        kid: parsed.kid,
        alg: parsed.alg,
        content_type: ct,
        error: `unexpected profile ${String(plain.profile)}`,
      };
    }
    const recomputed = computeEpochDigest({
      system_prompt_digest: plain.system_prompt_digest,
      tool_manifest_digest: plain.tool_manifest_digest,
      policy_digest: plain.policy_digest,
      model_id: plain.model_id,
      framework: plain.framework,
      metadata: plain.metadata ?? {},
    });
    if (recomputed !== plain.epoch_digest) {
      return {
        valid: false,
        ok: false,
        epoch: null,
        kid: parsed.kid,
        alg: parsed.alg,
        content_type: ct,
        error: 'epoch_digest mismatch',
      };
    }
    const keyObj = resolveVerifyKey(expectedKey, parsed.unprotected);
    if (!keyObj || !verifySign1(parsed, keyObj)) {
      return {
        valid: false,
        ok: false,
        epoch: null,
        kid: parsed.kid,
        alg: parsed.alg,
        content_type: ct,
        error: 'COSE signature verification failed',
      };
    }
    return {
      valid: true,
      ok: true,
      epoch: plain,
      kid: parsed.kid,
      alg: parsed.alg,
      content_type: ct,
    };
  } catch (e) {
    return {
      valid: false,
      ok: false,
      epoch: null,
      kid: '',
      alg: 0,
      content_type: '',
      error: (e as Error).message,
    };
  }
}

// --- Portable Agent Passport ------------------------------------------------

export type PassportConfirmationCounts = Record<'W0' | 'W1' | 'W2' | 'W3', number>;

export interface AgentPassportStats {
  total_receipts: number;
  completeness_ratio: number;
  zero_gap_streak: number;
  confirmations_by_level: PassportConfirmationCounts;
}

export interface TeeAttestationSummary {
  mode: 'none' | 'nitro' | 'sev-snp' | 'tdx' | 'gpu';
  measurement_digest?: Digest;
  attested_at?: string;
  provider?: string;
}

export interface AgentFederationBinding {
  spiffe_trust_domain?: string;
  oidc_issuer?: string;
  oidc_subject?: string;
  vlei?: string;
  did?: string;
}

export interface AgentPassportInput {
  spiffe_id: string;
  issuer_kid?: string;
  tier: 'T0' | 'T1' | 'T2' | 'T3';
  tee_attestation_summary?: TeeAttestationSummary;
  federation?: AgentFederationBinding;
  epochs: ConfigurationEpoch[];
  stats: AgentPassportStats;
  issued_at?: string;
}

export interface AgentPassport {
  profile: typeof AGENT_PASSPORT_PROFILE_URI;
  passport_id: Digest;
  spiffe_id: string;
  issuer_kid: string;
  tier: 'T0' | 'T1' | 'T2' | 'T3';
  tee_attestation_summary?: TeeAttestationSummary;
  federation?: AgentFederationBinding;
  epochs: ConfigurationEpoch[];
  stats: AgentPassportStats;
  issued_at: string;
}

interface WireAgentPassportCore {
  profile: typeof AGENT_PASSPORT_PROFILE_URI;
  spiffe_id: string;
  issuer_kid: string;
  tier: 'T0' | 'T1' | 'T2' | 'T3';
  tee_attestation_summary?: TeeAttestationSummary;
  federation?: AgentFederationBinding;
  epochs: ConfigurationEpoch[];
  stats: {
    total_receipts: number;
    completeness_ratio_bps: number;
    completeness_ratio_str: string;
    zero_gap_streak: number;
    confirmations_by_level: PassportConfirmationCounts;
  };
  issued_at: string;
}

interface WireAgentPassport extends WireAgentPassportCore {
  passport_id: Digest;
}

function toWirePassportCore(
  input: AgentPassportInput,
  issuerKid: string,
  issuedAt: string,
): WireAgentPassportCore {
  return {
    profile: AGENT_PASSPORT_PROFILE_URI,
    spiffe_id: input.spiffe_id,
    issuer_kid: issuerKid,
    tier: input.tier,
    ...(input.tee_attestation_summary
      ? { tee_attestation_summary: input.tee_attestation_summary }
      : {}),
    ...(input.federation ? { federation: input.federation } : {}),
    epochs: input.epochs,
    stats: {
      total_receipts: Math.trunc(input.stats.total_receipts),
      completeness_ratio_bps: Math.round(input.stats.completeness_ratio * 10000),
      completeness_ratio_str: String(input.stats.completeness_ratio),
      zero_gap_streak: Math.trunc(input.stats.zero_gap_streak),
      confirmations_by_level: {
        W0: Math.trunc(input.stats.confirmations_by_level.W0 ?? 0),
        W1: Math.trunc(input.stats.confirmations_by_level.W1 ?? 0),
        W2: Math.trunc(input.stats.confirmations_by_level.W2 ?? 0),
        W3: Math.trunc(input.stats.confirmations_by_level.W3 ?? 0),
      },
    },
    issued_at: issuedAt,
  };
}

export type SignedAgentPassportBundle = Buffer & {
  passport: AgentPassport;
  statement: Buffer;
  statementBytes: Buffer;
  coseKeyBytes: Buffer;
};

/**
 * Export and sign a portable AgentPassport as a COSE_Sign1 statement.
 * Returns a Buffer that also exposes `{ passport, statement, statementBytes, coseKeyBytes }`.
 */
export async function exportAgentPassport(
  signer: ReceiptSigner,
  input: AgentPassportInput,
): Promise<SignedAgentPassportBundle> {
  if (!input.spiffe_id || typeof input.spiffe_id !== 'string') {
    throw new Error('spiffe_id is required');
  }
  const issuerKid = input.issuer_kid ?? signer.kid;
  const issuedAt = input.issued_at ?? new Date().toISOString();
  const wireCore = toWirePassportCore(input, issuerKid, issuedAt);
  const passportId = digestOf(cborEncode(wireCore as never));
  const wirePassport: WireAgentPassport = {
    ...wireCore,
    passport_id: passportId,
  };
  const payload = cborEncode(wirePassport as never);
  const coseKeyBytes = cborEncode(signer.publicCoseKey());
  const stmt = await coseSign1(signer, payload, {
    contentType: AGENT_PASSPORT_MEDIA_TYPE,
    cwt: {
      iss: issuerKid,
      sub: input.spiffe_id,
      iat: Math.floor(Date.parse(issuedAt) / 1000) || Math.floor(Date.now() / 1000),
    },
    extraUnprotected: new Map<number, unknown>([[UNPROTECTED_EMBEDDED_KEY_LABEL, coseKeyBytes]]),
  });

  const passport: AgentPassport = {
    profile: AGENT_PASSPORT_PROFILE_URI,
    passport_id: passportId,
    spiffe_id: input.spiffe_id,
    issuer_kid: issuerKid,
    tier: input.tier,
    ...(input.tee_attestation_summary
      ? { tee_attestation_summary: input.tee_attestation_summary }
      : {}),
    ...(input.federation ? { federation: input.federation } : {}),
    epochs: input.epochs,
    stats: {
      total_receipts: wireCore.stats.total_receipts,
      completeness_ratio: Number(wireCore.stats.completeness_ratio_str),
      zero_gap_streak: wireCore.stats.zero_gap_streak,
      confirmations_by_level: wireCore.stats.confirmations_by_level,
    },
    issued_at: issuedAt,
  };

  return Object.assign(stmt, {
    passport,
    statement: stmt,
    statementBytes: stmt,
    coseKeyBytes,
  });
}

export interface VerifyAgentPassportResult {
  valid: boolean;
  ok: boolean;
  passport: AgentPassport | null;
  kid: string;
  alg: number;
  error?: string;
}

/**
 * Verify a signed AgentPassport statement (checks COSE signature, passport_id digest,
 * and every embedded ConfigurationEpoch digest).
 */
export function verifyAgentPassport(
  passportOrBytes:
    | Uint8Array
    | { statement?: Uint8Array; statementBytes?: Uint8Array; passport?: AgentPassport },
  expectedKey?: KeyObject | ReceiptSigner | Uint8Array,
): VerifyAgentPassportResult {
  const bytes =
    passportOrBytes instanceof Uint8Array
      ? Buffer.from(passportOrBytes)
      : Buffer.from(passportOrBytes.statementBytes ?? passportOrBytes.statement ?? []);
  try {
    const parsed = parseSign1(bytes);
    const ct = String(parsed.protectedHeader.get(3) ?? '');
    if (ct !== AGENT_PASSPORT_MEDIA_TYPE) {
      return {
        valid: false,
        ok: false,
        passport: null,
        kid: parsed.kid,
        alg: parsed.alg,
        error: `unexpected content-type ${ct}`,
      };
    }
    if (!parsed.payload) {
      return {
        valid: false,
        ok: false,
        passport: null,
        kid: parsed.kid,
        alg: parsed.alg,
        error: 'missing payload',
      };
    }
    const wire = cborToPlain(cborDecode(parsed.payload)) as WireAgentPassport;
    if (wire.profile !== AGENT_PASSPORT_PROFILE_URI) {
      return {
        valid: false,
        ok: false,
        passport: null,
        kid: parsed.kid,
        alg: parsed.alg,
        error: `unexpected profile ${String(wire.profile)}`,
      };
    }
    const { passport_id, ...wireCore } = wire;
    const recomputedId = digestOf(cborEncode(wireCore as never));
    if (recomputedId !== passport_id) {
      return {
        valid: false,
        ok: false,
        passport: null,
        kid: parsed.kid,
        alg: parsed.alg,
        error: 'passport_id does not match canonical payload',
      };
    }
    for (const epoch of wire.epochs ?? []) {
      const expectedEpochDigest = computeEpochDigest({
        system_prompt_digest: epoch.system_prompt_digest,
        tool_manifest_digest: epoch.tool_manifest_digest,
        policy_digest: epoch.policy_digest,
        model_id: epoch.model_id,
        framework: epoch.framework,
        metadata: epoch.metadata ?? {},
      });
      if (expectedEpochDigest !== epoch.epoch_digest) {
        return {
          valid: false,
          ok: false,
          passport: null,
          kid: parsed.kid,
          alg: parsed.alg,
          error: `embedded epoch ${epoch.epoch_digest} failed digest verification`,
        };
      }
    }
    const keyObj = resolveVerifyKey(expectedKey, parsed.unprotected);
    if (!keyObj || !verifySign1(parsed, keyObj)) {
      return {
        valid: false,
        ok: false,
        passport: null,
        kid: parsed.kid,
        alg: parsed.alg,
        error: 'COSE signature verification failed',
      };
    }
    const passport: AgentPassport = {
      profile: AGENT_PASSPORT_PROFILE_URI,
      passport_id: wire.passport_id,
      spiffe_id: wire.spiffe_id,
      issuer_kid: wire.issuer_kid,
      tier: wire.tier,
      ...(wire.tee_attestation_summary
        ? { tee_attestation_summary: wire.tee_attestation_summary }
        : {}),
      ...(wire.federation ? { federation: wire.federation } : {}),
      epochs: wire.epochs,
      stats: {
        total_receipts: wire.stats.total_receipts,
        completeness_ratio: Number(wire.stats.completeness_ratio_str),
        zero_gap_streak: wire.stats.zero_gap_streak,
        confirmations_by_level: wire.stats.confirmations_by_level,
      },
      issued_at: wire.issued_at,
    };
    return {
      valid: true,
      ok: true,
      passport,
      kid: parsed.kid,
      alg: parsed.alg,
    };
  } catch (e) {
    return {
      valid: false,
      ok: false,
      passport: null,
      kid: '',
      alg: 0,
      error: (e as Error).message,
    };
  }
}
