// SPDX-License-Identifier: Apache-2.0
/**
 * Universal Cross-Profile SCITT Verifier (`verifyUniversalStatement`).
 *
 * Verifies Transparent Statements from any SCITT Transparency Service (RFC 9943)
 * and normalizes claims across 4 profile families:
 *  1. Hivemind Agent Action Capsule (`urn:hivemind:receipts:capsule:1`,
 *     `application/vnd.hivemind.agent-action-capsule+cbor`)
 *  2. IETF `draft-mih-scitt-agent-action-capsule`
 *     (`application/vnd.scitt.agent-action-capsule+cbor`)
 *  3. Emirdag AIR — Agent Interaction Record (`urn:ietf:params:scitt:air:1`,
 *     `application/vnd.scitt.air+cbor`)
 *  4. Generic RFC 9943 `COSE_Sign1` with RFC 9162 inclusion receipts (header label `394`).
 */
import { randomBytes, type KeyObject } from 'node:crypto';
import { cborDecode, cborEncode, cborToPlain } from './cbor.js';
import {
  CAPSULE_MEDIA_TYPE,
  CAPSULE_PROFILE_URI,
  digestOf,
  isDigest,
  parseCapsule,
  verifyDisclosure,
  type Capsule,
  type Digest,
  type Disclosure,
} from './capsule.js';
import {
  attachReceipts,
  coseSign1,
  extractReceipts,
  issueReceipt,
  parseReceipt,
  parseSign1,
  statementLeafBytes,
  verifyReceipt,
  verifySign1,
  type CwtClaims,
} from './cose.js';
import { parseCheckpoint } from './checkpoint.js';
import { inclusionProof, leafHash, mth, verifyInclusion } from './merkle.js';
import {
  decodeCoseKey,
  publicKeyFromCoseKey,
  sha256,
  ulid,
  type CoseAlg,
  type ReceiptSigner,
} from './keys.js';
import {
  computeVerificationRunId,
  isValidVerificationRunId,
  type CheckResult,
  type TrustRoots,
} from './verify.js';

export const MIH_CAPSULE_PROFILE_URI = 'draft-mih-scitt-agent-action-capsule';
export const MIH_CAPSULE_URN = 'urn:ietf:params:scitt:agent-action-capsule:1';
export const MIH_CAPSULE_MEDIA_TYPE = 'application/vnd.scitt.agent-action-capsule+cbor';

export const EMIRDAG_AIR_PROFILE_URI = 'urn:ietf:params:scitt:air:1';
export const EMIRDAG_AIR_MEDIA_TYPE = 'application/vnd.scitt.air+cbor';

export type UniversalProfileFamily =
  | 'hivemind'
  | 'draft-mih'
  | 'emirdag-air'
  | 'generic-scitt';

export interface MihCapsuleInput {
  profile?: string;
  action_id?: string;
  actionId?: string;
  agent_id?: string;
  agentId?: string;
  session_id?: string;
  sessionId?: string;
  tool_name?: string;
  toolName?: string;
  method?: string;
  input_hash?: Digest;
  inputHash?: Digest;
  request_digest?: Digest;
  requestArgs?: unknown;
  output_hash?: Digest;
  outputHash?: Digest;
  response_digest?: Digest;
  observedResponse?: unknown;
  decision?: string;
  verdict?: string;
  policy_hash?: Digest;
  policyHash?: Digest;
  sequence_number?: number;
  sequenceNumber?: number;
  timestamp?: string;
  issued_at?: string;
}

export interface MihCapsulePayload {
  profile: string;
  capsule_id: Digest;
  action_id: string;
  agent_id: string;
  session_id: string;
  tool_name: string;
  input_hash: Digest;
  output_hash: Digest;
  decision: string;
  policy_hash?: Digest;
  sequence_number?: number;
  timestamp: string;
}

export type SignedForeignStatement<P> = Buffer & {
  statement: Buffer;
  statementBytes: Buffer;
  payload: P;
  payloadBytes: Buffer;
  checkpointRoot?: Buffer;
};

/**
 * Helper builder for `draft-mih-scitt-agent-action-capsule` statements
 * (`application/vnd.scitt.agent-action-capsule+cbor`).
 */
export async function buildMihCapsuleStatement(
  signer: ReceiptSigner,
  input: MihCapsuleInput,
  opts: {
    iss?: string;
    iat?: number;
    logSigner?: ReceiptSigner;
    priorLeaves?: Buffer[];
  } = {},
): Promise<SignedForeignStatement<MihCapsulePayload>> {
  const action_id = input.action_id ?? input.actionId ?? ulid(Date.now(), (n) => randomBytes(n));
  const agent_id = input.agent_id ?? input.agentId ?? 'spiffe://foreign.example/agent/mih';
  const session_id = input.session_id ?? input.sessionId ?? 'session-mih-1';
  const tool_name = input.tool_name ?? input.toolName ?? input.method ?? 'mcp.tool.call';
  const input_hash =
    input.input_hash ??
    input.inputHash ??
    input.request_digest ??
    digestOf(cborEncode((input.requestArgs ?? {}) as never));
  const output_hash =
    input.output_hash ??
    input.outputHash ??
    input.response_digest ??
    digestOf(cborEncode((input.observedResponse ?? {}) as never));
  const decision = input.decision ?? input.verdict ?? 'allow';
  const policy_hash = input.policy_hash ?? input.policyHash;
  const sequence_number = input.sequence_number ?? input.sequenceNumber;
  const timestamp = input.timestamp ?? input.issued_at ?? new Date().toISOString();
  const profile = input.profile ?? MIH_CAPSULE_PROFILE_URI;

  const core = {
    profile,
    action_id,
    agent_id,
    session_id,
    tool_name,
    input_hash,
    output_hash,
    decision,
    ...(policy_hash ? { policy_hash } : {}),
    ...(sequence_number !== undefined ? { sequence_number } : {}),
    timestamp,
  };
  const capsule_id = digestOf(cborEncode(core as never));
  const payload: MihCapsulePayload = { ...core, capsule_id };
  const payloadBytes = cborEncode(payload as never);

  let stmt = await coseSign1(signer, payloadBytes, {
    contentType: MIH_CAPSULE_MEDIA_TYPE,
    cwt: {
      iss: opts.iss ?? signer.kid,
      sub: action_id,
      iat: opts.iat ?? Math.floor(Date.now() / 1000),
    },
  });

  let checkpointRoot: Buffer | undefined;
  if (opts.logSigner) {
    const prior = opts.priorLeaves ?? [];
    const leaves = [...prior, leafHash(stmt)];
    const leafIdx = leaves.length - 1;
    checkpointRoot = mth(leaves);
    const receipt = await issueReceipt(
      opts.logSigner,
      stmt,
      inclusionProof(leafIdx, leaves),
      checkpointRoot,
    );
    stmt = attachReceipts(stmt, [receipt]);
  }

  return Object.assign(stmt, {
    statement: stmt,
    statementBytes: stmt,
    payload,
    payloadBytes,
    ...(checkpointRoot ? { checkpointRoot } : {}),
  });
}

export interface EmirdagAirInput {
  profile?: string;
  record_id?: string;
  recordId?: string;
  action_id?: string;
  actor?: string;
  agent_id?: string;
  agentId?: string;
  interaction_type?: string;
  interactionType?: string;
  tool_name?: string;
  method?: string;
  request_hash?: Digest;
  requestHash?: Digest;
  input_hash?: Digest;
  requestArgs?: unknown;
  response_hash?: Digest;
  responseHash?: Digest;
  output_hash?: Digest;
  observedResponse?: unknown;
  outcome?: string;
  verdict?: string;
  decision?: string;
  context_hash?: Digest;
  contextHash?: Digest;
  recorded_at?: string;
  timestamp?: string;
}

export interface EmirdagAirPayload {
  profile: string;
  record_id: string;
  actor: string;
  interaction_type: string;
  request_hash: Digest;
  response_hash: Digest;
  outcome: string;
  context_hash?: Digest;
  recorded_at: string;
}

/**
 * Helper builder for Emirdag AIR (`urn:ietf:params:scitt:air:1`,
 * `application/vnd.scitt.air+cbor`).
 */
export async function buildEmirdagAirStatement(
  signer: ReceiptSigner,
  input: EmirdagAirInput,
  opts: {
    iss?: string;
    iat?: number;
    logSigner?: ReceiptSigner;
    priorLeaves?: Buffer[];
  } = {},
): Promise<SignedForeignStatement<EmirdagAirPayload>> {
  const record_id =
    input.record_id ??
    input.recordId ??
    input.action_id ??
    ulid(Date.now(), (n) => randomBytes(n));
  const actor = input.actor ?? input.agent_id ?? input.agentId ?? 'spiffe://foreign.example/agent/air';
  const interaction_type =
    input.interaction_type ??
    input.interactionType ??
    input.tool_name ??
    input.method ??
    'tool_invocation';
  const request_hash =
    input.request_hash ??
    input.requestHash ??
    input.input_hash ??
    digestOf(cborEncode((input.requestArgs ?? {}) as never));
  const response_hash =
    input.response_hash ??
    input.responseHash ??
    input.output_hash ??
    digestOf(cborEncode((input.observedResponse ?? {}) as never));
  const outcome = input.outcome ?? input.verdict ?? input.decision ?? 'completed';
  const context_hash = input.context_hash ?? input.contextHash;
  const recorded_at = input.recorded_at ?? input.timestamp ?? new Date().toISOString();
  const profile = input.profile ?? EMIRDAG_AIR_PROFILE_URI;

  const payload: EmirdagAirPayload = {
    profile,
    record_id,
    actor,
    interaction_type,
    request_hash,
    response_hash,
    outcome,
    ...(context_hash ? { context_hash } : {}),
    recorded_at,
  };
  const payloadBytes = cborEncode(payload as never);

  let stmt = await coseSign1(signer, payloadBytes, {
    contentType: EMIRDAG_AIR_MEDIA_TYPE,
    cwt: {
      iss: opts.iss ?? signer.kid,
      sub: record_id,
      iat: opts.iat ?? Math.floor(Date.now() / 1000),
    },
  });

  let checkpointRoot: Buffer | undefined;
  if (opts.logSigner) {
    const prior = opts.priorLeaves ?? [];
    const leaves = [...prior, leafHash(stmt)];
    const leafIdx = leaves.length - 1;
    checkpointRoot = mth(leaves);
    const receipt = await issueReceipt(
      opts.logSigner,
      stmt,
      inclusionProof(leafIdx, leaves),
      checkpointRoot,
    );
    stmt = attachReceipts(stmt, [receipt]);
  }

  return Object.assign(stmt, {
    statement: stmt,
    statementBytes: stmt,
    payload,
    payloadBytes,
    ...(checkpointRoot ? { checkpointRoot } : {}),
  });
}

type KeyLike =
  | KeyObject
  | ReceiptSigner
  | Uint8Array
  | { key: KeyObject; alg?: CoseAlg };

function toKeyObject(k: KeyLike | undefined): KeyObject | null {
  if (!k) return null;
  if ('publicKeyObject' in k && typeof k.publicKeyObject === 'function') {
    return k.publicKeyObject();
  }
  if ('key' in k && k.key) {
    return k.key;
  }
  if (k instanceof Uint8Array) {
    return publicKeyFromCoseKey(decodeCoseKey(k)).key;
  }
  return k as KeyObject;
}

function recomputeRootFromReceipt(
  leaf: Buffer,
  proof: { treeSize: number; leafIndex: number; hashes: Buffer[] },
): Buffer {
  let fn = proof.leafIndex;
  let sn = proof.treeSize - 1;
  let r = leaf;
  for (const p of proof.hashes) {
    if (fn % 2 === 1 || fn === sn) {
      r = sha256(Buffer.concat([Buffer.from([1]), p, r]));
      while (fn % 2 === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      r = sha256(Buffer.concat([Buffer.from([1]), r, p]));
    }
    fn >>= 1;
    sn >>= 1;
  }
  return r;
}

export interface UniversalVerifyOptions {
  issuerKey?: KeyLike;
  issuers?: Map<string, KeyLike>;
  logKey?: KeyLike;
  logKeys?: Map<string, KeyLike>;
  checkpointRoot?: Buffer;
  checkpoint?: string;
  detachedPayload?: Buffer;
  disclosure?: Disclosure;
  trustRoots?: TrustRoots;
  requireReceipt?: boolean;
}

export interface UniversalVerifyReport {
  valid: boolean;
  verdict: 'VERIFIED' | 'FAILED';
  verification_run_id: string;
  verificationRunId: string;
  profile: UniversalProfileFamily;
  profile_family: UniversalProfileFamily;
  content_type: string;
  profile_uri: string | null;
  kid: string;
  alg: number;
  cwt: CwtClaims | null;
  signature_valid: boolean;
  payload_valid: boolean;
  inclusion_verified: boolean;
  receipt_valid: boolean;
  receipt_count: number;
  leaf_index: number | null;
  tree_size: number | null;
  capsule: Capsule | null;
  payload: Record<string, unknown> | null;
  normalized: {
    subject_id: string | null;
    agent_id: string | null;
    action_or_tool: string | null;
    verdict_or_outcome: string | null;
    request_digest: string | null;
    response_digest: string | null;
  };
  checks: CheckResult[];
  errors: string[];
}

/**
 * Verify a SCITT Signed or Transparent Statement across Hivemind, IETF draft-mih,
 * Emirdag AIR, and generic RFC 9943 COSE_Sign1 profiles.
 */
export function verifyUniversalStatement(
  statementInput:
    | Buffer
    | Uint8Array
    | { statement?: Uint8Array; statementBytes?: Uint8Array },
  opts: UniversalVerifyOptions = {},
): UniversalVerifyReport {
  const statementBytes =
    statementInput instanceof Uint8Array
      ? Buffer.from(statementInput)
      : Buffer.from(statementInput.statementBytes ?? statementInput.statement ?? []);

  const checks: CheckResult[] = [];
  const errors: string[] = [];
  const addCheck = (name: string, ok: boolean, passMsg: string, failMsg: string) => {
    checks.push({ check: name, status: ok ? 'pass' : 'fail', detail: ok ? passMsg : failMsg });
    if (!ok) errors.push(`${name}: ${failMsg}`);
  };

  let parsed;
  try {
    parsed = parseSign1(statementBytes);
    addCheck('cose_envelope', true, 'COSE_Sign1 envelope decoded', '');
  } catch (e) {
    const msg = (e as Error).message;
    addCheck('cose_envelope', false, '', msg);
    const failRunId = computeVerificationRunId(
      `universal:parse_error:${sha256(statementBytes).toString('hex')}:${msg}`,
    );
    return {
      valid: false,
      verdict: 'FAILED',
      verification_run_id: failRunId,
      verificationRunId: failRunId,
      profile: 'generic-scitt',
      profile_family: 'generic-scitt',
      content_type: '',
      profile_uri: null,
      kid: '',
      alg: 0,
      cwt: null,
      signature_valid: false,
      payload_valid: false,
      inclusion_verified: false,
      receipt_valid: false,
      receipt_count: 0,
      leaf_index: null,
      tree_size: null,
      capsule: null,
      payload: null,
      normalized: {
        subject_id: null,
        agent_id: null,
        action_or_tool: null,
        verdict_or_outcome: null,
        request_digest: null,
        response_digest: null,
      },
      checks,
      errors,
    };
  }

  const contentType = String(parsed.protectedHeader.get(3) ?? '');
  const issuerCandidate =
    opts.issuerKey ??
    opts.issuers?.get(parsed.kid) ??
    opts.trustRoots?.issuers.get(parsed.kid);
  const issuerKeyObj = toKeyObject(issuerCandidate);

  let signature_valid = false;
  if (!issuerKeyObj) {
    addCheck('signature', false, '', `no issuer public key resolved for kid ${parsed.kid}`);
  } else {
    signature_valid = verifySign1(
      parsed,
      issuerKeyObj,
      opts.detachedPayload ? { detachedPayload: opts.detachedPayload } : {},
    );
    addCheck(
      'signature',
      signature_valid,
      `COSE_Sign1 signature verified with kid ${parsed.kid}`,
      'COSE_Sign1 signature verification failed',
    );
  }

  const rawPayload = parsed.payload ?? opts.detachedPayload ?? null;
  let decodedPlain: Record<string, unknown> | null = null;
  if (rawPayload) {
    try {
      const dec = cborDecode(rawPayload);
      const plain = cborToPlain(dec);
      if (plain && typeof plain === 'object' && !Array.isArray(plain)) {
        decodedPlain = plain as Record<string, unknown>;
      }
    } catch {
      // Non-CBOR or opaque binary payload in generic-scitt
    }
  }

  const profileUri =
    typeof decodedPlain?.['profile'] === 'string' ? decodedPlain['profile'] : null;

  let profileFamily: UniversalProfileFamily = 'generic-scitt';
  if (
    contentType === CAPSULE_MEDIA_TYPE ||
    profileUri === CAPSULE_PROFILE_URI ||
    (profileUri && profileUri.startsWith('urn:hivemind:receipts:capsule:'))
  ) {
    profileFamily = 'hivemind';
  } else if (
    contentType === MIH_CAPSULE_MEDIA_TYPE ||
    profileUri === MIH_CAPSULE_PROFILE_URI ||
    profileUri === MIH_CAPSULE_URN
  ) {
    profileFamily = 'draft-mih';
  } else if (
    contentType === EMIRDAG_AIR_MEDIA_TYPE ||
    profileUri === EMIRDAG_AIR_PROFILE_URI
  ) {
    profileFamily = 'emirdag-air';
  }

  let payload_valid = false;
  let capsule: Capsule | null = null;
  const normalized: UniversalVerifyReport['normalized'] = {
    subject_id: parsed.cwt?.sub ?? null,
    agent_id: null,
    action_or_tool: null,
    verdict_or_outcome: null,
    request_digest: null,
    response_digest: null,
  };

  if (!rawPayload) {
    addCheck('payload', false, '', 'missing payload');
  } else if (profileFamily === 'hivemind') {
    try {
      capsule = parseCapsule(rawPayload);
      payload_valid = true;
      normalized.subject_id = capsule.action_id;
      normalized.agent_id =
        capsule.agent.spiffe_id ?? capsule.agent.key_thumbprint ?? null;
      normalized.action_or_tool = capsule.operation.method;
      normalized.verdict_or_outcome = capsule.verdict_class;
      normalized.request_digest = capsule.request_digest;
      normalized.response_digest = capsule.effect?.response_digest ?? null;
      addCheck(
        'payload',
        true,
        `Hivemind capsule ${capsule.capsule_id} validated`,
        '',
      );
      if (opts.disclosure) {
        const disc = verifyDisclosure(capsule, opts.disclosure);
        addCheck(
          'disclosure',
          disc.ok,
          `disclosed fields verified: ${disc.checked.join(', ')}`,
          `disclosure mismatch: ${disc.failed.join(', ')}`,
        );
      }
    } catch (e) {
      addCheck('payload', false, '', (e as Error).message);
    }
  } else if (profileFamily === 'draft-mih') {
    if (!decodedPlain) {
      addCheck('payload', false, '', 'draft-mih payload is not a valid CBOR map');
    } else {
      const mih = decodedPlain as unknown as Partial<MihCapsulePayload>;
      const missing: string[] = [];
      if (!mih.agent_id) missing.push('agent_id');
      if (!mih.tool_name) missing.push('tool_name');
      if (!isDigest(mih.input_hash)) missing.push('input_hash');
      if (!isDigest(mih.output_hash)) missing.push('output_hash');
      if (!mih.decision) missing.push('decision');

      let hashMatch = true;
      if (mih.capsule_id) {
        const { capsule_id, ...rest } = decodedPlain;
        void capsule_id;
        if (digestOf(cborEncode(rest as never)) !== mih.capsule_id) {
          hashMatch = false;
        }
      }

      payload_valid = missing.length === 0 && hashMatch;
      normalized.subject_id = mih.action_id ?? mih.session_id ?? normalized.subject_id;
      normalized.agent_id = mih.agent_id ?? null;
      normalized.action_or_tool = mih.tool_name ?? null;
      normalized.verdict_or_outcome = mih.decision ?? null;
      normalized.request_digest = mih.input_hash ?? null;
      normalized.response_digest = mih.output_hash ?? null;
      addCheck(
        'payload',
        payload_valid,
        'draft-mih-scitt-agent-action-capsule payload validated',
        !hashMatch
          ? 'draft-mih capsule_id does not match canonical payload'
          : `draft-mih missing/invalid fields: ${missing.join(', ')}`,
      );
    }
  } else if (profileFamily === 'emirdag-air') {
    if (!decodedPlain) {
      addCheck('payload', false, '', 'emirdag-air payload is not a valid CBOR map');
    } else {
      const air = decodedPlain as unknown as Partial<EmirdagAirPayload>;
      const missing: string[] = [];
      if (!air.record_id) missing.push('record_id');
      if (!air.actor) missing.push('actor');
      if (!air.interaction_type) missing.push('interaction_type');
      if (!isDigest(air.request_hash)) missing.push('request_hash');
      if (!isDigest(air.response_hash)) missing.push('response_hash');
      if (!air.outcome) missing.push('outcome');

      payload_valid = missing.length === 0;
      normalized.subject_id = air.record_id ?? normalized.subject_id;
      normalized.agent_id = air.actor ?? null;
      normalized.action_or_tool = air.interaction_type ?? null;
      normalized.verdict_or_outcome = air.outcome ?? null;
      normalized.request_digest = air.request_hash ?? null;
      normalized.response_digest = air.response_hash ?? null;
      addCheck(
        'payload',
        payload_valid,
        `Emirdag AIR record ${air.record_id} validated`,
        `Emirdag AIR missing/invalid fields: ${missing.join(', ')}`,
      );
    }
  } else {
    payload_valid = rawPayload.length > 0;
    addCheck(
      'payload',
      payload_valid,
      `generic RFC 9943 payload (${rawPayload.length} bytes)`,
      'empty payload',
    );
  }

  // RFC 9162 / RFC 9942 SCITT inclusion receipts at unprotected header label 394
  const receipts = extractReceipts(statementBytes);
  const leafBytes = statementLeafBytes(statementBytes);
  const entryLeaf = leafHash(leafBytes);

  let checkpointRoot: Buffer | null = opts.checkpointRoot ?? null;
  if (!checkpointRoot && opts.checkpoint) {
    try {
      checkpointRoot = parseCheckpoint(opts.checkpoint).checkpoint.root;
    } catch (e) {
      addCheck('checkpoint', false, '', (e as Error).message);
    }
  }

  let inclusion_verified = false;
  let leaf_index: number | null = null;
  let tree_size: number | null = null;

  if (receipts.length > 0) {
    for (const rb of receipts) {
      try {
        const parsedReceipt = parseReceipt(rb);
        const logCandidate =
          opts.logKey ??
          opts.logKeys?.get(parsedReceipt.logKid) ??
          opts.trustRoots?.logKeys.get(parsedReceipt.logKid);
        const logKeyObj = toKeyObject(logCandidate);
        const targetRoot =
          checkpointRoot ?? recomputeRootFromReceipt(entryLeaf, parsedReceipt.inclusion);

        if (logKeyObj) {
          if (verifyReceipt(rb, leafBytes, targetRoot, logKeyObj)) {
            inclusion_verified = true;
            leaf_index = parsedReceipt.inclusion.leafIndex;
            tree_size = parsedReceipt.inclusion.treeSize;
            break;
          }
        } else if (checkpointRoot && verifyInclusion(entryLeaf, parsedReceipt.inclusion, checkpointRoot)) {
          inclusion_verified = true;
          leaf_index = parsedReceipt.inclusion.leafIndex;
          tree_size = parsedReceipt.inclusion.treeSize;
          break;
        }
      } catch {
        // try next receipt
      }
    }
    addCheck(
      'inclusion',
      inclusion_verified,
      `RFC 9162 inclusion verified at leaf ${leaf_index} of ${tree_size}`,
      'no attached SCITT receipt verified against the log key / root',
    );
  } else if (opts.requireReceipt || opts.logKey || opts.checkpointRoot || opts.checkpoint) {
    addCheck('inclusion', false, '', 'no SCITT receipt (header 394) attached to statement');
  } else {
    checks.push({
      check: 'inclusion',
      status: 'skip',
      detail: 'no receipt attached (signed statement only)',
    });
  }

  const rawValid = !checks.some((c) => c.status === 'fail');
  const runId = computeVerificationRunId(
    `universal:${sha256(statementBytes).toString('hex')}:${profileFamily}:${rawValid}:${checks.map((c) => `${c.check}=${c.status}`).join(',')}`,
  );
  const valid = rawValid && isValidVerificationRunId(runId);

  return {
    valid,
    verdict: valid ? 'VERIFIED' : 'FAILED',
    verification_run_id: runId,
    verificationRunId: runId,
    profile: profileFamily,
    profile_family: profileFamily,
    content_type: contentType,
    profile_uri: profileUri,
    kid: parsed.kid,
    alg: parsed.alg,
    cwt: parsed.cwt,
    signature_valid,
    payload_valid,
    inclusion_verified,
    receipt_valid: inclusion_verified,
    receipt_count: receipts.length,
    leaf_index,
    tree_size,
    capsule,
    payload: decodedPlain,
    normalized,
    checks,
    errors,
  };
}
