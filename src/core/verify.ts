// SPDX-License-Identifier: Apache-2.0
/**
 * The Class-1 verifier core. Offline, deterministic, no model, no network, no
 * clock heuristics: the same inputs give the same report in the CLI, the
 * browser bundle, CI and the Rust port (all consume the same conformance
 * vectors). Timestamps are REPORTED (log checkpoint time is bounded by
 * witness cosignature times and RFC 3161 tokens) but recency never flips a
 * verdict. Every report names the claims that remain only asserted.
 */
import { createHash, type KeyObject } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseCapsule, verifyDisclosure, type Capsule, type Disclosure } from './capsule.js';
import {
  extractReceipts,
  parseReceipt,
  parseSign1,
  statementLeafBytes,
  verifyCountersignature,
  verifyCountersignatureMlDsa,
  verifyReceipt,
  verifySign1,
  type ParsedSign1,
} from './cose.js';
import {
  parseCheckpoint,
  quorumSatisfied,
  verifyCheckpointSignatures,
  type WitnessPolicy,
} from './checkpoint.js';
import { leafHash, verifyConsistency, verifyInclusion as verifyInclusionProof } from './merkle.js';
import { parseBatchPayload, verifyBatchInclusion, type BatchPayload } from './batch.js';
import {
  COSE_ALG,
  CUSTOMER_ISSUER_ALLOWED_ALGS,
  HYPEREUM_OPERATED_ALLOWED_ALGS,
  PRODUCTION_RECEIPTS_KID,
  type CoseAlg,
} from './keys.js';

export type CheckStatus = 'pass' | 'fail' | 'skip';
export interface CheckResult {
  check: string;
  status: CheckStatus;
  detail: string;
}

export interface IssuerTrust {
  kid: string;
  key: KeyObject;
  alg: CoseAlg;
  tier?: 'T0' | 'T1' | 'T2' | 'T3' | string | null | undefined;
  display: string; // domain (T1), legal entity + LEI (T2/T3)
  revoked?: boolean;
  operatedBy?: 'hypereum' | 'customer' | string | null | undefined;
}

const HYPEREUM_ISSUER_DOMAIN_PATTERNS = [
  /(?:^|\.|:\/\/)(?:[a-z0-9-]+\.)*hivemindax\.com(?:\/|$)/i,
  /(?:^|\.|:\/\/)(?:[a-z0-9-]+\.)*hypereum\.ai(?:\/|$)/i,
  /^urn:hivemind:ax:/i,
  /^hivemind\s+ax\b/i,
];

/**
 * Ruling R83: EdDSA-only (-8) applies to keys operated by Hypereum
 * (log checkpoint and receipt keys, Hivemind AX issuer keys).
 * Customer issuer keys verify against CUSTOMER_ISSUER_ALLOWED_ALGS [OWNER; default EdDSA, ES256, ES384].
 */
export function isHypereumOperatedIssuer(
  issuer: Pick<IssuerTrust, 'kid' | 'display' | 'operatedBy'>,
  cwtIss?: string,
): boolean {
  if (typeof issuer.operatedBy === 'string') {
    const norm = issuer.operatedBy.trim().toLowerCase();
    if (norm === 'hypereum') return true;
    if (norm === 'customer') return false;
  }
  if (
    issuer.kid === PRODUCTION_RECEIPTS_KID ||
    issuer.kid.startsWith('hm_prod_receipts_ed25519_') ||
    issuer.kid.startsWith('hypereum-') ||
    issuer.kid.startsWith('hivemind-ax')
  ) {
    return true;
  }
  const display = issuer.display ?? '';
  const iss = cwtIss ?? '';
  return HYPEREUM_ISSUER_DOMAIN_PATTERNS.some((re) => re.test(display) || re.test(iss));
}

export interface TrustRoots {
  issuers: Map<string, IssuerTrust>;
  logKeys: Map<string, { key: KeyObject; alg: CoseAlg }>; // by log kid
  noteVerifiers: string[]; // log + witness signed-note verifiers
  witnessPolicy: WitnessPolicy | null;
  counterSigners?: Map<string, { key: KeyObject; alg: CoseAlg }>; // classical countersignature keys by kid
  mlDsaCounterSigners?: Map<string, { publicKey: Buffer; alg: CoseAlg }>; // ML-DSA (RFC 9964) countersigners
  canonicalJson?: string;
}

export interface VerifyInput {
  statement: Buffer; // transparent statement (may carry receipts)
  detachedPayload?: Buffer;
  checkpoint?: string; // cosigned checkpoint text the receipt proves against
  /**
   * When the receipt was issued against an older checkpoint than the one
   * supplied: the root at receipt time plus an RFC 9162 consistency proof
   * from that root to the supplied checkpoint root.
   */
  consistencyChain?: {
    rootAtReceipt: Buffer;
    proof: { firstSize: number; secondSize: number; hashes: Buffer[] };
  };
  disclosure?: Disclosure;
  batch?: { proof: { treeSize: number; leafIndex: number; hashes: Buffer[] }; capsuleBytes: Buffer };
  timestampCheck?: (statement: ParsedSign1) => CheckResult;
}

export interface VerifyReport {
  verdict: 'VERIFIED' | 'FAILED';
  run_id: string;
  verification_run_id: string;
  verificationRunId: string;
  verifier_build_id: string;
  checks: CheckResult[];
  assertedOnly: string[];
  capsule: Capsule | null;
  batch: BatchPayload | null;
  issuer_tier: string | null;
  issuerTier: string | null;
  log: { origin: string; treeSize: number; leafIndex: number } | null;
  witnessTimes: number[];
  failure_summary: string | null;
  tampered_region: string | null;
}

const FALLBACK_CLI_VERIFIER_BUILD_SHA256 =
  '9f4a8d2c6b1e5f3a7d0c4b8e2f6a9d3c7b1e5f9a3d7c1b5e9f3a7d1c5b9e3f7a';

function resolveVerifierBuildId(): string {
  try {
    const selfPath = fileURLToPath(import.meta.url);
    if (selfPath.endsWith('hvr-cli.bundle.mjs') && existsSync(selfPath)) {
      return createHash('sha256').update(readFileSync(selfPath)).digest('hex');
    }
    const candidates = [
      path.resolve(path.dirname(selfPath), '../../../dist/receipts/hvr-cli.bundle.mjs'),
      path.resolve(process.cwd(), 'dist/receipts/hvr-cli.bundle.mjs'),
    ];
    for (const bundlePath of candidates) {
      if (existsSync(bundlePath)) {
        return createHash('sha256').update(readFileSync(bundlePath)).digest('hex');
      }
    }
    return createHash('sha256').update(readFileSync(selfPath)).digest('hex');
  } catch {
    return FALLBACK_CLI_VERIFIER_BUILD_SHA256;
  }
}

export const VERIFIER_BUILD_ID = resolveVerifierBuildId();

export function canonicalizeJson(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJson(item)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort();
    const entries = keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`);
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value);
}

function serializeTrustRootsForHash(trustRoots: unknown): string {
  if (!trustRoots) return '';
  if (typeof trustRoots === 'string') {
    try {
      return canonicalizeJson(JSON.parse(trustRoots));
    } catch {
      return trustRoots.trim();
    }
  }
  if (typeof trustRoots === 'object') {
    const tr = trustRoots as Partial<TrustRoots> & Record<string, unknown>;
    if (typeof tr.canonicalJson === 'string' && tr.canonicalJson.length > 0) {
      return tr.canonicalJson;
    }
    if (tr.issuers instanceof Map && tr.logKeys instanceof Map) {
      const issuers = [...tr.issuers.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([kid, iss]) => ({
          kid,
          alg: iss.alg,
          ...(iss.tier ? { tier: iss.tier } : {}),
          display: iss.display,
        }));
      const log_keys = [...tr.logKeys.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([kid, lk]) => ({ kid, alg: lk.alg }));
      return canonicalizeJson({
        issuers,
        log_keys,
        note_verifiers: tr.noteVerifiers ?? [],
        ...(tr.witnessPolicy ? { witness_policy: tr.witnessPolicy } : {}),
      });
    }
    return canonicalizeJson(trustRoots);
  }
  return String(trustRoots);
}

/**
 * Deterministic verification run ID formula:
 * `run_id = "vrun_" + hex(sha256(verifier_build_id || sha256(statement) || sha256(checkpoint) || sha256(trust_roots)))`
 * Each verifier build (browser WASM vs CLI `verify.ts`) binds its own `verifier_build_id`.
 */
export function computeDeterministicRunId(
  statementBytes: Uint8Array,
  checkpointText = '',
  trustRoots?: unknown,
  buildId: string = VERIFIER_BUILD_ID,
): string {
  const buildIdBytes = Buffer.from(buildId, 'utf8');
  const stmtHash = createHash('sha256').update(statementBytes).digest();
  const cpNorm = checkpointText.trim().replace(/\r\n/g, '\n');
  const cpHash = createHash('sha256').update(Buffer.from(cpNorm, 'utf8')).digest();
  const trustCanonical = serializeTrustRootsForHash(trustRoots);
  const trustHash = createHash('sha256').update(Buffer.from(trustCanonical, 'utf8')).digest();
  const combined = Buffer.concat([buildIdBytes, stmtHash, cpHash, trustHash]);
  return `vrun_${createHash('sha256').update(combined).digest('hex')}`;
}

export function computeVerificationRunId(material: Buffer | string): string {
  const buf = typeof material === 'string' ? Buffer.from(material, 'utf8') : material;
  return `vrun_${createHash('sha256').update(buf).digest('hex')}`;
}

export function isValidVerificationRunId(value: unknown): value is string {
  return typeof value === 'string' && /^vrun_[0-9a-f]{16,64}$/.test(value);
}

/**
 * Fail-closed guard for any verification report / badge / seal / verdict helper.
 * Throws `VERIFICATION_FAILED` if `verification_run_id` / `verificationRunId` is missing or malformed.
 */
export function assertVerificationRunId<
  T extends {
    verification_run_id?: string | undefined;
    verificationRunId?: string | undefined;
  },
>(report: T): T & { verification_run_id: string; verificationRunId: string } {
  const runId = report?.verification_run_id || report?.verificationRunId;
  if (!isValidVerificationRunId(runId)) {
    throw new Error('VERIFICATION_FAILED: missing or invalid verification_run_id');
  }
  return {
    ...report,
    verification_run_id: runId,
    verificationRunId: runId,
  };
}

export function renderVerificationBadge(report: {
  verdict?: 'VERIFIED' | 'FAILED' | string | undefined;
  valid?: boolean | undefined;
  ok?: boolean | undefined;
  verification_run_id?: string | undefined;
  verificationRunId?: string | undefined;
}): {
  status: 'VERIFIED' | 'VERIFICATION_FAILED';
  verification_run_id: string | null;
  badge: string;
} {
  const runId = report?.verification_run_id || report?.verificationRunId;
  const passed =
    report?.verdict === 'VERIFIED' ||
    (report?.verdict === undefined && (report?.valid === true || report?.ok === true));
  if (!passed || !isValidVerificationRunId(runId)) {
    return {
      status: 'VERIFICATION_FAILED',
      verification_run_id: null,
      badge: 'VERIFICATION_FAILED',
    };
  }
  return {
    status: 'VERIFIED',
    verification_run_id: runId,
    badge: `VERIFIED (${runId})`,
  };
}

function check(name: string, ok: boolean, passDetail: string, failDetail: string): CheckResult {
  return { check: name, status: ok ? 'pass' : 'fail', detail: ok ? passDetail : failDetail };
}

export function verifyReceiptBundle(input: VerifyInput, trust: TrustRoots): VerifyReport {
  const checks: CheckResult[] = [];
  const asserted = new Set<string>();
  let capsule: Capsule | null = null;
  let batch: BatchPayload | null = null;
  let issuer_tier: string | null = null;
  let issuerTier: string | null = null;
  let logInfo: VerifyReport['log'] = null;
  let witnessTimes: number[] = [];
  const runId = computeDeterministicRunId(input.statement, input.checkpoint ?? '', trust);

  let parsed: ParsedSign1;
  try {
    parsed = parseSign1(input.statement);
    checks.push(check('envelope', true, 'COSE_Sign1 parses in strict deterministic CBOR', ''));
  } catch (e) {
    checks.push({ check: 'envelope', status: 'fail', detail: (e as Error).message });
    return {
      verdict: 'FAILED',
      run_id: runId,
      verification_run_id: runId,
      verificationRunId: runId,
      verifier_build_id: VERIFIER_BUILD_ID,
      checks,
      assertedOnly: [],
      capsule,
      batch,
      issuer_tier: null,
      issuerTier,
      log: null,
      witnessTimes,
      failure_summary: 'First failing check: envelope parse failed (tampered region: protected header).',
      tampered_region: 'protected header',
    };
  }

  const issuer = trust.issuers.get(parsed.kid);
  if (!issuer) {
    checks.push({ check: 'issuer_identity', status: 'fail', detail: `unknown issuer kid ${parsed.kid}: no bare "verified"; identity is unverifiable` });
  } else {
    const rawTier = typeof issuer.tier === 'string' && issuer.tier.trim().length > 0 ? issuer.tier.trim() : null;
    issuer_tier = rawTier;
    const tierLabel = rawTier ?? 'Tier unknown';
    issuerTier = `${tierLabel} · ${issuer.display}`;
    checks.push(
      check(
        'issuer_identity',
        !issuer.revoked,
        issuerTier,
        `issuer key ${parsed.kid} is revoked in key transparency`,
      ),
    );
    const isHypereumIssuer = isHypereumOperatedIssuer(issuer, parsed.cwt?.iss);
    const allowedAlgs: readonly number[] = isHypereumIssuer
      ? HYPEREUM_OPERATED_ALLOWED_ALGS
      : CUSTOMER_ISSUER_ALLOWED_ALGS;
    const algAllowed = allowedAlgs.includes(parsed.alg) && allowedAlgs.includes(issuer.alg);
    const sigOk =
      algAllowed &&
      issuer.alg === parsed.alg &&
      verifySign1(parsed, issuer.key, input.detachedPayload ? { detachedPayload: input.detachedPayload } : {});
    const failDetail = !algAllowed
      ? isHypereumIssuer
        ? `Hypereum-operated issuer key requires EdDSA (${COSE_ALG.EdDSA}); got alg ${parsed.alg}`
        : `customer issuer algorithm ${parsed.alg} is not in registered algorithm list [${CUSTOMER_ISSUER_ALLOWED_ALGS.join(', ')}]`
      : 'COSE signature does not verify';
    checks.push(check('signature', sigOk, `COSE signature verifies (alg ${parsed.alg})`, failDetail));
  }

  // Post-quantum countersignature, when the relying party pins such a key.
  if (trust.mlDsaCounterSigners && trust.mlDsaCounterSigners.size > 0) {
    let ok = false;
    let kidUsed = '';
    for (const [kid, entry] of trust.mlDsaCounterSigners) {
      if (verifyCountersignatureMlDsa(parsed, kid, entry.publicKey, entry.alg)) {
        ok = true;
        kidUsed = kid;
        break;
      }
    }
    checks.push(
      check(
        'pq_countersignature',
        ok,
        `ML-DSA countersignature by ${kidUsed} verifies (RFC 9964)`,
        'no valid ML-DSA countersignature for a pinned key',
      ),
    );
  } else if (trust.counterSigners && trust.counterSigners.size > 0) {
    let ok = false;
    let kidUsed = '';
    for (const [kid, entry] of trust.counterSigners) {
      if (verifyCountersignature(parsed, kid, entry.key, entry.alg)) {
        ok = true;
        kidUsed = kid;
        break;
      }
    }
    checks.push(
      check(
        'pq_countersignature',
        ok,
        `countersignature by ${kidUsed} verifies (hybrid PQ)`,
        'no valid post-quantum countersignature for a pinned key',
      ),
    );
  } else {
    checks.push({ check: 'pq_countersignature', status: 'skip', detail: 'no PQ countersigner pinned by this relying party' });
  }

  // Payload: capsule or batch.
  const payload = parsed.payload ?? input.detachedPayload ?? null;
  if (!payload) {
    checks.push({ check: 'capsule', status: 'fail', detail: 'detached payload was not supplied' });
  } else {
    try {
      capsule = parseCapsule(payload);
      checks.push(check('capsule', true, `capsule ${capsule.capsule_id} is canonical and valid`, ''));
    } catch {
      try {
        batch = parseBatchPayload(payload);
        checks.push(check('capsule', true, `batch of ${batch.count} capsules, root ${batch.batch_root}`, ''));
      } catch (e) {
        checks.push({ check: 'capsule', status: 'fail', detail: `payload is neither a valid capsule nor a batch: ${(e as Error).message}` });
      }
    }
  }

  if (batch && input.batch) {
    try {
      const inner = parseCapsule(input.batch.capsuleBytes);
      const incOk = verifyBatchInclusion(input.batch.capsuleBytes, input.batch.proof, batch.batch_root);
      checks.push(check('batch_inclusion', incOk, `capsule ${inner.capsule_id} is in the batch`, 'capsule is not committed to by the batch root'));
      capsule = inner;
    } catch (e) {
      checks.push({ check: 'batch_inclusion', status: 'fail', detail: (e as Error).message });
    }
  }

  if (capsule) {
    checks.push(
      check(
        'effect_binding',
        capsule.effect?.status !== 'confirmed' || Boolean(capsule.effect?.response_digest),
        capsule.effect?.status === 'confirmed'
          ? 'confirmed effect carries the observed response digest'
          : `verdict ${capsule.verdict_class} claims no confirmed effect`,
        'invariant 2 violated: confirmed effect without response_digest',
      ),
    );
    if (capsule.effect?.status !== 'confirmed') asserted.add('effect');
    asserted.add('model'); // model id is issuer-reported unless provider-signed (opinion layer)
    asserted.add('issued_at'); // issuer clock is informative; registration time is authoritative
    if (!capsule.runtime?.attestation_ref) asserted.add('runtime integrity');
  }

  if (capsule && input.disclosure) {
    const d = verifyDisclosure(capsule, input.disclosure);
    checks.push(
      check(
        'disclosure',
        d.ok,
        `disclosed fields match salted commitments: ${d.checked.join(', ') || 'none'}`,
        `disclosure does not open commitments: ${d.failed.join(', ')}`,
      ),
    );
    for (const f of d.checked) if (!d.failed.includes(f)) asserted.delete(f === 'response' ? 'effect' : f);
  } else if (capsule) {
    checks.push({ check: 'disclosure', status: 'skip', detail: 'no disclosure supplied; commitments stay closed (private by construction)' });
    asserted.add('request content');
  }

  // Inclusion in the log + witness quorum on the checkpoint.
  const receiptBytesList = extractReceipts(input.statement);
  const leafBytes = statementLeafBytes(input.statement);
  void leafHash(leafBytes);
  if (receiptBytesList.length === 0) {
    checks.push({ check: 'inclusion', status: 'fail', detail: 'no COSE receipt attached: statement is not attested as registered' });
  } else if (!input.checkpoint) {
    checks.push({ check: 'inclusion', status: 'fail', detail: 'receipt present but no checkpoint supplied to prove against' });
  } else {
    try {
      const { checkpoint } = parseCheckpoint(input.checkpoint);
      let verified = false;
      let leafIndex = -1;
      let viaConsistency = false;
      let rejectedLogReceiptAlg: number | null = null;
      for (const rb of receiptBytesList) {
        let receipt: ReturnType<typeof parseReceipt>;
        try {
          receipt = parseReceipt(rb);
        } catch {
          continue;
        }
        const logKey = trust.logKeys.get(receipt.logKid);
        if (!logKey) continue;
        if (
          !(HYPEREUM_OPERATED_ALLOWED_ALGS as readonly number[]).includes(receipt.alg) ||
          !(HYPEREUM_OPERATED_ALLOWED_ALGS as readonly number[]).includes(logKey.alg)
        ) {
          rejectedLogReceiptAlg = receipt.alg;
          continue;
        }
        if (receipt.inclusion.treeSize === checkpoint.treeSize && verifyReceipt(rb, leafBytes, checkpoint.root, logKey.key)) {
          verified = true;
          leafIndex = receipt.inclusion.leafIndex;
          break;
        }
        // Older receipt + consistency chain to the supplied checkpoint.
        const chain = input.consistencyChain;
        if (
          chain &&
          receipt.inclusion.treeSize === chain.proof.firstSize &&
          chain.proof.secondSize === checkpoint.treeSize &&
          verifyReceipt(rb, leafBytes, chain.rootAtReceipt, logKey.key) &&
          verifyConsistency(chain.proof, chain.rootAtReceipt, checkpoint.root)
        ) {
          verified = true;
          viaConsistency = true;
          leafIndex = receipt.inclusion.leafIndex;
          break;
        }
      }
      void verifyInclusionProof;
      logInfo = { origin: checkpoint.origin, treeSize: checkpoint.treeSize, leafIndex };
      checks.push(
        check(
          'inclusion',
          verified,
          `inclusion proof verifies at leaf ${leafIndex} of ${checkpoint.treeSize} (${checkpoint.origin})${viaConsistency ? ' via consistency proof from the receipt-time root' : ''}`,
          rejectedLogReceiptAlg !== null
            ? `log receipt requires EdDSA (${COSE_ALG.EdDSA}); got alg ${rejectedLogReceiptAlg}`
            : 'no attached receipt verifies against the checkpoint root',
        ),
      );
      const sig = verifyCheckpointSignatures(input.checkpoint, trust.noteVerifiers);
      checks.push(check('checkpoint_signature', sig.logValid, 'log signed the checkpoint', 'log checkpoint signature does not verify'));
      const validWitnesses = sig.cosignatures.filter((c) => c.valid).map((c) => c.name);
      witnessTimes = sig.cosignatures.filter((c) => c.valid).map((c) => c.timestamp);
      if (trust.witnessPolicy) {
        const validCount = new Set(validWitnesses).size;
        const requiredCount = trust.witnessPolicy.quorum;
        checks.push(
          check(
            'witness_quorum',
            quorumSatisfied(trust.witnessPolicy, validWitnesses),
            `${validCount} cosignatures, ${requiredCount} required`,
            `${validCount} cosignatures, ${requiredCount} required`,
          ),
        );
      } else {
        checks.push({ check: 'witness_quorum', status: 'skip', detail: 'no witness policy pinned by this relying party' });
      }
    } catch (e) {
      checks.push({ check: 'inclusion', status: 'fail', detail: (e as Error).message });
    }
  }

  if (input.timestampCheck) checks.push(input.timestampCheck(parsed));

  const rawVerdict = checks.some((c) => c.status === 'fail') ? 'FAILED' : 'VERIFIED';
  const verdict: 'VERIFIED' | 'FAILED' =
    rawVerdict === 'VERIFIED' && isValidVerificationRunId(runId) ? 'VERIFIED' : 'FAILED';
  let failure_summary: string | null = null;
  let tampered_region: string | null = null;
  if (verdict === 'FAILED') {
    const firstFail = checks.find((c) => c.status === 'fail');
    const capsuleFailed = checks.some((c) => c.check === 'capsule' && c.status === 'fail');
    if (firstFail?.check === 'envelope') {
      tampered_region = 'protected header';
      failure_summary = 'First failing check: envelope parse failed (tampered region: protected header).';
    } else if (firstFail?.check === 'signature') {
      const region = capsuleFailed ? 'payload' : 'signature';
      tampered_region = region;
      failure_summary = `First failing check: statement signature check failed (tampered region: ${region}).`;
    } else if (firstFail?.check === 'capsule') {
      tampered_region = 'payload';
      failure_summary = 'First failing check: capsule payload check failed (tampered region: payload).';
    } else if (firstFail?.check === 'inclusion') {
      tampered_region = 'payload';
      failure_summary = 'First failing check: log inclusion proof failed (tampered region: payload).';
    } else if (firstFail) {
      tampered_region = firstFail.check;
      failure_summary = `First failing check: ${firstFail.check} (${firstFail.detail}).`;
    }
  }
  return {
    verdict,
    run_id: runId,
    verification_run_id: runId,
    verificationRunId: runId,
    verifier_build_id: VERIFIER_BUILD_ID,
    checks,
    assertedOnly: [...asserted],
    capsule,
    batch,
    issuer_tier,
    issuerTier,
    log: logInfo,
    witnessTimes,
    failure_summary,
    tampered_region,
  };
}

export function formatReport(r: VerifyReport): string {
  const runId = r.run_id || r.verification_run_id || r.verificationRunId;
  if (!isValidVerificationRunId(runId)) {
    return [
      'VERDICT: VERIFICATION_FAILED (missing or invalid verification_run_id)',
      `Issuer: ${r.issuerTier ?? 'Tier unknown'}`,
    ].join('\n');
  }
  const effectiveVerdict = r.verdict === 'VERIFIED' ? 'VERIFIED' : 'FAILED';
  const lines = [
    `VERDICT: ${effectiveVerdict}`,
    `run_id: ${runId}`,
    `verification_run_id: ${runId}`,
    `Issuer: ${r.issuerTier ?? 'Tier unknown'}`,
  ];
  if (r.failure_summary) {
    lines.push(`Failure: ${r.failure_summary}`);
  }
  for (const c of r.checks) lines.push(`  [${c.status.toUpperCase().padEnd(4)}] ${c.check}: ${c.detail}`);
  lines.push(`Asserted only (not attested by this receipt): ${r.assertedOnly.join(', ') || 'none'}`);
  lines.push(
    'A receipt proves registration, signatures, witnessed checkpoints and disclosed commitments. ' +
      'It does not prove an output was correct or that an unwitnessed fact is true.',
  );
  return lines.join('\n');
}
