// SPDX-License-Identifier: Apache-2.0
/**
 * The capture layer shared by every integration surface (SDK, OTel, MCP,
 * A2A, hooks, gateways): authorize() before the action, record() after —
 * on EVERY verdict. Local canonicalisation, salting, signing, batching and
 * retries live here so no surface re-implements them.
 */
import { buildCapsule, digestOf, type Capsule, type Disclosure, type RiskTier, type VerdictClass } from '../core/capsule.js';
import { coseSign1, CONTENT_TYPE_CAPSULE } from '../core/cose.js';
import { buildBatch, BATCH_MEDIA_TYPE } from '../core/batch.js';
import { cborEncode } from '../core/cbor.js';
import type { ReceiptSigner } from '../core/keys.js';
import type { AuthZenRequest, AuthZenResponse } from '../authz/authzen-types.js';

export interface AuthorizeClient {
  evaluate(req: AuthZenRequest): Promise<AuthZenResponse>;
}

export interface RegisterClient {
  register(statement: Buffer): Promise<{ transparentStatement: Buffer; index: number }>;
}

export class HttpAuthorizeClient implements AuthorizeClient {
  constructor(private readonly baseUrl: string, private readonly fetchFn: typeof fetch = fetch) {}
  async evaluate(req: AuthZenRequest): Promise<AuthZenResponse> {
    const res = await this.fetchFn(`${this.baseUrl.replace(/\/$/, '')}/authz/evaluate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(req),
    });
    if (!res.ok) throw new Error(`authz evaluate failed (${res.status})`);
    return (await res.json()) as AuthZenResponse;
  }
}

export class HttpRegisterClient implements RegisterClient {
  constructor(private readonly baseUrl: string, private readonly fetchFn: typeof fetch = fetch) {}
  async register(statement: Buffer): Promise<{ transparentStatement: Buffer; index: number }> {
    let lastError: unknown;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const res = await this.fetchFn(`${this.baseUrl.replace(/\/$/, '')}/transparency/entries`, {
          method: 'POST',
          headers: { 'content-type': 'application/cose' },
          body: new Uint8Array(statement),
        });
        if (res.status === 422) {
          const body = (await res.json().catch(() => ({}))) as { reason?: string };
          throw new Error(`registration refused: ${body.reason ?? res.status}`);
        }
        if (!res.ok) throw new Error(`registration failed (${res.status})`);
        return {
          transparentStatement: Buffer.from(await res.arrayBuffer()),
          index: Number(res.headers.get('x-leaf-index') ?? -1),
        };
      } catch (e) {
        lastError = e;
        if (attempt < 2) await new Promise((r) => setTimeout(r, 100 * (attempt + 1)));
      }
    }
    throw lastError;
  }
}

export interface ActionDescriptor {
  method: string;
  kind?: Capsule['operation']['kind'];
  riskTier?: RiskTier;
  target?: unknown;
  toolSchemaDigest?: `sha256:${string}`;
  args: unknown;
  principalSubject?: unknown;
  agent?: Capsule['agent'];
  criteriaRef?: `sha256:${string}`;
  model?: Capsule['model'];
  causality?: Capsule['causality'];
  subjectType?: string;
  subjectId?: string;
  resourceType?: string;
  resourceId?: string;
  extensions?: Record<string, unknown>;
}

export interface RecordedReceipt {
  capsule: Capsule;
  capsuleBytes: Buffer;
  disclosure: Disclosure;
  statement: Buffer;
  transparentStatement: Buffer | null;
  leafIndex: number | null;
  decision: AuthZenResponse;
}

export class ReceiptCapture {
  private pendingBatch: Buffer[] = [];
  constructor(
    private readonly signer: ReceiptSigner,
    private readonly authz: AuthorizeClient,
    private readonly registerClient: RegisterClient | null,
    private readonly issuer = 'urn:hivemind:issuer:self',
    private readonly batchSize = 0, // 0 = register each capsule; >1 = Merkle batches
  ) {}

  async authorize(action: ActionDescriptor, approvalDigest = ''): Promise<AuthZenResponse> {
    return this.authz.evaluate({
      subject: { type: action.subjectType ?? 'Agent', id: action.subjectId ?? 'agent' },
      action: { name: action.method },
      resource: { type: action.resourceType ?? 'Tool', id: action.resourceId ?? action.method },
      context: {
        risk_tier: action.riskTier ?? 'read',
        approval_digest: approvalDigest,
        kill_switch: false,
      },
    });
  }

  /**
   * Authorize, run, and ALWAYS record — refusal, error and timeout included.
   * If authorization denies or demands approval, the action never runs and
   * the capsule says so (verdict blocked/denied).
   */
  async run<T>(
    action: ActionDescriptor,
    fn: () => Promise<{ result: T; observedResponse?: unknown }>,
    opts: { approvalDigest?: string; timeoutMs?: number } = {},
  ): Promise<{ result: T | null; receipt: RecordedReceipt }> {
    const decision = await this.authorize(action, opts.approvalDigest ?? '');
    let verdict: VerdictClass;
    let result: T | null = null;
    let observed: unknown;
    if (!decision.decision) {
      verdict = decision.hivemind.requires_approval ? 'blocked' : 'denied';
    } else {
      try {
        const raced = opts.timeoutMs
          ? await Promise.race([
              fn(),
              new Promise<never>((_, reject) =>
                setTimeout(() => reject(Object.assign(new Error('timed out'), { hivemindTimeout: true })), opts.timeoutMs).unref?.(),
              ),
            ])
          : await fn();
        result = raced.result;
        observed = raced.observedResponse ?? raced.result;
        verdict = 'executed';
      } catch (e) {
        verdict = (e as { hivemindTimeout?: boolean }).hivemindTimeout ? 'timed_out' : 'errored';
        observed = { error: (e as Error).message };
      }
    }
    const receipt = await this.record(action, verdict, decision, verdict === 'executed' ? observed : undefined);
    return { result, receipt };
  }

  async record(
    action: ActionDescriptor,
    verdict: VerdictClass,
    decision: AuthZenResponse,
    observedResponse?: unknown,
  ): Promise<RecordedReceipt> {
    const { capsule, capsuleBytes, disclosure } = buildCapsule({
      agent: action.agent ?? {},
      principalSubject: action.principalSubject ?? action.subjectId ?? 'unknown',
      operation: {
        kind: action.kind ?? 'tool',
        method: action.method,
        risk_tier: action.riskTier ?? 'read',
        ...(action.target !== undefined ? { target: action.target } : {}),
        ...(action.toolSchemaDigest ? { tool_schema_digest: action.toolSchemaDigest } : {}),
      },
      requestArgs: action.args,
      verdict,
      ...(observedResponse !== undefined ? { observedResponse } : {}),
      disposition: {
        authority: decision.hivemind.decision_digest,
        decision_digest: decision.hivemind.decision_digest as never,
      },
      ...(action.criteriaRef ? { criteriaRef: action.criteriaRef } : {}),
      ...(action.model ? { model: action.model } : {}),
      ...(action.causality ? { causality: action.causality } : {}),
      ...(action.extensions ? { extensions: action.extensions } : {}),
      ledgerMode: this.registerClient ? 'anchored' : 'standalone',
    });
    const statement = await coseSign1(this.signer, capsuleBytes, {
      contentType: CONTENT_TYPE_CAPSULE,
      cwt: { iss: this.issuer, sub: capsule.action_id, iat: Math.floor(Date.now() / 1000) },
    });
    let transparentStatement: Buffer | null = null;
    let leafIndex: number | null = null;
    if (this.registerClient) {
      if (this.batchSize > 1) {
        this.pendingBatch.push(capsuleBytes);
        if (this.pendingBatch.length >= this.batchSize) await this.flushBatch();
      } else {
        const registered = await this.registerClient.register(statement);
        transparentStatement = registered.transparentStatement;
        leafIndex = registered.index;
      }
    }
    return { capsule, capsuleBytes, disclosure, statement, transparentStatement, leafIndex, decision };
  }

  async flushBatch(): Promise<{ batchRoot: string; count: number; index: number } | null> {
    if (this.pendingBatch.length === 0 || !this.registerClient) return null;
    const batch = buildBatch(this.pendingBatch);
    this.pendingBatch = [];
    const statement = await coseSign1(this.signer, batch.payloadBytes, {
      contentType: BATCH_MEDIA_TYPE,
      cwt: { iss: this.issuer, sub: batch.payload.batch_root, iat: Math.floor(Date.now() / 1000) },
    });
    const registered = await this.registerClient.register(statement);
    return { batchRoot: batch.payload.batch_root, count: batch.payload.count, index: registered.index };
  }
}

export function requestDigestOf(args: unknown): string {
  return digestOf(cborEncode(args as never));
}
