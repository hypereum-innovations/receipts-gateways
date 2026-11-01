// SPDX-License-Identifier: Apache-2.0
/**
 * Gateway enforcement and receipt plugins:
 *  - Envoy `ext_authz` (HTTP check + 5-byte gRPC wire framing codec over
 *    `envoy.service.auth.v3.CheckRequest` / `CheckResponse`, fail-closed 403)
 *  - Envoy `ext_proc` (`envoy.service.ext_proc.v3.ExternalProcessor` request/response processor)
 *  - Cloudflare Worker Gateway (edge `fetch` interceptor with `"no receipt, no action"`)
 *  - `agentgateway` (MCP & A2A request/response interceptor)
 *  - Kong Gateway (`access` + `response` phases)
 *  - Gravitee Gateway (`onRequest` + `onResponse` policy hooks)
 *  - LiteLLM (`pre_call_hook`, `post_call_success_hook`, `post_call_failure_hook`)
 *  - Portkey Gateway (webhook / guardrail handler)
 *
 * All gateways support `GatewayEnforcementOptions`:
 *  - `mode?: 'observe' | 'enforce'` (`"no receipt, no action"` in `'enforce'` mode)
 *  - `requirePreActionIntent?: boolean`
 *  - `haltFeed?: HaltFeed` (immediate 403 block on halted global/issuer/agent/workspace/key scope)
 *  - `redactJsonPaths?: string[]` (field-level JSONPath SHA-256 redaction before signing)
 */
import type { RiskTier, VerdictClass } from '../core/capsule.js';
import type { AuthZenResponse } from '../authz/authzen-types.js';
import { matchHaltedScopeInFeed, type HaltFeed, type HaltRecord } from '../authz/killswitch-verify.js';
import type { ActionDescriptor, ReceiptCapture, RecordedReceipt } from './capture.js';
import { applyJsonPathRedaction, type EnforcementMode } from './surface-helpers.js';
import { classifyRisk, envoyCheckToAuthZen, mcpReceiptMeta } from './surface-helpers.js';

export const HEADER_DECISION_RECEIPT = 'x-hivemind-decision-receipt';
export const HEADER_CAPSULE_DIGEST = 'x-hivemind-capsule-digest';
export const HEADER_DECISION_DIGEST = 'x-hivemind-decision-digest';
export const HEADER_INTENT_CAPSULE_DIGEST = 'x-hivemind-intent-capsule-digest';

export interface GatewayEnforcementOptions {
  mode?: EnforcementMode | undefined;
  requirePreActionIntent?: boolean | undefined;
  haltFeed?: HaltFeed | undefined;
  redactJsonPaths?: string[] | undefined;
  issuer?: string | undefined;
  workspace?: string | undefined;
}

function buildHaltDeniedDecision(halted: { scopeKey: string; reason: string }): AuthZenResponse {
  return {
    decision: false,
    hivemind: {
      decision_digest: 'sha256:' + 'ee'.repeat(32),
      policy_set_digest: 'kill-switch-halt-feed',
      reasons: [`kill_switch_active:${halted.scopeKey}:${halted.reason}`],
      requires_approval: false,
    },
  };
}

function checkGatewayHalt(
  opts: GatewayEnforcementOptions | undefined,
  scopes: {
    agent?: string | undefined;
    workspace?: string | undefined;
    keyId?: string | undefined;
  },
): { scopeKey: string; reason: string } | undefined {
  if (!opts?.haltFeed) return undefined;
  const res = matchHaltedScopeInFeed(opts.haltFeed, {
    issuer: opts.issuer,
    agent: scopes.agent,
    workspace: scopes.workspace ?? opts.workspace,
    keyId: scopes.keyId,
  });
  if (!res.halted) return undefined;
  return {
    scopeKey: res.scopeKey ?? res.matchedScope ?? 'global',
    reason: res.reason ?? 'halted',
  };
}

function redactActionArgs(action: ActionDescriptor, opts?: GatewayEnforcementOptions): ActionDescriptor {
  if (!opts?.redactJsonPaths || opts.redactJsonPaths.length === 0) return action;
  return {
    ...action,
    args: applyJsonPathRedaction(action.args, opts.redactJsonPaths),
  };
}

// ---------------------------------------------------------------------------
// 1. Envoy ext_authz (HTTP + gRPC 5-byte wire framing + Protobuf/JSON codec)
// ---------------------------------------------------------------------------

export interface EnvoyCheckRequest {
  attributes?: {
    request?: {
      http?: {
        id?: string;
        method?: string;
        path?: string;
        host?: string;
        scheme?: string;
        headers?: Record<string, string>;
        body?: string;
      };
    };
    source?: {
      principal?: string;
    };
  };
}

export interface EnvoyHeaderValueOption {
  header: {
    key: string;
    value: string;
  };
  append?: boolean;
}

export interface EnvoyCheckResponse {
  status: {
    code: number; // 0 = OK, 7 = PERMISSION_DENIED
    message?: string;
  };
  httpStatus: 200 | 403;
  okResponse?: {
    headers: EnvoyHeaderValueOption[];
  };
  deniedResponse?: {
    status: { code: 403 };
    headers: EnvoyHeaderValueOption[];
    body: string;
  };
  receipt: RecordedReceipt;
}

/**
 * Encode a gRPC Length-Prefixed-Message frame:
 * `[compressed_flag: 1 byte (0 or 1)][message_length: 4 bytes uint32 BE][payload]`
 */
export function encodeGrpcFrame(payload: Buffer | Uint8Array, compressed = false): Buffer {
  const body = Buffer.from(payload);
  const header = Buffer.alloc(5);
  header.writeUInt8(compressed ? 1 : 0, 0);
  header.writeUInt32BE(body.length, 1);
  return Buffer.concat([header, body]);
}

/**
 * Decode a gRPC Length-Prefixed-Message frame (`[compressed_flag:1, length:4]`).
 */
export function decodeGrpcFrame(frame: Buffer | Uint8Array): {
  compressed: boolean;
  length: number;
  payload: Buffer;
  remaining: Buffer;
} {
  const buf = Buffer.from(frame);
  if (buf.length < 5) {
    throw new Error(`invalid gRPC frame: expected at least 5 header bytes, got ${buf.length}`);
  }
  const flag = buf.readUInt8(0);
  if (flag !== 0 && flag !== 1) {
    throw new Error(`invalid gRPC compression flag: ${flag}`);
  }
  const length = buf.readUInt32BE(1);
  if (buf.length < 5 + length) {
    throw new Error(`truncated gRPC frame: declared ${length} bytes, available ${buf.length - 5}`);
  }
  return {
    compressed: flag === 1,
    length,
    payload: buf.subarray(5, 5 + length),
    remaining: buf.subarray(5 + length),
  };
}

// Minimal protobuf wire helpers for envoy.service.auth.v3.CheckRequest / CheckResponse
function encodeVarint(n: number): Buffer {
  const bytes: number[] = [];
  let v = n >>> 0;
  while (v >= 0x80) {
    bytes.push((v & 0x7f) | 0x80);
    v >>>= 7;
  }
  bytes.push(v);
  return Buffer.from(bytes);
}

function decodeVarint(buf: Buffer, offset: number): { value: number; nextOffset: number } {
  let result = 0;
  let shift = 0;
  let i = offset;
  while (i < buf.length) {
    const b = buf[i++]!;
    result |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) {
      return { value: result >>> 0, nextOffset: i };
    }
    shift += 7;
  }
  throw new Error('truncated protobuf varint');
}

function encodeLengthDelimited(fieldNumber: number, data: Buffer | string): Buffer {
  const b = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  const tag = encodeVarint((fieldNumber << 3) | 2);
  const len = encodeVarint(b.length);
  return Buffer.concat([tag, len, b]);
}

/**
 * Encode an `EnvoyCheckRequest` into binary protobuf wire format
 * (`envoy.service.auth.v3.CheckRequest`: field 1 = attributes).
 */
export function encodeEnvoyCheckRequestProto(req: EnvoyCheckRequest): Buffer {
  const http = req.attributes?.request?.http ?? {};
  const httpParts: Buffer[] = [];
  if (http.id) httpParts.push(encodeLengthDelimited(1, http.id));
  if (http.method) httpParts.push(encodeLengthDelimited(2, http.method));
  if (http.headers) {
    for (const [k, v] of Object.entries(http.headers)) {
      const entry = Buffer.concat([encodeLengthDelimited(1, k), encodeLengthDelimited(2, v)]);
      httpParts.push(encodeLengthDelimited(3, entry));
    }
  }
  if (http.path) httpParts.push(encodeLengthDelimited(4, http.path));
  if (http.host) httpParts.push(encodeLengthDelimited(5, http.host));
  if (http.scheme) httpParts.push(encodeLengthDelimited(6, http.scheme));
  if (http.body) httpParts.push(encodeLengthDelimited(10, http.body));

  const requestMsg = encodeLengthDelimited(2, Buffer.concat(httpParts)); // Request.http = field 2
  const attrParts: Buffer[] = [encodeLengthDelimited(4, requestMsg)]; // AttributeContext.request = field 4
  if (req.attributes?.source?.principal) {
    const peer = encodeLengthDelimited(4, req.attributes.source.principal); // Peer.principal = field 4
    attrParts.push(encodeLengthDelimited(1, peer)); // AttributeContext.source = field 1
  }
  return encodeLengthDelimited(1, Buffer.concat(attrParts)); // CheckRequest.attributes = field 1
}

function parseProtoFields(buf: Buffer): Array<{ field: number; wireType: number; data: Buffer | number }> {
  const out: Array<{ field: number; wireType: number; data: Buffer | number }> = [];
  let offset = 0;
  while (offset < buf.length) {
    const tag = decodeVarint(buf, offset);
    offset = tag.nextOffset;
    const field = tag.value >>> 3;
    const wireType = tag.value & 0x07;
    if (wireType === 0) {
      const v = decodeVarint(buf, offset);
      offset = v.nextOffset;
      out.push({ field, wireType, data: v.value });
    } else if (wireType === 2) {
      const len = decodeVarint(buf, offset);
      offset = len.nextOffset;
      if (offset + len.value > buf.length) throw new Error('truncated protobuf length-delimited field');
      out.push({ field, wireType, data: buf.subarray(offset, offset + len.value) });
      offset += len.value;
    } else {
      throw new Error(`unsupported protobuf wire type ${wireType}`);
    }
  }
  return out;
}

export function decodeEnvoyCheckRequestProto(buf: Buffer): EnvoyCheckRequest {
  const top = parseProtoFields(buf);
  const attrField = top.find((f) => f.field === 1 && Buffer.isBuffer(f.data));
  if (!attrField || !Buffer.isBuffer(attrField.data)) return {};
  const attrFields = parseProtoFields(attrField.data);
  let principal: string | undefined;
  const sourceField = attrFields.find((f) => f.field === 1 && Buffer.isBuffer(f.data));
  if (sourceField && Buffer.isBuffer(sourceField.data)) {
    const peerFields = parseProtoFields(sourceField.data);
    const p = peerFields.find((f) => f.field === 4 && Buffer.isBuffer(f.data));
    if (p && Buffer.isBuffer(p.data)) principal = p.data.toString('utf8');
  }

  const reqField = attrFields.find((f) => f.field === 4 && Buffer.isBuffer(f.data));
  const httpOut: NonNullable<NonNullable<EnvoyCheckRequest['attributes']>['request']>['http'] = {};
  if (reqField && Buffer.isBuffer(reqField.data)) {
    const reqFields = parseProtoFields(reqField.data);
    const httpField = reqFields.find((f) => f.field === 2 && Buffer.isBuffer(f.data));
    if (httpField && Buffer.isBuffer(httpField.data)) {
      const hFields = parseProtoFields(httpField.data);
      const headers: Record<string, string> = {};
      for (const hf of hFields) {
        if (!Buffer.isBuffer(hf.data)) continue;
        if (hf.field === 1) httpOut.id = hf.data.toString('utf8');
        else if (hf.field === 2) httpOut.method = hf.data.toString('utf8');
        else if (hf.field === 3) {
          const kv = parseProtoFields(hf.data);
          const k = kv.find((x) => x.field === 1 && Buffer.isBuffer(x.data));
          const v = kv.find((x) => x.field === 2 && Buffer.isBuffer(x.data));
          if (k && v && Buffer.isBuffer(k.data) && Buffer.isBuffer(v.data)) {
            headers[k.data.toString('utf8')] = v.data.toString('utf8');
          }
        } else if (hf.field === 4) httpOut.path = hf.data.toString('utf8');
        else if (hf.field === 5) httpOut.host = hf.data.toString('utf8');
        else if (hf.field === 6) httpOut.scheme = hf.data.toString('utf8');
        else if (hf.field === 10) httpOut.body = hf.data.toString('utf8');
      }
      if (Object.keys(headers).length > 0) httpOut.headers = headers;
    }
  }

  return {
    attributes: {
      request: { http: httpOut },
      ...(principal ? { source: { principal } } : {}),
    },
  };
}

const FAIL_CLOSED_DECISION: AuthZenResponse = {
  decision: false,
  hivemind: {
    decision_digest: 'sha256:' + 'ff'.repeat(32),
    policy_set_digest: 'fail-closed',
    reasons: ['envoy ext_authz fail-closed: malformed request or authorization failure'],
    requires_approval: false,
  },
};

export class EnvoyExtAuthzGateway {
  constructor(
    private readonly capture: ReceiptCapture,
    private readonly opts: GatewayEnforcementOptions = {},
  ) {}

  async handleHttpCheck(checkReq: EnvoyCheckRequest): Promise<EnvoyCheckResponse> {
    const mode = this.opts.mode ?? 'enforce';
    let authZenReq;
    try {
      if (!checkReq || typeof checkReq !== 'object' || !checkReq.attributes?.request?.http) {
        throw new Error('missing attributes.request.http');
      }
      authZenReq = envoyCheckToAuthZen(checkReq);
    } catch {
      const fallbackReceipt = await this.capture.record(
        {
          method: 'http:INVALID /',
          kind: 'http',
          riskTier: 'destructive',
          args: checkReq ?? {},
          subjectId: 'anonymous',
          extensions: { 'io.hivemind.gateway': 'envoy-ext-authz', 'io.hivemind.fail_closed': true },
        },
        'denied',
        FAIL_CLOSED_DECISION,
      );
      return this.buildDeniedResponse(fallbackReceipt, FAIL_CLOSED_DECISION);
    }

    const http = checkReq.attributes?.request?.http ?? {};
    const method = (http.method ?? 'GET').toUpperCase();
    const path = http.path ?? '/';
    const rawArgs = { method, path, headers: http.headers ?? {}, ...(http.body ? { body: http.body } : {}) };
    const action: ActionDescriptor = redactActionArgs(
      {
        method: authZenReq.action.name,
        kind: 'http',
        riskTier: (authZenReq.context?.risk_tier as RiskTier | undefined) ?? classifyRisk(path),
        args: rawArgs,
        subjectId: authZenReq.subject.id,
        resourceId: path,
        extensions: { 'io.hivemind.gateway': 'envoy-ext-authz' },
      },
      this.opts,
    );

    const halted = checkGatewayHalt(this.opts, {
      agent: action.subjectId,
      workspace: http.headers?.['x-hivemind-workspace'],
      keyId: http.headers?.['x-hivemind-api-key'],
    });
    if (halted && mode === 'enforce') {
      const haltDecision = buildHaltDeniedDecision(halted);
      const receipt = await this.capture.record(action, 'blocked', haltDecision);
      return this.buildDeniedResponse(receipt, haltDecision);
    }

    if (this.opts.requirePreActionIntent && !http.headers?.['x-hivemind-intent-digest']) {
      if (mode === 'enforce') {
        const intentMissingDecision: AuthZenResponse = {
          decision: false,
          hivemind: {
            decision_digest: 'sha256:' + 'dd'.repeat(32),
            policy_set_digest: 'pre-action-intent-required',
            reasons: ['no_receipt_no_action:missing_pre_action_intent'],
            requires_approval: false,
          },
        };
        const receipt = await this.capture.record(action, 'denied', intentMissingDecision);
        return this.buildDeniedResponse(receipt, intentMissingDecision);
      }
    }

    try {
      const decision = await this.capture.authorize(action, http.headers?.['x-hivemind-approval-digest'] ?? '');
      const verdict: VerdictClass = decision.decision
        ? 'executed'
        : decision.hivemind.requires_approval
          ? 'blocked'
          : 'denied';
      const receipt = await this.capture.record(
        action,
        verdict,
        decision,
        decision.decision ? { authorized: true, method, path } : undefined,
      );
      if (!decision.decision && mode === 'enforce') {
        return this.buildDeniedResponse(receipt, decision);
      }

      const stmtB64 = (receipt.transparentStatement ?? receipt.statement).toString('base64url');
      const headers: EnvoyHeaderValueOption[] = [
        { header: { key: HEADER_DECISION_RECEIPT, value: stmtB64 }, append: false },
        { header: { key: HEADER_CAPSULE_DIGEST, value: receipt.capsule.capsule_id }, append: false },
        { header: { key: HEADER_DECISION_DIGEST, value: decision.hivemind.decision_digest }, append: false },
      ];
      return {
        status: { code: 0, message: 'OK' },
        httpStatus: 200,
        okResponse: { headers },
        receipt,
      };
    } catch {
      const receipt = await this.capture.record(action, 'denied', FAIL_CLOSED_DECISION);
      return this.buildDeniedResponse(receipt, FAIL_CLOSED_DECISION);
    }
  }

  private buildDeniedResponse(receipt: RecordedReceipt, decision: AuthZenResponse): EnvoyCheckResponse {
    const stmtB64 = (receipt.transparentStatement ?? receipt.statement).toString('base64url');
    const headers: EnvoyHeaderValueOption[] = [
      { header: { key: HEADER_DECISION_RECEIPT, value: stmtB64 }, append: false },
      { header: { key: HEADER_CAPSULE_DIGEST, value: receipt.capsule.capsule_id }, append: false },
      { header: { key: HEADER_DECISION_DIGEST, value: decision.hivemind.decision_digest }, append: false },
    ];
    return {
      status: { code: 7, message: 'PermissionDenied' },
      httpStatus: 403,
      deniedResponse: {
        status: { code: 403 },
        headers,
        body: JSON.stringify({
          error: 'denied_by_hivemind_policy',
          reasons: decision.hivemind.reasons,
          capsule_id: receipt.capsule.capsule_id,
        }),
      },
      receipt,
    };
  }

  /**
   * Handle a binary gRPC `envoy.service.auth.v3.Authorization/Check` frame
   * (`[compressed_flag:1, length:4]` + JSON or Protobuf `CheckRequest`).
   * Returns both the decoded `EnvoyCheckResponse` and the 5-byte gRPC framed response.
   */
  async handleGrpcCheck(grpcFrame: Buffer | Uint8Array): Promise<{
    frame: Buffer;
    response: EnvoyCheckResponse;
  }> {
    let checkReq: EnvoyCheckRequest;
    try {
      const decoded = decodeGrpcFrame(grpcFrame);
      const trimmed = decoded.payload.toString('utf8').trim();
      if (trimmed.startsWith('{')) {
        checkReq = JSON.parse(trimmed) as EnvoyCheckRequest;
      } else {
        checkReq = decodeEnvoyCheckRequestProto(decoded.payload);
      }
    } catch {
      const res = await this.handleHttpCheck({});
      const outBytes = Buffer.from(JSON.stringify(this.toSerializableCheckResponse(res)), 'utf8');
      return { frame: encodeGrpcFrame(outBytes, false), response: res };
    }

    const response = await this.handleHttpCheck(checkReq);
    const outBytes = Buffer.from(JSON.stringify(this.toSerializableCheckResponse(response)), 'utf8');
    return {
      frame: encodeGrpcFrame(outBytes, false),
      response,
    };
  }

  private toSerializableCheckResponse(res: EnvoyCheckResponse): Record<string, unknown> {
    return {
      status: res.status,
      httpStatus: res.httpStatus,
      ...(res.okResponse ? { okResponse: res.okResponse } : {}),
      ...(res.deniedResponse ? { deniedResponse: res.deniedResponse } : {}),
      capsule_id: res.receipt.capsule.capsule_id,
    };
  }
}

// ---------------------------------------------------------------------------
// 1b. Envoy ext_proc (envoy.service.ext_proc.v3.ExternalProcessor)
// ---------------------------------------------------------------------------

export interface EnvoyExtProcRequest {
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: unknown;
  principal?: string;
  workspace?: string;
  apiKey?: string;
  responseStatus?: number;
  responseBody?: unknown;
}

export interface EnvoyExtProcResponse {
  allowed: boolean;
  httpStatus: 200 | 403 | 503;
  reason?: string;
  headers: Record<string, string>;
  immediateResponse?: {
    status: 403 | 503;
    headers: Record<string, string>;
    body: string;
  };
  intentReceipt?: RecordedReceipt;
  receipt?: RecordedReceipt;
}

export class EnvoyExtProcGateway {
  constructor(
    private readonly capture: ReceiptCapture,
    private readonly opts: GatewayEnforcementOptions = {},
  ) {}

  async process(req: EnvoyExtProcRequest): Promise<EnvoyExtProcResponse> {
    const mode = this.opts.mode ?? 'enforce';
    const method = req.method.toUpperCase();
    const headers = req.headers ?? {};
    const action = redactActionArgs(
      {
        method: `http:${method} ${req.path}`,
        kind: 'http',
        riskTier: method === 'GET' || method === 'HEAD' ? 'read' : classifyRisk(req.path),
        args: { method, path: req.path, body: req.body ?? null },
        subjectId: req.principal ?? headers['x-hivemind-agent'] ?? 'envoy-ext-proc-caller',
        resourceId: req.path,
        extensions: { 'io.hivemind.gateway': 'envoy-ext-proc' },
      },
      this.opts,
    );

    const halted = checkGatewayHalt(this.opts, {
      agent: action.subjectId,
      workspace: req.workspace ?? headers['x-hivemind-workspace'],
      keyId: req.apiKey ?? headers['x-hivemind-api-key'],
    });
    if (halted && mode === 'enforce') {
      const haltDecision = buildHaltDeniedDecision(halted);
      let receipt: RecordedReceipt | undefined;
      try {
        receipt = await this.capture.record(action, 'blocked', haltDecision);
      } catch {
        // still block on halt
      }
      const reason = `kill_switch_active:${halted.scopeKey}:${halted.reason}`;
      return {
        allowed: false,
        httpStatus: 403,
        reason,
        headers: { 'x-hivemind-halt-scope': halted.scopeKey },
        immediateResponse: {
          status: 403,
          headers: { 'x-hivemind-halt-scope': halted.scopeKey },
          body: JSON.stringify({ error: 'kill_switch_active', scope: halted.scopeKey, reason: halted.reason }),
        },
        ...(receipt ? { receipt } : {}),
      };
    }

    try {
      const decision = await this.capture.authorize(action, headers['x-hivemind-approval-digest'] ?? '');
      if (!decision.decision && mode === 'enforce') {
        const verdict: VerdictClass = decision.hivemind.requires_approval ? 'blocked' : 'denied';
        const receipt = await this.capture.record(action, verdict, decision);
        const reason = decision.hivemind.reasons.join('; ') || 'denied_by_policy';
        return {
          allowed: false,
          httpStatus: 403,
          reason,
          headers: { [HEADER_CAPSULE_DIGEST]: receipt.capsule.capsule_id },
          immediateResponse: {
            status: 403,
            headers: { [HEADER_CAPSULE_DIGEST]: receipt.capsule.capsule_id },
            body: JSON.stringify({ error: 'denied_by_hivemind_policy', reason }),
          },
          receipt,
        };
      }

      let intentReceipt: RecordedReceipt | undefined;
      if (this.opts.requirePreActionIntent) {
        intentReceipt = await this.capture.record(
          { ...action, method: `${action.method}:intent` },
          'executed',
          decision,
          { phase: 'intent' },
        );
      }

      const redactedResp = req.responseBody
        ? applyJsonPathRedaction(req.responseBody, this.opts.redactJsonPaths)
        : { authorized: true, method, path: req.path };
      const receipt = await this.capture.record(
        action,
        req.responseStatus && req.responseStatus >= 400 ? 'errored' : 'executed',
        decision,
        redactedResp,
      );
      const stmtB64 = (receipt.transparentStatement ?? receipt.statement).toString('base64url');
      return {
        allowed: true,
        httpStatus: 200,
        headers: {
          [HEADER_DECISION_RECEIPT]: stmtB64,
          [HEADER_CAPSULE_DIGEST]: receipt.capsule.capsule_id,
          [HEADER_DECISION_DIGEST]: decision.hivemind.decision_digest,
          ...(intentReceipt ? { [HEADER_INTENT_CAPSULE_DIGEST]: intentReceipt.capsule.capsule_id } : {}),
        },
        ...(intentReceipt ? { intentReceipt } : {}),
        receipt,
      };
    } catch (err) {
      const reason = `no_receipt_no_action:${(err as Error).message}`;
      if (mode === 'enforce') {
        return {
          allowed: false,
          httpStatus: 503,
          reason,
          headers: {},
          immediateResponse: {
            status: 503,
            headers: {},
            body: JSON.stringify({ error: 'no_receipt_no_action', reason }),
          },
        };
      }
      return { allowed: true, httpStatus: 200, reason: 'observe_mode_passthrough', headers: {} };
    }
  }
}

// ---------------------------------------------------------------------------
// 1c. Cloudflare Worker Gateway
// ---------------------------------------------------------------------------

export interface CloudflareWorkerRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: unknown;
  agentId?: string;
  workspace?: string;
  apiKey?: string;
}

export interface CloudflareWorkerResponse {
  allowed: boolean;
  status: 200 | 403 | 503;
  reason?: string;
  headers: Record<string, string>;
  body: unknown;
  intentReceipt?: RecordedReceipt;
  receipt?: RecordedReceipt;
}

export class CloudflareWorkerGateway {
  constructor(
    private readonly capture: ReceiptCapture,
    private readonly opts: GatewayEnforcementOptions = {},
  ) {}

  async fetch(
    req: CloudflareWorkerRequest,
    upstream?: (req: CloudflareWorkerRequest) => Promise<{ status: number; headers?: Record<string, string>; body?: unknown }>,
  ): Promise<CloudflareWorkerResponse> {
    const mode = this.opts.mode ?? 'enforce';
    const headers = req.headers ?? {};
    const method = req.method.toUpperCase();
    const action = redactActionArgs(
      {
        method: `http:${method} ${req.url}`,
        kind: 'http',
        riskTier: method === 'GET' || method === 'HEAD' ? 'read' : classifyRisk(req.url),
        args: { method, url: req.url, body: req.body ?? null },
        subjectId: req.agentId ?? headers['x-hivemind-agent'] ?? 'cf-worker-agent',
        resourceId: req.url,
        extensions: { 'io.hivemind.gateway': 'cloudflare-worker' },
      },
      this.opts,
    );

    const halted = checkGatewayHalt(this.opts, {
      agent: action.subjectId,
      workspace: req.workspace ?? headers['x-hivemind-workspace'],
      keyId: req.apiKey ?? headers['x-hivemind-api-key'],
    });
    if (halted && mode === 'enforce') {
      const haltDecision = buildHaltDeniedDecision(halted);
      let receipt: RecordedReceipt | undefined;
      try {
        receipt = await this.capture.record(action, 'blocked', haltDecision);
      } catch {
        // block even if recording fails
      }
      const reason = `kill_switch_active:${halted.scopeKey}:${halted.reason}`;
      return {
        allowed: false,
        status: 403,
        reason,
        headers: { 'x-hivemind-halt-scope': halted.scopeKey },
        body: { error: 'kill_switch_active', scope: halted.scopeKey, reason: halted.reason },
        ...(receipt ? { receipt } : {}),
      };
    }

    try {
      const decision = await this.capture.authorize(action, headers['x-hivemind-approval-digest'] ?? '');
      if (!decision.decision && mode === 'enforce') {
        const verdict: VerdictClass = decision.hivemind.requires_approval ? 'blocked' : 'denied';
        const receipt = await this.capture.record(action, verdict, decision);
        const reason = decision.hivemind.reasons.join('; ') || 'denied_by_policy';
        return {
          allowed: false,
          status: 403,
          reason,
          headers: { [HEADER_CAPSULE_DIGEST]: receipt.capsule.capsule_id },
          body: { error: 'denied_by_hivemind_policy', reason },
          receipt,
        };
      }

      let intentReceipt: RecordedReceipt | undefined;
      if (this.opts.requirePreActionIntent) {
        intentReceipt = await this.capture.record(
          { ...action, method: `${action.method}:intent` },
          'executed',
          decision,
          { phase: 'intent' },
        );
      }

      const upstreamRes = upstream
        ? await upstream(req)
        : { status: 200, body: { ok: true } };

      const redactedResp = applyJsonPathRedaction(upstreamRes.body ?? { status: upstreamRes.status }, this.opts.redactJsonPaths);
      const receipt = await this.capture.record(
        action,
        upstreamRes.status < 400 ? 'executed' : 'errored',
        decision,
        redactedResp,
      );
      const stmtB64 = (receipt.transparentStatement ?? receipt.statement).toString('base64url');
      return {
        allowed: true,
        status: 200,
        headers: {
          ...(upstreamRes.headers ?? {}),
          [HEADER_DECISION_RECEIPT]: stmtB64,
          [HEADER_CAPSULE_DIGEST]: receipt.capsule.capsule_id,
          [HEADER_DECISION_DIGEST]: decision.hivemind.decision_digest,
        },
        body: upstreamRes.body,
        ...(intentReceipt ? { intentReceipt } : {}),
        receipt,
      };
    } catch (err) {
      const reason = `no_receipt_no_action:${(err as Error).message}`;
      if (mode === 'enforce') {
        return {
          allowed: false,
          status: 503,
          reason,
          headers: {},
          body: { error: 'no_receipt_no_action', reason },
        };
      }
      const upstreamRes = upstream ? await upstream(req) : { status: 200, body: { ok: true } };
      return {
        allowed: true,
        status: 200,
        reason: 'observe_mode_passthrough',
        headers: upstreamRes.headers ?? {},
        body: upstreamRes.body,
      };
    }
  }
}

// ---------------------------------------------------------------------------
// 2. agentgateway Plugin (MCP & A2A traffic interceptor)
// ---------------------------------------------------------------------------

export interface AgentGatewayRequest {
  protocol: 'mcp' | 'a2a';
  method: string;
  toolName?: string;
  payload: unknown;
  principal?: string;
  workspace?: string;
  apiKey?: string;
  headers?: Record<string, string>;
}

export class AgentGatewayPlugin {
  constructor(
    private readonly capture: ReceiptCapture,
    private readonly opts: GatewayEnforcementOptions = {},
  ) {}

  async onRequest(req: AgentGatewayRequest): Promise<{
    allow: boolean;
    allowed: boolean;
    status: 200 | 403 | 503;
    reason?: string;
    headers: Record<string, string>;
    decision: AuthZenResponse;
    action: ActionDescriptor;
    intentReceipt?: RecordedReceipt;
    receipt?: RecordedReceipt;
  }> {
    const mode = this.opts.mode ?? 'enforce';
    const method =
      req.protocol === 'mcp' && req.toolName ? `tools/call:${req.toolName}` : req.method;
    const action: ActionDescriptor = redactActionArgs(
      {
        method,
        kind: req.protocol,
        riskTier: classifyRisk(method),
        args: req.payload,
        subjectId: req.principal ?? 'agentgateway-caller',
        extensions: { 'io.hivemind.gateway': 'agentgateway', 'io.hivemind.protocol': req.protocol },
      },
      this.opts,
    );

    const halted = checkGatewayHalt(this.opts, {
      agent: action.subjectId,
      workspace: req.workspace ?? req.headers?.['x-hivemind-workspace'],
      keyId: req.apiKey ?? req.headers?.['x-hivemind-api-key'],
    });
    if (halted && mode === 'enforce') {
      const decision = buildHaltDeniedDecision(halted);
      let receipt: RecordedReceipt | undefined;
      try {
        receipt = await this.capture.record(action, 'blocked', decision);
      } catch {
        // block even if receipt fails
      }
      return {
        allow: false,
        allowed: false,
        status: 403,
        reason: `kill_switch_active:${halted.scopeKey}:${halted.reason}`,
        headers: { 'x-hivemind-halt-scope': halted.scopeKey },
        decision,
        action,
        ...(receipt ? { receipt } : {}),
      };
    }

    try {
      const decision = await this.capture.authorize(action, req.headers?.['x-hivemind-approval-digest'] ?? '');
      if (!decision.decision && mode === 'enforce') {
        const verdict: VerdictClass = decision.hivemind.requires_approval ? 'blocked' : 'denied';
        const receipt = await this.capture.record(action, verdict, decision);
        return {
          allow: false,
          allowed: false,
          status: 403,
          reason: decision.hivemind.reasons.join('; '),
          headers: {
            [HEADER_CAPSULE_DIGEST]: receipt.capsule.capsule_id,
            [HEADER_DECISION_RECEIPT]: (receipt.transparentStatement ?? receipt.statement).toString('base64url'),
            [HEADER_DECISION_DIGEST]: decision.hivemind.decision_digest,
          },
          decision,
          action,
          receipt,
        };
      }
      let intentReceipt: RecordedReceipt | undefined;
      if (this.opts.requirePreActionIntent) {
        intentReceipt = await this.capture.record(
          { ...action, method: `${action.method}:intent` },
          'executed',
          decision,
          { phase: 'intent' },
        );
      }
      return {
        allow: true,
        allowed: true,
        status: 200,
        headers: {
          [HEADER_DECISION_DIGEST]: decision.hivemind.decision_digest,
          ...(intentReceipt ? { [HEADER_INTENT_CAPSULE_DIGEST]: intentReceipt.capsule.capsule_id } : {}),
        },
        decision,
        action,
        ...(intentReceipt ? { intentReceipt } : {}),
      };
    } catch (err) {
      const reason = `no_receipt_no_action:${(err as Error).message}`;
      if (mode === 'enforce') {
        return {
          allow: false,
          allowed: false,
          status: 503,
          reason,
          headers: {},
          decision: FAIL_CLOSED_DECISION,
          action,
        };
      }
      return {
        allow: true,
        allowed: true,
        status: 200,
        reason: 'observe_mode_passthrough',
        headers: {},
        decision: FAIL_CLOSED_DECISION,
        action,
      };
    }
  }

  async onResponse(
    pre: { action: ActionDescriptor; decision: AuthZenResponse },
    res: { statusOk: boolean; body: Record<string, unknown> },
  ): Promise<{
    receipt: RecordedReceipt;
    headers: Record<string, string>;
    body: Record<string, unknown>;
  }> {
    const verdict: VerdictClass = res.statusOk ? 'executed' : 'errored';
    const redactedBody = applyJsonPathRedaction(res.body, this.opts.redactJsonPaths);
    const receipt = await this.capture.record(
      pre.action,
      verdict,
      pre.decision,
      res.statusOk ? redactedBody : undefined,
    );
    const stmtB64 = (receipt.transparentStatement ?? receipt.statement).toString('base64url');
    return {
      receipt,
      headers: {
        [HEADER_CAPSULE_DIGEST]: receipt.capsule.capsule_id,
        [HEADER_DECISION_RECEIPT]: stmtB64,
        [HEADER_DECISION_DIGEST]: pre.decision.hivemind.decision_digest,
      },
      body: {
        ...res.body,
        _meta: {
          ...((res.body['_meta'] as Record<string, unknown> | undefined) ?? {}),
          ...mcpReceiptMeta(receipt),
        },
      },
    };
  }
}

// ---------------------------------------------------------------------------
// 3. Kong Gateway Plugin
// ---------------------------------------------------------------------------

export interface KongRequestContext {
  method: string;
  path: string;
  headers: Record<string, string>;
  body?: unknown;
  consumer?: { id: string; username?: string };
  workspace?: string;
  apiKey?: string;
}

export class KongReceiptsPlugin {
  constructor(
    private readonly capture: ReceiptCapture,
    private readonly opts: GatewayEnforcementOptions = {},
  ) {}

  async access(ctx: KongRequestContext): Promise<{
    allowed: boolean;
    exitStatus: 403 | 503 | null;
    reason?: string;
    headers: Record<string, string>;
    body?: Record<string, unknown>;
    action: ActionDescriptor;
    decision: AuthZenResponse;
    intentReceipt?: RecordedReceipt;
    receipt?: RecordedReceipt;
  }> {
    const mode = this.opts.mode ?? 'enforce';
    const method = ctx.method.toUpperCase();
    const action: ActionDescriptor = redactActionArgs(
      {
        method: `http:${method} ${ctx.path}`,
        kind: 'http',
        riskTier: method === 'GET' || method === 'HEAD' ? 'read' : classifyRisk(ctx.path),
        args: { method, path: ctx.path, body: ctx.body ?? null },
        subjectId: ctx.consumer?.username ?? ctx.consumer?.id ?? 'kong-anonymous',
        resourceId: ctx.path,
        extensions: { 'io.hivemind.gateway': 'kong' },
      },
      this.opts,
    );

    const halted = checkGatewayHalt(this.opts, {
      agent: action.subjectId,
      workspace: ctx.workspace ?? ctx.headers['x-hivemind-workspace'],
      keyId: ctx.apiKey ?? ctx.headers['x-hivemind-api-key'],
    });
    if (halted && mode === 'enforce') {
      const decision = buildHaltDeniedDecision(halted);
      let receipt: RecordedReceipt | undefined;
      try {
        receipt = await this.capture.record(action, 'blocked', decision);
      } catch {
        // block even if receipt fails
      }
      const reason = `kill_switch_active:${halted.scopeKey}:${halted.reason}`;
      return {
        allowed: false,
        exitStatus: 403,
        reason,
        headers: { 'x-hivemind-halt-scope': halted.scopeKey },
        body: {
          message: 'Blocked by Hivemind Kill Switch',
          scope: halted.scopeKey,
          reasons: decision.hivemind.reasons,
        },
        action,
        decision,
        ...(receipt ? { receipt } : {}),
      };
    }

    try {
      const decision = await this.capture.authorize(action, ctx.headers['x-hivemind-approval-digest'] ?? '');
      if (!decision.decision && mode === 'enforce') {
        const verdict: VerdictClass = decision.hivemind.requires_approval ? 'blocked' : 'denied';
        const receipt = await this.capture.record(action, verdict, decision);
        const stmtB64 = (receipt.transparentStatement ?? receipt.statement).toString('base64url');
        return {
          allowed: false,
          exitStatus: 403,
          reason: decision.hivemind.reasons.join('; '),
          headers: {
            [HEADER_DECISION_RECEIPT]: stmtB64,
            [HEADER_CAPSULE_DIGEST]: receipt.capsule.capsule_id,
            [HEADER_DECISION_DIGEST]: decision.hivemind.decision_digest,
          },
          body: {
            message: 'Blocked by Hivemind Receipts policy',
            capsule_id: receipt.capsule.capsule_id,
            reasons: decision.hivemind.reasons,
          },
          action,
          decision,
          receipt,
        };
      }
      let intentReceipt: RecordedReceipt | undefined;
      if (this.opts.requirePreActionIntent) {
        intentReceipt = await this.capture.record(
          { ...action, method: `${action.method}:intent` },
          'executed',
          decision,
          { phase: 'intent' },
        );
      }
      return {
        allowed: true,
        exitStatus: null,
        headers: {
          [HEADER_DECISION_DIGEST]: decision.hivemind.decision_digest,
          ...(intentReceipt ? { [HEADER_INTENT_CAPSULE_DIGEST]: intentReceipt.capsule.capsule_id } : {}),
        },
        action,
        decision,
        ...(intentReceipt ? { intentReceipt } : {}),
      };
    } catch (err) {
      const reason = `no_receipt_no_action:${(err as Error).message}`;
      if (mode === 'enforce') {
        return {
          allowed: false,
          exitStatus: 503,
          reason,
          headers: {},
          body: { message: 'Blocked: no receipt, no action', reason },
          action,
          decision: FAIL_CLOSED_DECISION,
        };
      }
      return {
        allowed: true,
        exitStatus: null,
        reason: 'observe_mode_passthrough',
        headers: {},
        action,
        decision: FAIL_CLOSED_DECISION,
      };
    }
  }

  async response(
    accessOut: { action: ActionDescriptor; decision: AuthZenResponse },
    upstream: { status: number; body?: unknown },
  ): Promise<{
    headers: Record<string, string>;
    receipt: RecordedReceipt;
  }> {
    const ok = upstream.status >= 200 && upstream.status < 400;
    const redactedBody = applyJsonPathRedaction(
      upstream.body ?? { status: upstream.status },
      this.opts.redactJsonPaths,
    );
    const receipt = await this.capture.record(
      accessOut.action,
      ok ? 'executed' : 'errored',
      accessOut.decision,
      ok ? redactedBody : undefined,
    );
    return {
      headers: {
        [HEADER_DECISION_RECEIPT]: (receipt.transparentStatement ?? receipt.statement).toString('base64url'),
        [HEADER_CAPSULE_DIGEST]: receipt.capsule.capsule_id,
        [HEADER_DECISION_DIGEST]: accessOut.decision.hivemind.decision_digest,
      },
      receipt,
    };
  }
}

// ---------------------------------------------------------------------------
// 4. Gravitee Gateway Policy
// ---------------------------------------------------------------------------

export interface GraviteeExecutionContext {
  method: string;
  path: string;
  headers: Record<string, string>;
  attributes: Record<string, unknown>;
  payload?: unknown;
  user?: string;
  workspace?: string;
  apiKey?: string;
}

export class GraviteeReceiptsPolicy {
  constructor(
    private readonly capture: ReceiptCapture,
    private readonly opts: GatewayEnforcementOptions = {},
  ) {}

  async onRequest(ctx: GraviteeExecutionContext): Promise<{
    allowed: boolean;
    state: 'CONTINUE' | 'FAILURE';
    statusCode: 200 | 403 | 503;
    reason?: string;
    headers: Record<string, string>;
    action: ActionDescriptor;
    decision: AuthZenResponse;
    intentReceipt?: RecordedReceipt;
    receipt?: RecordedReceipt;
  }> {
    const mode = this.opts.mode ?? 'enforce';
    const method = ctx.method.toUpperCase();
    const action: ActionDescriptor = redactActionArgs(
      {
        method: `http:${method} ${ctx.path}`,
        kind: 'http',
        riskTier: method === 'GET' || method === 'HEAD' ? 'read' : classifyRisk(ctx.path),
        args: { method, path: ctx.path, payload: ctx.payload ?? null },
        subjectId: ctx.user ?? 'gravitee-anonymous',
        resourceId: ctx.path,
        extensions: { 'io.hivemind.gateway': 'gravitee' },
      },
      this.opts,
    );

    const halted = checkGatewayHalt(this.opts, {
      agent: action.subjectId,
      workspace: ctx.workspace ?? ctx.headers['x-hivemind-workspace'],
      keyId: ctx.apiKey ?? ctx.headers['x-hivemind-api-key'],
    });
    if (halted && mode === 'enforce') {
      const decision = buildHaltDeniedDecision(halted);
      let receipt: RecordedReceipt | undefined;
      try {
        receipt = await this.capture.record(action, 'blocked', decision);
      } catch {
        // block even if receipt fails
      }
      return {
        allowed: false,
        state: 'FAILURE',
        statusCode: 403,
        reason: `kill_switch_active:${halted.scopeKey}:${halted.reason}`,
        headers: { 'x-hivemind-halt-scope': halted.scopeKey },
        action,
        decision,
        ...(receipt ? { receipt } : {}),
      };
    }

    try {
      const decision = await this.capture.authorize(action, ctx.headers['x-hivemind-approval-digest'] ?? '');
      if (!decision.decision && mode === 'enforce') {
        const verdict: VerdictClass = decision.hivemind.requires_approval ? 'blocked' : 'denied';
        const receipt = await this.capture.record(action, verdict, decision);
        ctx.attributes['hivemind.receipt_id'] = receipt.capsule.capsule_id;
        return {
          allowed: false,
          state: 'FAILURE',
          statusCode: 403,
          reason: decision.hivemind.reasons.join('; '),
          headers: {
            [HEADER_CAPSULE_DIGEST]: receipt.capsule.capsule_id,
            [HEADER_DECISION_RECEIPT]: (receipt.transparentStatement ?? receipt.statement).toString('base64url'),
          },
          action,
          decision,
          receipt,
        };
      }
      let intentReceipt: RecordedReceipt | undefined;
      if (this.opts.requirePreActionIntent) {
        intentReceipt = await this.capture.record(
          { ...action, method: `${action.method}:intent` },
          'executed',
          decision,
          { phase: 'intent' },
        );
      }
      return {
        allowed: true,
        state: 'CONTINUE',
        statusCode: 200,
        headers: { [HEADER_DECISION_DIGEST]: decision.hivemind.decision_digest },
        action,
        decision,
        ...(intentReceipt ? { intentReceipt } : {}),
      };
    } catch (err) {
      const reason = `no_receipt_no_action:${(err as Error).message}`;
      if (mode === 'enforce') {
        return {
          allowed: false,
          state: 'FAILURE',
          statusCode: 503,
          reason,
          headers: {},
          action,
          decision: FAIL_CLOSED_DECISION,
        };
      }
      return {
        allowed: true,
        state: 'CONTINUE',
        statusCode: 200,
        reason: 'observe_mode_passthrough',
        headers: {},
        action,
        decision: FAIL_CLOSED_DECISION,
      };
    }
  }

  async onResponse(
    reqOut: { action: ActionDescriptor; decision: AuthZenResponse },
    res: { statusCode: number; payload?: unknown },
  ): Promise<{
    headers: Record<string, string>;
    receipt: RecordedReceipt;
  }> {
    const ok = res.statusCode >= 200 && res.statusCode < 400;
    const redactedPayload = applyJsonPathRedaction(
      res.payload ?? { statusCode: res.statusCode },
      this.opts.redactJsonPaths,
    );
    const receipt = await this.capture.record(
      reqOut.action,
      ok ? 'executed' : 'errored',
      reqOut.decision,
      ok ? redactedPayload : undefined,
    );
    return {
      headers: {
        [HEADER_CAPSULE_DIGEST]: receipt.capsule.capsule_id,
        [HEADER_DECISION_RECEIPT]: (receipt.transparentStatement ?? receipt.statement).toString('base64url'),
      },
      receipt,
    };
  }
}

// ---------------------------------------------------------------------------
// 5. LiteLLM Proxy Callbacks (pre_call_hook / post_call_success_hook / post_call_failure_hook)
// ---------------------------------------------------------------------------

export interface LiteLLMCallData {
  model: string;
  messages: unknown[];
  tools?: Array<{ function?: { name?: string } }>;
  user?: string;
  call_type?: string;
  metadata?: Record<string, unknown>;
}

export class LiteLLMReceiptsHook {
  constructor(
    private readonly capture: ReceiptCapture,
    private readonly opts: GatewayEnforcementOptions = {},
  ) {}

  private buildAction(data: LiteLLMCallData): ActionDescriptor {
    const toolNames = (data.tools ?? [])
      .map((t) => t.function?.name)
      .filter((n): n is string => Boolean(n));
    const method = toolNames.length > 0 ? `litellm.tools:${toolNames.join(',')}` : `litellm.completion:${data.model}`;
    return redactActionArgs(
      {
        method,
        kind: 'other',
        riskTier: toolNames.length > 0 ? classifyRisk(toolNames.join(' ')) : 'read',
        args: { model: data.model, messages: data.messages, tools: data.tools ?? [] },
        subjectId: data.user ?? 'litellm-user',
        model: { provider: 'litellm', model_id: data.model },
        extensions: {
          'io.hivemind.gateway': 'litellm',
          ...(data.call_type ? { 'io.hivemind.call_type': data.call_type } : {}),
        },
      },
      this.opts,
    );
  }

  async pre_call_hook(data: LiteLLMCallData): Promise<{
    allowed: boolean;
    status: 200 | 403 | 503;
    reason?: string;
    decision: AuthZenResponse;
    data: LiteLLMCallData;
    intentReceipt?: RecordedReceipt;
    receipt?: RecordedReceipt;
  }> {
    const mode = this.opts.mode ?? 'enforce';
    const action = this.buildAction(data);
    const halted = checkGatewayHalt(this.opts, {
      agent: action.subjectId,
      workspace: data.metadata?.['workspace'] as string | undefined,
      keyId: data.metadata?.['api_key'] as string | undefined,
    });
    if (halted && mode === 'enforce') {
      const decision = buildHaltDeniedDecision(halted);
      let receipt: RecordedReceipt | undefined;
      try {
        receipt = await this.capture.record(action, 'blocked', decision);
      } catch {
        // block even if receipt fails
      }
      return {
        allowed: false,
        status: 403,
        reason: `kill_switch_active:${halted.scopeKey}:${halted.reason}`,
        decision,
        data,
        ...(receipt ? { receipt } : {}),
      };
    }

    try {
      const approvalDigest = String(data.metadata?.['approval_digest'] ?? '');
      const decision = await this.capture.authorize(action, approvalDigest);
      data.metadata = {
        ...(data.metadata ?? {}),
        hivemind_decision: decision,
        hivemind_action: action,
      };
      if (!decision.decision && mode === 'enforce') {
        const verdict: VerdictClass = decision.hivemind.requires_approval ? 'blocked' : 'denied';
        const receipt = await this.capture.record(action, verdict, decision);
        data.metadata['hivemind_receipt_id'] = receipt.capsule.capsule_id;
        return {
          allowed: false,
          status: 403,
          reason: decision.hivemind.reasons.join('; '),
          decision,
          data,
          receipt,
        };
      }
      let intentReceipt: RecordedReceipt | undefined;
      if (this.opts.requirePreActionIntent) {
        intentReceipt = await this.capture.record(
          { ...action, method: `${action.method}:intent` },
          'executed',
          decision,
          { phase: 'intent' },
        );
      }
      return { allowed: true, status: 200, decision, data, ...(intentReceipt ? { intentReceipt } : {}) };
    } catch (err) {
      const reason = `no_receipt_no_action:${(err as Error).message}`;
      if (mode === 'enforce') {
        return { allowed: false, status: 503, reason, decision: FAIL_CLOSED_DECISION, data };
      }
      return {
        allowed: true,
        status: 200,
        reason: 'observe_mode_passthrough',
        decision: FAIL_CLOSED_DECISION,
        data,
      };
    }
  }

  async post_call_success_hook(
    data: LiteLLMCallData,
    response: { id?: string; model?: string; choices?: unknown[]; usage?: unknown },
  ): Promise<{
    receipt: RecordedReceipt;
    headers: Record<string, string>;
  }> {
    const action = (data.metadata?.['hivemind_action'] as ActionDescriptor | undefined) ?? this.buildAction(data);
    if (response.id) {
      action.model = {
        ...(action.model ?? {}),
        provider: 'litellm',
        model_id: response.model ?? data.model,
        provider_request_id: response.id,
      };
    }
    const decision =
      (data.metadata?.['hivemind_decision'] as AuthZenResponse | undefined) ??
      (await this.capture.authorize(action));
    const redactedResponse = applyJsonPathRedaction(response, this.opts.redactJsonPaths);
    const receipt = await this.capture.record(action, 'executed', decision, redactedResponse);
    return {
      receipt,
      headers: {
        [HEADER_CAPSULE_DIGEST]: receipt.capsule.capsule_id,
        [HEADER_DECISION_RECEIPT]: (receipt.transparentStatement ?? receipt.statement).toString('base64url'),
      },
    };
  }

  async post_call_failure_hook(
    data: LiteLLMCallData,
    error: Error | string,
  ): Promise<{
    receipt: RecordedReceipt;
    headers: Record<string, string>;
  }> {
    const action = (data.metadata?.['hivemind_action'] as ActionDescriptor | undefined) ?? this.buildAction(data);
    const decision =
      (data.metadata?.['hivemind_decision'] as AuthZenResponse | undefined) ??
      (await this.capture.authorize(action));
    const errMsg = typeof error === 'string' ? error : error.message;
    const verdict: VerdictClass = /timeout|timed out/i.test(errMsg) ? 'timed_out' : 'errored';
    const receipt = await this.capture.record(action, verdict, decision);
    return {
      receipt,
      headers: {
        [HEADER_CAPSULE_DIGEST]: receipt.capsule.capsule_id,
        [HEADER_DECISION_RECEIPT]: (receipt.transparentStatement ?? receipt.statement).toString('base64url'),
      },
    };
  }
}

// ---------------------------------------------------------------------------
// 6. Portkey Gateway Guardrail / Webhook Handler
// ---------------------------------------------------------------------------

export interface PortkeyGuardrailHookInput {
  eventType: 'beforeRequestHook' | 'afterRequestHook';
  provider?: string;
  model?: string;
  request: {
    method?: string;
    url?: string;
    body?: Record<string, unknown>;
    headers?: Record<string, string>;
  };
  response?: {
    status?: number;
    body?: Record<string, unknown>;
  };
}

export class PortkeyReceiptsGuardrail {
  constructor(
    private readonly capture: ReceiptCapture,
    private readonly opts: GatewayEnforcementOptions = {},
  ) {}

  async handleWebhook(input: PortkeyGuardrailHookInput): Promise<{
    allowed: boolean;
    verdict: boolean;
    status: 200 | 403 | 503;
    reason?: string;
    headers: Record<string, string>;
    intentReceipt?: RecordedReceipt;
    receipt?: RecordedReceipt;
  }> {
    const mode = this.opts.mode ?? 'enforce';
    const toolCallName = String(
      (input.request.body?.['tool_name'] as string | undefined) ??
        input.request.url ??
        `portkey:${input.model ?? 'default'}`,
    );
    const action: ActionDescriptor = redactActionArgs(
      {
        method: toolCallName,
        kind: 'http',
        riskTier: classifyRisk(toolCallName),
        args: input.request.body ?? {},
        subjectId: input.request.headers?.['x-portkey-user'] ?? 'portkey-agent',
        ...(input.model
          ? { model: { provider: input.provider ?? 'portkey', model_id: input.model } }
          : {}),
        extensions: {
          'io.hivemind.gateway': 'portkey',
          'io.hivemind.hook_event': input.eventType,
        },
      },
      this.opts,
    );

    const halted = checkGatewayHalt(this.opts, {
      agent: action.subjectId,
      workspace: input.request.headers?.['x-portkey-workspace'] ?? input.request.headers?.['x-hivemind-workspace'],
      keyId: input.request.headers?.['x-portkey-api-key'] ?? input.request.headers?.['x-hivemind-api-key'],
    });
    if (halted && mode === 'enforce') {
      const decision = buildHaltDeniedDecision(halted);
      let receipt: RecordedReceipt | undefined;
      try {
        receipt = await this.capture.record(action, 'blocked', decision);
      } catch {
        // block even if receipt fails
      }
      return {
        allowed: false,
        verdict: false,
        status: 403,
        reason: `kill_switch_active:${halted.scopeKey}:${halted.reason}`,
        headers: { 'x-hivemind-halt-scope': halted.scopeKey },
        ...(receipt ? { receipt } : {}),
      };
    }

    try {
      const decision = await this.capture.authorize(
        action,
        input.request.headers?.['x-hivemind-approval-digest'] ?? '',
      );

      let verdictClass: VerdictClass;
      let observed: unknown;
      if (!decision.decision) {
        verdictClass = decision.hivemind.requires_approval ? 'blocked' : 'denied';
      } else if (input.eventType === 'afterRequestHook' && input.response) {
        const ok = (input.response.status ?? 200) < 400;
        verdictClass = ok ? 'executed' : 'errored';
        if (ok) {
          observed = applyJsonPathRedaction(
            input.response.body ?? { status: input.response.status ?? 200 },
            this.opts.redactJsonPaths,
          );
        }
      } else {
        verdictClass = 'executed';
        observed = { hook: 'beforeRequestHook', allowed: true };
      }

      let intentReceipt: RecordedReceipt | undefined;
      if (this.opts.requirePreActionIntent && decision.decision) {
        intentReceipt = await this.capture.record(
          { ...action, method: `${action.method}:intent` },
          'executed',
          decision,
          { phase: 'intent' },
        );
      }

      const receipt = await this.capture.record(action, verdictClass, decision, observed);
      const stmtB64 = (receipt.transparentStatement ?? receipt.statement).toString('base64url');
      const allowed = mode === 'observe' ? true : decision.decision;
      return {
        allowed,
        verdict: allowed,
        status: allowed ? 200 : 403,
        ...(!allowed ? { reason: decision.hivemind.reasons.join('; ') } : {}),
        headers: {
          'x-portkey-hivemind-receipt': receipt.capsule.capsule_id,
          [HEADER_CAPSULE_DIGEST]: receipt.capsule.capsule_id,
          [HEADER_DECISION_RECEIPT]: stmtB64,
        },
        ...(intentReceipt ? { intentReceipt } : {}),
        receipt,
      };
    } catch (err) {
      const reason = `no_receipt_no_action:${(err as Error).message}`;
      if (mode === 'enforce') {
        return {
          allowed: false,
          verdict: false,
          status: 503,
          reason,
          headers: {},
        };
      }
      return {
        allowed: true,
        verdict: true,
        status: 200,
        reason: 'observe_mode_passthrough',
        headers: {},
      };
    }
  }
}
