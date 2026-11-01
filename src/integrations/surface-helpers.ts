// SPDX-License-Identifier: Apache-2.0
/**
 * Open integration surface helpers for MCP, Envoy ext_authz, and OpenTelemetry GenAI spans.
 */
import { createHash } from 'node:crypto';
import type { RiskTier, VerdictClass } from '../core/capsule.js';
import type { AuthZenRequest } from '../authz/authzen-types.js';
import type { ActionDescriptor, RecordedReceipt } from './capture.js';

export type EnforcementMode = 'observe' | 'enforce';

export const OTEL_RECEIPT_ATTRIBUTE = 'hivemind.receipt_id';
export const MCP_RECEIPT_META_KEY = 'io.hivemind/receipt_id';
export const MCP_EXTENSION_ID = 'io.hivemind/receipts';

export function applyJsonPathRedaction<T>(value: T, jsonPaths?: readonly string[]): T {
  if (!jsonPaths || jsonPaths.length === 0 || value === null || typeof value !== 'object') {
    return value;
  }
  const cloned = JSON.parse(JSON.stringify(value)) as T;
  for (const rawPath of jsonPaths) {
    const normalized = rawPath.trim().replace(/^\$\.?/, '');
    if (!normalized) continue;
    const segments = normalized.split('.').filter(Boolean);
    let cur: Record<string, unknown> | undefined = cloned as unknown as Record<string, unknown>;
    for (let i = 0; i < segments.length - 1; i++) {
      const next = cur?.[segments[i]!];
      if (!next || typeof next !== 'object') {
        cur = undefined;
        break;
      }
      cur = next as Record<string, unknown>;
    }
    const last = segments[segments.length - 1];
    if (cur && last && last in cur) {
      const digest = createHash('sha256').update(JSON.stringify(cur[last])).digest('hex');
      cur[last] = { $redacted: `sha256:${digest}` };
    }
  }
  return cloned;
}

export interface OtelSpan {
  trace_id: string;
  span_id: string;
  name: string;
  attributes: Record<string, string | number | boolean>;
  status?: 'ok' | 'error';
  parent_span_id?: string;
}

export function classifyRisk(methodOrTool: string): RiskTier {
  const m = methodOrTool.toLowerCase();
  if (/(refund|charge|pay|billing|invoice|transfer|payout)/.test(m)) return 'financial';
  if (/(delete|destroy|drop|purge|remove|wipe|terminate)/.test(m)) return 'destructive';
  if (/(email|send|post|publish|message|notify|sms|tweet)/.test(m)) return 'external_communication';
  if (/(create|update|write|edit|set|put|patch|upload|merge)/.test(m)) return 'write';
  return 'read';
}

export function mcpReceiptMeta(receipt: RecordedReceipt, traceparent?: string): Record<string, unknown> {
  return {
    [MCP_RECEIPT_META_KEY]: receipt.capsule.capsule_id,
    ...(traceparent ? { traceparent } : {}),
  };
}

export function envoyCheckToAuthZen(check: {
  attributes?: {
    request?: { http?: { method?: string; path?: string; headers?: Record<string, string> } };
    source?: { principal?: string };
  };
}): AuthZenRequest {
  const http = check.attributes?.request?.http ?? {};
  const method = (http.method ?? 'GET').toUpperCase();
  const reqPath = http.path ?? '/';
  return {
    subject: { type: 'Agent', id: check.attributes?.source?.principal ?? 'anonymous' },
    action: { name: `http:${method} ${reqPath}` },
    resource: { type: 'HttpEndpoint', id: reqPath },
    context: { risk_tier: method === 'GET' || method === 'HEAD' ? 'read' : classifyRisk(reqPath), kill_switch: false },
  };
}

export function otelSpanToAction(span: OtelSpan, body?: { args?: unknown; response?: unknown }): {
  action: ActionDescriptor;
  verdict: VerdictClass;
  observed?: unknown;
} | null {
  const op = String(span.attributes['gen_ai.operation.name'] ?? '');
  if (!['execute_tool', 'invoke_agent'].includes(op) && !span.name.startsWith('execute_tool')) return null;
  const toolName = String(span.attributes['gen_ai.tool.name'] ?? span.name.replace(/^execute_tool\s+/, ''));
  const isMcp = String(span.attributes['mcp.method.name'] ?? '') === 'tools/call' || span.attributes['gen_ai.system'] === 'mcp';
  const errored = span.status === 'error';
  return {
    action: {
      method: isMcp ? `tools/call:${toolName}` : toolName,
      kind: isMcp ? 'mcp' : 'tool',
      riskTier: classifyRisk(toolName),
      args: body?.args ?? span.attributes['gen_ai.tool.call.arguments'] ?? {},
      ...(span.attributes['gen_ai.agent.id'] ? { agent: { spiffe_id: String(span.attributes['gen_ai.agent.id']) } } : {}),
      ...(span.attributes['gen_ai.request.model']
        ? { model: { provider: String(span.attributes['gen_ai.system'] ?? ''), model_id: String(span.attributes['gen_ai.request.model']) } }
        : {}),
      causality: {
        trace_id: span.trace_id,
        span_id: span.span_id,
        ...(span.attributes['mcp.request.id'] ? { mcp_request_id: String(span.attributes['mcp.request.id']) } : {}),
      },
    },
    verdict: errored ? 'errored' : 'executed',
    ...(body?.response !== undefined ? { observed: body.response } : {}),
  };
}
