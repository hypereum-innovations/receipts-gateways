// SPDX-License-Identifier: Apache-2.0
/**
 * Standard OpenID AuthZEN Authorization API 1.0 request/response types
 * used by the open SDK, MCP, Gateway, and OTel capture layers.
 */
import type { CelValue } from '../core/cel.js';

export interface AuthZenRequest {
  subject: { type: string; id: string; properties?: Record<string, CelValue> };
  action: { name: string; properties?: Record<string, CelValue> };
  resource: { type: string; id: string; properties?: Record<string, CelValue> };
  context?: Record<string, CelValue>;
}

export interface AuthZenResponse {
  decision: boolean;
  obligations?: Array<{ id: string; [k: string]: unknown }>;
  advice?: Array<{ id: string; [k: string]: unknown }>;
  hivemind: {
    decision_digest: string;
    policy_set_digest: string;
    reasons: string[];
    statement?: string;
    requires_approval: boolean;
  };
}
