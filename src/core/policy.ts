// SPDX-License-Identifier: Apache-2.0
/**
 * Deterministic authorization policy engine — a Cedar-compatible subset.
 * Policies: `permit|forbid (principal, action, resource) when { expr } unless { expr };`
 * with Cedar entity references (`User::"alice"`, `Action::"tools/call:refund"`),
 * `==` and `in` scope operators, and empty scopes meaning "any". Conditions
 * are evaluated with the CEL engine over {principal, action, resource,
 * context}, where each entity exposes {type, id, ...attrs} and `in` tests
 * hierarchy membership through `parents`. Semantics match Cedar's defaults:
 * forbid overrides permit, default is deny, evaluation is order-independent
 * and analyzable before deployment (`lintPolicySet`). The policy-set digest
 * (SHA-256 over the canonically joined policy texts) is what decisions commit
 * to, so any holder of the policies can replay a decision offline.
 */
import { evalCel, parseCel, type CelValue } from './cel.js';
import { sha256 } from './keys.js';
import type { RiskTier } from './capsule.js';

export interface Entity {
  type: string;
  id: string;
  parents?: string[]; // "Type::\"id\"" refs
  attrs?: Record<string, CelValue>;
}

export interface PolicyRequest {
  principal: Entity;
  action: Entity;
  resource: Entity;
  context: Record<string, CelValue>;
}

function entityRef(e: { type: string; id: string }): string {
  return `${e.type}::"${e.id}"`;
}

interface Scope {
  kind: 'any' | 'eq' | 'in' | 'in-list';
  refs: string[];
}

export interface Policy {
  id: string;
  effect: 'permit' | 'forbid';
  principal: Scope;
  action: Scope;
  resource: Scope;
  when?: string | undefined;
  unless?: string | undefined;
  text: string;
}

function parseScope(raw: string): Scope {
  const s = raw.trim();
  if (s === '') return { kind: 'any', refs: [] };
  const eq = /^==\s*(.+)$/.exec(s);
  if (eq) return { kind: 'eq', refs: [normalizeRef(eq[1]!)] };
  const inList = /^in\s*\[(.*)\]$/.exec(s);
  if (inList) return { kind: 'in-list', refs: splitRefs(inList[1]!).map(normalizeRef) };
  const inOne = /^in\s+(.+)$/.exec(s);
  if (inOne) return { kind: 'in', refs: [normalizeRef(inOne[1]!)] };
  throw new Error(`policy: bad scope "${s}"`);
}

function splitRefs(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = '';
  for (const ch of s) {
    if (ch === '"') depth ^= 1;
    if (ch === ',' && depth === 0) {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

function normalizeRef(s: string): string {
  const t = s.trim();
  const m = /^([A-Za-z][A-Za-z0-9_]*(?:::[A-Za-z][A-Za-z0-9_]*)*)::"([^"]*)"$/.exec(t);
  if (!m) throw new Error(`policy: bad entity reference "${t}"`);
  return `${m[1]}::"${m[2]}"`;
}

export function parsePolicySet(source: string): Policy[] {
  const policies: Policy[] = [];
  // Split on top-level semicolons; policy bodies in this subset have no ';' inside strings with braces tracked.
  let i = 0;
  let n = 0;
  while (i < source.length) {
    const start = source.indexOf(';', i);
    if (start < 0) break;
    const chunk = source
      .slice(i, start)
      .replace(/\/\/[^\n]*/g, '')
      .trim();
    i = start + 1;
    if (!chunk) continue;
    const head = /^(permit|forbid)\s*\(([^)]*)\)\s*(.*)$/s.exec(chunk);
    if (!head) throw new Error(`policy: cannot parse "${chunk.slice(0, 80)}"`);
    const scopes = head[2]!.split(',').map((x) => x.trim());
    if (scopes.length !== 3) throw new Error('policy: expected (principal, action, resource)');
    // Scopes may themselves contain commas inside lists only for action `in [...]` handled below:
    const [pRaw, aRaw, rRaw] = rejoinScopes(head[2]!);
    void scopes;
    let rest = head[3]!.trim();
    let when: string | undefined;
    let unless: string | undefined;
    const grab = (kw: 'when' | 'unless') => {
      const re = new RegExp(`^${kw}\\s*\\{([\\s\\S]*)\\}\\s*(.*)$`);
      const m = re.exec(rest);
      if (m) {
        rest = (m[2] ?? '').trim();
        return m[1]!.trim();
      }
      return undefined;
    };
    when = grab('when') ?? when;
    unless = grab('unless') ?? unless;
    when = grab('when') ?? when;
    unless = grab('unless') ?? unless;
    if (rest) throw new Error(`policy: trailing text "${rest}"`);
    if (when) parseCel(cedarToCel(when));
    if (unless) parseCel(cedarToCel(unless));
    policies.push({
      id: `policy-${n++}`,
      effect: head[1] as 'permit' | 'forbid',
      principal: parseScope(stripScopeName(pRaw, 'principal')),
      action: parseScope(stripScopeName(aRaw, 'action')),
      resource: parseScope(stripScopeName(rRaw, 'resource')),
      when,
      unless,
      text: `${chunk};`,
    });
  }
  if (policies.length === 0) throw new Error('policy: empty policy set');
  return policies;
}

function rejoinScopes(inner: string): [string, string, string] {
  // Split at commas that separate "principal ..., action ..., resource ..." respecting [] and quotes.
  const parts: string[] = [];
  let cur = '';
  let bracket = 0;
  let inStr = false;
  for (const ch of inner) {
    if (ch === '"') inStr = !inStr;
    if (!inStr) {
      if (ch === '[') bracket++;
      if (ch === ']') bracket--;
    }
    if (ch === ',' && bracket === 0 && !inStr) {
      const look = inner.slice(inner.indexOf(ch)).slice(0, 200);
      void look;
      // Only split when the following text starts with a scope keyword.
      parts.push(cur);
      cur = '';
    } else cur += ch;
  }
  // The naive split above splits every top-level comma; merge fragments back so that
  // exactly segments starting with principal/action/resource begin a new scope.
  const merged: string[] = [];
  for (const p of [...parts, cur]) {
    const t = p.trim();
    if (/^(principal|action|resource)\b/.test(t) || merged.length === 0) merged.push(t);
    else merged[merged.length - 1] = `${merged[merged.length - 1]}, ${t}`;
  }
  if (merged.length !== 3) throw new Error('policy: expected three scopes');
  return merged as [string, string, string];
}

function stripScopeName(raw: string, name: string): string {
  const t = raw.trim();
  if (!t.startsWith(name)) throw new Error(`policy: scope must start with ${name}`);
  return t.slice(name.length).trim();
}

/** Cedar condition syntax -> CEL subset: entity refs become comparable strings via __ref helpers. */
export function cedarToCel(expr: string): string {
  return expr
    .replace(/([A-Za-z][A-Za-z0-9_]*(?:::[A-Za-z][A-Za-z0-9_]*)*)::"([^"]*)"/g, '"$1::\\"$2\\""')
    .replace(/\bhas\s+([A-Za-z_][A-Za-z0-9_.]*)/g, 'has($1)');
}

function entityEnv(e: Entity): CelValue {
  return {
    type: e.type,
    id: e.id,
    __ref: entityRef(e),
    __parents: (e.parents ?? []) as CelValue[],
    ...(e.attrs ?? {}),
  } as CelValue;
}

function scopeMatches(scope: Scope, e: Entity): boolean {
  const ref = entityRef(e);
  if (scope.kind === 'any') return true;
  if (scope.kind === 'eq') return scope.refs[0] === ref;
  // `in`: equal to, or a descendant of (via parents chain names), any listed ref.
  const ancestry = new Set([ref, ...(e.parents ?? [])]);
  return scope.refs.some((r) => ancestry.has(r));
}

export interface PolicyDecision {
  decision: 'permit' | 'deny';
  permitting: string[];
  forbidding: string[];
  reasons: string[];
}

export function evaluatePolicies(policies: Policy[], req: PolicyRequest): PolicyDecision {
  const permitting: string[] = [];
  const forbidding: string[] = [];
  const env: Record<string, CelValue> = {
    principal: entityEnv(req.principal),
    action: entityEnv(req.action),
    resource: entityEnv(req.resource),
    context: req.context as CelValue,
  };
  const cond = (src?: string): boolean => {
    if (!src) return true;
    return evalCel(parseCel(cedarToCel(src)), env, {
      has: (args) => args[0] !== null && args[0] !== undefined,
    }) === true;
  };
  for (const p of policies) {
    if (!scopeMatches(p.principal, req.principal)) continue;
    if (!scopeMatches(p.action, req.action)) continue;
    if (!scopeMatches(p.resource, req.resource)) continue;
    let ok = false;
    try {
      ok = cond(p.when) && !(p.unless ? cond(p.unless) : false);
    } catch {
      ok = false; // an evaluation error never grants; deny-by-default
    }
    if (!ok) continue;
    (p.effect === 'permit' ? permitting : forbidding).push(p.id);
  }
  const decision = forbidding.length === 0 && permitting.length > 0 ? 'permit' : 'deny';
  const reasons =
    forbidding.length > 0
      ? forbidding.map((id) => `forbidden by ${id}`)
      : permitting.length > 0
        ? permitting.map((id) => `permitted by ${id}`)
        : ['no permitting policy (default deny)'];
  return { decision, permitting, forbidding, reasons };
}

export function policySetDigest(policies: Policy[]): string {
  const joined = policies.map((p) => p.text.trim()).sort().join('\n');
  return `sha256:${sha256(Buffer.from(joined, 'utf8')).toString('hex')}`;
}

export function lintPolicySet(policies: Policy[]): string[] {
  const warnings: string[] = [];
  const unconditionalPermitAll = policies.some(
    (p) =>
      p.effect === 'permit' &&
      p.principal.kind === 'any' &&
      p.action.kind === 'any' &&
      p.resource.kind === 'any' &&
      !p.when &&
      !p.unless,
  );
  if (unconditionalPermitAll) warnings.push('an unconditional permit(,,) policy allows everything not forbidden');
  const seen = new Set<string>();
  for (const p of policies) {
    if (seen.has(p.text)) warnings.push(`duplicate policy ${p.id}`);
    seen.add(p.text);
  }
  return warnings;
}

/** Built-in risk posture: destructive and financial actions are denied unless a policy permits them. */
export const DEFAULT_DENY_TIERS: RiskTier[] = ['destructive', 'financial'];

export function defaultPolicyText(): string {
  return [
    '// Hivemind Receipts default policy: reads and writes by authenticated principals,',
    '// destructive/financial/external communication only through explicit permit + approval context.',
    'permit (principal, action, resource) when { context.risk_tier == "read" };',
    'permit (principal, action, resource) when { context.risk_tier == "write" };',
    'permit (principal, action, resource) when { (context.risk_tier == "destructive" || context.risk_tier == "financial" || context.risk_tier == "external_communication") && context.approval_digest != "" };',
    'forbid (principal, action, resource) when { context.kill_switch == true };',
    '',
  ].join('\n');
}
