// SPDX-License-Identifier: Apache-2.0
/**
 * Criteria-as-code: a deterministic CEL subset evaluator. Outcome criteria
 * are programs like `ticket.state == 'solved' && !reopened_within(duration('168h'))`.
 * The evaluator terminates by construction (no loops, bounded input, bounded
 * AST), is pure (same confirmations -> same verdict, anywhere), and refuses
 * anything outside the subset at parse time. The Rust verifier's CEL is
 * conformance-tested against this implementation and against cel-go outputs
 * for the shared vector set in conformance/receipts.
 */

export type CelValue =
  | null
  | boolean
  | number
  | string
  | CelValue[]
  | { [k: string]: CelValue }
  | CelDuration
  | CelTimestamp;

export class CelDuration {
  constructor(readonly seconds: number) {}
}
export class CelTimestamp {
  constructor(readonly epochSeconds: number) {}
}

type Tok = { t: string; v?: string };

function lex(src: string): Tok[] {
  const toks: Tok[] = [];
  let i = 0;
  const isId = (c: string) => /[A-Za-z_]/.test(c);
  while (i < src.length) {
    const c = src[i]!;
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') i++;
    else if (src.startsWith('//', i)) while (i < src.length && src[i] !== '\n') i++;
    else if (c === "'" || c === '"') {
      let j = i + 1;
      let s = '';
      while (j < src.length && src[j] !== c) {
        if (src[j] === '\\') {
          const n = src[j + 1];
          s += n === 'n' ? '\n' : n === 't' ? '\t' : n;
          j += 2;
        } else s += src[j++];
      }
      if (j >= src.length) throw new Error('CEL: unterminated string');
      toks.push({ t: 'str', v: s });
      i = j + 1;
    } else if (/[0-9]/.test(c)) {
      let j = i;
      while (j < src.length && /[0-9]/.test(src[j]!)) j++;
      toks.push({ t: 'num', v: src.slice(i, j) });
      i = j;
    } else if (isId(c)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j]!)) j++;
      toks.push({ t: 'id', v: src.slice(i, j) });
      i = j;
    } else {
      const two = src.slice(i, i + 2);
      if (['&&', '||', '==', '!=', '<=', '>='].includes(two)) {
        toks.push({ t: two });
        i += 2;
      } else if ('()[].,!<>+-*/%?:{}'.includes(c)) {
        toks.push({ t: c });
        i++;
      } else throw new Error(`CEL: bad character ${c}`);
    }
  }
  toks.push({ t: 'eof' });
  return toks;
}

export type Ast =
  | { k: 'lit'; v: CelValue }
  | { k: 'id'; name: string }
  | { k: 'get'; obj: Ast; key: string }
  | { k: 'index'; obj: Ast; idx: Ast }
  | { k: 'call'; fn: string; target?: Ast; args: Ast[] }
  | { k: 'bin'; op: string; l: Ast; r: Ast }
  | { k: 'not'; e: Ast }
  | { k: 'neg'; e: Ast }
  | { k: 'list'; items: Ast[] }
  | { k: 'tern'; c: Ast; a: Ast; b: Ast };

class Parser {
  pos = 0;
  constructor(private toks: Tok[]) {}
  peek(): Tok {
    return this.toks[this.pos]!;
  }
  next(): Tok {
    return this.toks[this.pos++]!;
  }
  expect(t: string): void {
    const got = this.next();
    if (got.t !== t) throw new Error(`CEL: expected ${t}, got ${got.t}`);
  }
  parse(): Ast {
    const e = this.ternary();
    if (this.peek().t !== 'eof') throw new Error('CEL: trailing tokens');
    return e;
  }
  ternary(): Ast {
    const c = this.or();
    if (this.peek().t === '?') {
      this.next();
      const a = this.ternary();
      this.expect(':');
      const b = this.ternary();
      return { k: 'tern', c, a, b };
    }
    return c;
  }
  or(): Ast {
    let l = this.and();
    while (this.peek().t === '||') (this.next(), (l = { k: 'bin', op: '||', l, r: this.and() }));
    return l;
  }
  and(): Ast {
    let l = this.cmp();
    while (this.peek().t === '&&') (this.next(), (l = { k: 'bin', op: '&&', l, r: this.cmp() }));
    return l;
  }
  cmp(): Ast {
    let l = this.add();
    for (;;) {
      const t = this.peek().t;
      if (['==', '!=', '<', '>', '<=', '>='].includes(t)) {
        this.next();
        l = { k: 'bin', op: t, l, r: this.add() };
      } else if (t === 'id' && this.peek().v === 'in') {
        this.next();
        l = { k: 'bin', op: 'in', l, r: this.add() };
      } else return l;
    }
  }
  add(): Ast {
    let l = this.mul();
    while (this.peek().t === '+' || this.peek().t === '-') {
      const op = this.next().t;
      l = { k: 'bin', op, l, r: this.mul() };
    }
    return l;
  }
  mul(): Ast {
    let l = this.unary();
    while (['*', '/', '%'].includes(this.peek().t)) {
      const op = this.next().t;
      l = { k: 'bin', op, l, r: this.unary() };
    }
    return l;
  }
  unary(): Ast {
    if (this.peek().t === '!') {
      this.next();
      return { k: 'not', e: this.unary() };
    }
    if (this.peek().t === '-') {
      this.next();
      return { k: 'neg', e: this.unary() };
    }
    return this.postfix();
  }
  postfix(): Ast {
    let e = this.primary();
    for (;;) {
      if (this.peek().t === '.') {
        this.next();
        const nameTok = this.next();
        if (nameTok.t !== 'id') throw new Error('CEL: expected field after .');
        if (this.peek().t === '(') {
          this.next();
          const args = this.args();
          e = { k: 'call', fn: nameTok.v!, target: e, args };
        } else e = { k: 'get', obj: e, key: nameTok.v! };
      } else if (this.peek().t === '[') {
        this.next();
        const idx = this.ternary();
        this.expect(']');
        e = { k: 'index', obj: e, idx };
      } else return e;
    }
  }
  args(): Ast[] {
    const out: Ast[] = [];
    if (this.peek().t === ')') {
      this.next();
      return out;
    }
    for (;;) {
      out.push(this.ternary());
      if (this.peek().t === ',') this.next();
      else {
        this.expect(')');
        return out;
      }
    }
  }
  primary(): Ast {
    const tok = this.next();
    if (tok.t === 'num') {
      const n = Number(tok.v);
      if (!Number.isSafeInteger(n)) throw new Error('CEL: integer out of range');
      return { k: 'lit', v: n };
    }
    if (tok.t === 'str') return { k: 'lit', v: tok.v! };
    if (tok.t === '(') {
      const e = this.ternary();
      this.expect(')');
      return e;
    }
    if (tok.t === '[') {
      const items: Ast[] = [];
      if (this.peek().t === ']') {
        this.next();
        return { k: 'list', items };
      }
      for (;;) {
        items.push(this.ternary());
        if (this.peek().t === ',') this.next();
        else {
          this.expect(']');
          return { k: 'list', items };
        }
      }
    }
    if (tok.t === 'id') {
      if (tok.v === 'true') return { k: 'lit', v: true };
      if (tok.v === 'false') return { k: 'lit', v: false };
      if (tok.v === 'null') return { k: 'lit', v: null };
      if (this.peek().t === '(') {
        this.next();
        return { k: 'call', fn: tok.v!, args: this.args() };
      }
      return { k: 'id', name: tok.v! };
    }
    throw new Error(`CEL: unexpected token ${tok.t}`);
  }
}

export function parseCel(src: string): Ast {
  if (src.length > 8192) throw new Error('CEL: program too large');
  return new Parser(lex(src)).parse();
}

export function parseDuration(s: string): CelDuration {
  const m = /^(-)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/.exec(s.trim());
  if (!m || (!m[2] && !m[3] && !m[4])) throw new Error(`CEL: bad duration ${s}`);
  const secs = Number(m[2] ?? 0) * 3600 + Number(m[3] ?? 0) * 60 + Number(m[4] ?? 0);
  return new CelDuration(m[1] ? -secs : secs);
}

export function parseTimestamp(s: string): CelTimestamp {
  const ms = Date.parse(s);
  if (Number.isNaN(ms)) throw new Error(`CEL: bad timestamp ${s}`);
  return new CelTimestamp(Math.floor(ms / 1000));
}

export type CelFunctions = Record<string, (args: CelValue[], target?: CelValue) => CelValue>;

function eq(a: CelValue, b: CelValue): boolean {
  if (a instanceof CelDuration && b instanceof CelDuration) return a.seconds === b.seconds;
  if (a instanceof CelTimestamp && b instanceof CelTimestamp) return a.epochSeconds === b.epochSeconds;
  return JSON.stringify(a) === JSON.stringify(b);
}

function cmpNum(a: CelValue): number {
  if (typeof a === 'number') return a;
  if (a instanceof CelDuration) return a.seconds;
  if (a instanceof CelTimestamp) return a.epochSeconds;
  throw new Error('CEL: not comparable as number');
}

export function evalCel(
  ast: Ast,
  env: Record<string, CelValue>,
  functions: CelFunctions = {},
): CelValue {
  const ev = (e: Ast): CelValue => {
    switch (e.k) {
      case 'lit':
        return e.v;
      case 'id':
        if (!(e.name in env)) throw new Error(`CEL: unknown name ${e.name}`);
        return env[e.name]!;
      case 'get': {
        const o = ev(e.obj);
        if (o && typeof o === 'object' && !Array.isArray(o) && !(o instanceof CelDuration) && !(o instanceof CelTimestamp)) {
          if (!(e.key in (o as Record<string, CelValue>))) throw new Error(`CEL: no field ${e.key}`);
          return (o as Record<string, CelValue>)[e.key]!;
        }
        throw new Error('CEL: field access on non-map');
      }
      case 'index': {
        const o = ev(e.obj);
        const idx = ev(e.idx);
        if (Array.isArray(o) && typeof idx === 'number') {
          if (idx < 0 || idx >= o.length) throw new Error('CEL: index out of range');
          return o[idx]!;
        }
        if (o && typeof o === 'object' && typeof idx === 'string')
          return (o as Record<string, CelValue>)[idx] ?? null;
        throw new Error('CEL: bad index');
      }
      case 'list':
        return e.items.map(ev);
      case 'not':
        return ev(e.e) !== true;
      case 'neg': {
        const v = ev(e.e);
        if (v instanceof CelDuration) return new CelDuration(-v.seconds);
        if (typeof v === 'number') return -v;
        throw new Error('CEL: bad negation');
      }
      case 'tern':
        return ev(e.c) === true ? ev(e.a) : ev(e.b);
      case 'bin': {
        if (e.op === '&&') return ev(e.l) === true && ev(e.r) === true;
        if (e.op === '||') return ev(e.l) === true || ev(e.r) === true;
        const l = ev(e.l);
        const r = ev(e.r);
        switch (e.op) {
          case '==': return eq(l, r);
          case '!=': return !eq(l, r);
          case '<': return cmpNum(l) < cmpNum(r);
          case '<=': return cmpNum(l) <= cmpNum(r);
          case '>': return cmpNum(l) > cmpNum(r);
          case '>=': return cmpNum(l) >= cmpNum(r);
          case 'in':
            if (Array.isArray(r)) return r.some((x) => eq(x, l));
            if (r && typeof r === 'object' && typeof l === 'string') return l in (r as object);
            throw new Error('CEL: `in` needs a list or map');
          case '+':
            if (l instanceof CelTimestamp && r instanceof CelDuration) return new CelTimestamp(l.epochSeconds + r.seconds);
            if (l instanceof CelDuration && r instanceof CelDuration) return new CelDuration(l.seconds + r.seconds);
            if (typeof l === 'number' && typeof r === 'number') return l + r;
            if (typeof l === 'string' && typeof r === 'string') return l + r;
            throw new Error('CEL: bad + operands');
          case '-':
            if (l instanceof CelTimestamp && r instanceof CelTimestamp) return new CelDuration(l.epochSeconds - r.epochSeconds);
            if (l instanceof CelTimestamp && r instanceof CelDuration) return new CelTimestamp(l.epochSeconds - r.seconds);
            if (l instanceof CelDuration && r instanceof CelDuration) return new CelDuration(l.seconds - r.seconds);
            if (typeof l === 'number' && typeof r === 'number') return l - r;
            throw new Error('CEL: bad - operands');
          case '*': if (typeof l === 'number' && typeof r === 'number') return l * r; break;
          case '/': if (typeof l === 'number' && typeof r === 'number' && r !== 0) return Math.trunc(l / r); break;
          case '%': if (typeof l === 'number' && typeof r === 'number' && r !== 0) return l % r; break;
        }
        throw new Error(`CEL: bad operands for ${e.op}`);
      }
      case 'call': {
        const args = e.args.map(ev);
        const target = e.target ? ev(e.target) : undefined;
        if (functions[e.fn]) return functions[e.fn]!(args, target);
        switch (e.fn) {
          case 'duration':
            return parseDuration(String(args[0]));
          case 'timestamp':
            return parseTimestamp(String(args[0]));
          case 'size': {
            const v = target ?? args[0];
            if (typeof v === 'string' || Array.isArray(v)) return v.length;
            if (v && typeof v === 'object') return Object.keys(v).length;
            throw new Error('CEL: size of non-collection');
          }
          case 'has': {
            // has(map.field) approximated via has(map, 'field') in this subset.
            if (args.length === 2 && args[0] && typeof args[0] === 'object' && typeof args[1] === 'string')
              return args[1] in (args[0] as object);
            throw new Error('CEL: has expects (map, "field") in this subset');
          }
          case 'startsWith':
            return String(target ?? args[0]).startsWith(String(args[target ? 0 : 1]));
          case 'endsWith':
            return String(target ?? args[0]).endsWith(String(args[target ? 0 : 1]));
          case 'contains': {
            const v = target ?? args[0];
            const needle = args[target ? 0 : 1];
            if (typeof v === 'string') return v.includes(String(needle));
            if (Array.isArray(v)) return v.some((x) => eq(x, needle!));
            throw new Error('CEL: contains on unsupported value');
          }
          case 'matches':
            return new RegExp(String(args[target ? 0 : 1])).test(String(target ?? args[0]));
          default:
            throw new Error(`CEL: unknown function ${e.fn}`);
        }
      }
    }
  };
  return ev(ast);
}

export function runCel(
  src: string,
  env: Record<string, CelValue>,
  functions: CelFunctions = {},
): CelValue {
  return evalCel(parseCel(src), env, functions);
}

export function celVerdict(
  src: string,
  env: Record<string, CelValue>,
  functions: CelFunctions = {},
): boolean {
  return runCel(src, env, functions) === true;
}
