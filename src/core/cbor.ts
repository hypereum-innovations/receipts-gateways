// SPDX-License-Identifier: Apache-2.0
/**
 * Deterministic CBOR (RFC 8949 §4.2.1, core deterministic encoding).
 * The only bytes Hivemind Receipts ever signs. Encoder output is canonical:
 * shortest-form integers, definite lengths, map keys sorted length-first then
 * bytewise over their encodings. The strict decoder rejects indefinite
 * lengths, non-shortest forms, duplicate keys and unsorted keys, so a
 * statement has exactly one valid byte form and re-encoding a decoded
 * statement always reproduces the signed bytes.
 * Non-integer numbers are refused: capsule amounts are integer minor units.
 */
export type CborValue =
  | null
  | boolean
  | number
  | bigint
  | string
  | Uint8Array
  | CborValue[]
  | Map<string | number, CborValue>
  | { [key: string]: CborValue };

export class CborTag {
  constructor(
    readonly tag: number,
    readonly value: CborValue,
  ) {}
}

function head(major: number, n: bigint, out: number[]): void {
  const m = major << 5;
  if (n < 24n) out.push(m | Number(n));
  else if (n <= 0xffn) out.push(m | 24, Number(n));
  else if (n <= 0xffffn) out.push(m | 25, Number(n >> 8n) & 0xff, Number(n) & 0xff);
  else if (n <= 0xffffffffn)
    out.push(m | 26, ...[24n, 16n, 8n, 0n].map((s) => Number(n >> s) & 0xff));
  else if (n <= 0xffffffffffffffffn)
    out.push(m | 27, ...[56n, 48n, 40n, 32n, 24n, 16n, 8n, 0n].map((s) => Number(n >> s) & 0xff));
  else throw new Error('CBOR integer out of range');
}

function encodeInto(v: unknown, out: number[]): void {
  if (v === null || v === undefined) out.push(0xf6);
  else if (v === false) out.push(0xf4);
  else if (v === true) out.push(0xf5);
  else if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new Error(`CBOR: non-integer or unsafe number ${v}`);
    if (v >= 0) head(0, BigInt(v), out);
    else head(1, BigInt(-1 - v), out);
  } else if (typeof v === 'bigint') {
    if (v >= 0n) head(0, v, out);
    else head(1, -1n - v, out);
  } else if (typeof v === 'string') {
    const b = Buffer.from(v, 'utf8');
    head(3, BigInt(b.length), out);
    for (const x of b) out.push(x);
  } else if (v instanceof Uint8Array) {
    head(2, BigInt(v.length), out);
    for (const x of v) out.push(x);
  } else if (v instanceof CborTag) {
    head(6, BigInt(v.tag), out);
    encodeInto(v.value, out);
  } else if (Array.isArray(v)) {
    head(4, BigInt(v.length), out);
    for (const x of v) encodeInto(x, out);
  } else if (v instanceof Map || (typeof v === 'object')) {
    const entries: Array<[unknown, unknown]> =
      v instanceof Map ? [...v.entries()] : Object.entries(v as Record<string, unknown>);
    const encoded = entries.map(([k, val]) => {
      const kb: number[] = [];
      encodeInto(k, kb);
      return { kb: Buffer.from(kb), val };
    });
    // Core deterministic map ordering: shorter encoded key first, then bytewise.
    encoded.sort((a, b) => a.kb.length - b.kb.length || Buffer.compare(a.kb, b.kb));
    for (let i = 1; i < encoded.length; i++)
      if (encoded[i]!.kb.equals(encoded[i - 1]!.kb)) throw new Error('CBOR: duplicate map key');
    head(5, BigInt(encoded.length), out);
    for (const e of encoded) {
      for (const x of e.kb) out.push(x);
      encodeInto(e.val, out);
    }
  } else throw new Error(`CBOR: unsupported value of type ${typeof v}`);
}

export function cborEncode(v: unknown): Buffer {
  const out: number[] = [];
  encodeInto(v, out);
  return Buffer.from(out);
}

class Reader {
  pos = 0;
  constructor(private readonly buf: Buffer) {}
  byte(): number {
    if (this.pos >= this.buf.length) throw new Error('CBOR: unexpected end');
    return this.buf[this.pos++]!;
  }
  bytes(n: number): Buffer {
    if (this.pos + n > this.buf.length) throw new Error('CBOR: unexpected end');
    const b = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return Buffer.from(b);
  }
  arg(ai: number): bigint {
    if (ai < 24) return BigInt(ai);
    if (ai === 24) {
      const v = this.byte();
      if (v < 24) throw new Error('CBOR: non-shortest form');
      return BigInt(v);
    }
    const widths: Record<number, number> = { 25: 2, 26: 4, 27: 8 };
    const w = widths[ai];
    if (!w) throw new Error('CBOR: indefinite length or reserved additional info');
    let v = 0n;
    for (let i = 0; i < w; i++) v = (v << 8n) | BigInt(this.byte());
    const min = w === 2 ? 256n : w === 4 ? 65536n : 4294967296n;
    if (v < min) throw new Error('CBOR: non-shortest form');
    return v;
  }
  value(depth: number): unknown {
    if (depth > 64) throw new Error('CBOR: nesting too deep');
    const ib = this.byte();
    const major = ib >> 5;
    const ai = ib & 0x1f;
    switch (major) {
      case 0: {
        const v = this.arg(ai);
        return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
      }
      case 1: {
        const v = -1n - this.arg(ai);
        return v >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(v) : v;
      }
      case 2:
        return this.bytes(Number(this.arg(ai)));
      case 3: {
        const rawText = this.bytes(Number(this.arg(ai)));
        try {
          return new TextDecoder('utf-8', { fatal: true }).decode(rawText);
        } catch {
          throw new Error('CBOR: invalid utf8 text string');
        }
      }
      case 4: {
        const n = Number(this.arg(ai));
        const arr: unknown[] = [];
        for (let i = 0; i < n; i++) arr.push(this.value(depth + 1));
        return arr;
      }
      case 5: {
        const n = Number(this.arg(ai));
        const map = new Map<unknown, unknown>();
        let prevKey: Buffer | null = null;
        for (let i = 0; i < n; i++) {
          const start = this.pos;
          const k = this.value(depth + 1);
          const keyBytes = this.buf.subarray(start, this.pos);
          if (prevKey) {
            const cmp = prevKey.length - keyBytes.length || Buffer.compare(prevKey, keyBytes);
            if (cmp === 0) throw new Error('CBOR: duplicate map key');
            if (cmp > 0) throw new Error('CBOR: map keys not in deterministic order');
          }
          prevKey = Buffer.from(keyBytes);
          map.set(k, this.value(depth + 1));
        }
        return map;
      }
      case 6: {
        const tag = Number(this.arg(ai));
        return new CborTag(tag, this.value(depth + 1) as CborValue);
      }
      case 7: {
        if (ai === 20) return false;
        if (ai === 21) return true;
        if (ai === 22) return null;
        throw new Error('CBOR: floats and simple values are not in the receipts profile');
      }
      default:
        throw new Error('CBOR: bad major type');
    }
  }
}

/** Strict deterministic decode. Throws on any non-canonical encoding or trailing bytes. */
export function cborDecode(buf: Uint8Array): unknown {
  const r = new Reader(Buffer.from(buf));
  const v = r.value(0);
  if (r.pos !== buf.length) throw new Error('CBOR: trailing bytes');
  return v;
}

/** Convert a decoded CBOR map (string keys) to a plain object. Buffers stay Buffers. */
export function cborToPlain(v: unknown): unknown {
  if (v instanceof Map) {
    const o: Record<string, unknown> = {};
    for (const [k, val] of v) {
      if (typeof k !== 'string') throw new Error('CBOR plain conversion needs string keys');
      if (k === '__proto__') throw new Error('CBOR plain conversion refuses __proto__');
      o[k] = cborToPlain(val);
    }
    return o;
  }
  if (Array.isArray(v)) return v.map(cborToPlain);
  return v;
}

/** RFC 8785 (JCS) JSON view: sorted keys, no whitespace. Display only — never signed. */
export function jcsStringify(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? 'null';
  if (v instanceof Uint8Array) return JSON.stringify(Buffer.from(v).toString('base64'));
  if (Array.isArray(v)) return `[${v.map(jcsStringify).join(',')}]`;
  if (v instanceof Map) v = cborToPlain(v);
  const rec = v as Record<string, unknown>;
  const keys = Object.keys(rec).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${jcsStringify(rec[k])}`).join(',')}}`;
}
