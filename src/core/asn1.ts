// SPDX-License-Identifier: Apache-2.0
/** Minimal DER reader/writer — just enough ASN.1 for RFC 3161 tokens and CMS. */
export interface DerNode {
  tag: number; // full first byte (class+constructed+number) for low tags
  constructed: boolean;
  content: Buffer;
  children: DerNode[] | null;
  raw: Buffer;
}

export function parseDer(buf: Buffer): DerNode {
  const { node, next } = parseAt(buf, 0);
  if (next !== buf.length) throw new Error('DER: trailing bytes');
  return node;
}

export function parseAt(buf: Buffer, offset: number): { node: DerNode; next: number } {
  if (offset + 2 > buf.length) throw new Error('DER: truncated');
  const tag = buf[offset]!;
  let i = offset + 1;
  let len = buf[i++]!;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('DER: bad length');
    len = 0;
    for (let k = 0; k < n; k++) len = len * 256 + buf[i++]!;
  }
  if (i + len > buf.length) throw new Error('DER: truncated content');
  const content = Buffer.from(buf.subarray(i, i + len));
  const raw = Buffer.from(buf.subarray(offset, i + len));
  const constructed = Boolean(tag & 0x20);
  let children: DerNode[] | null = null;
  if (constructed) {
    children = [];
    let c = 0;
    while (c < content.length) {
      const parsed = parseAt(content, c);
      children.push(parsed.node);
      c = parsed.next;
    }
  }
  return { node: { tag, constructed, content, children, raw }, next: i + len };
}

export function oidToString(content: Buffer): string {
  const out: number[] = [Math.floor(content[0]! / 40), content[0]! % 40];
  let v = 0;
  for (let i = 1; i < content.length; i++) {
    v = v * 128 + (content[i]! & 0x7f);
    if (!(content[i]! & 0x80)) {
      out.push(v);
      v = 0;
    }
  }
  return out.join('.');
}

function lengthBytes(len: number): Buffer {
  if (len < 128) return Buffer.from([len]);
  const bytes: number[] = [];
  for (let v = len; v > 0; v >>= 8) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function der(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), lengthBytes(content.length), content]);
}
export const derSeq = (parts: Buffer[]): Buffer => der(0x30, Buffer.concat(parts));
export const derSet = (parts: Buffer[]): Buffer => der(0x31, Buffer.concat(parts));
export const derOctetString = (b: Buffer): Buffer => der(0x04, b);
export const derNull = (): Buffer => Buffer.from([0x05, 0x00]);
export const derExplicit = (n: number, inner: Buffer): Buffer => der(0xa0 + n, inner);

export function derInt(value: number | bigint | Buffer): Buffer {
  let bytes: Buffer;
  if (Buffer.isBuffer(value)) bytes = Buffer.from(value);
  else {
    let v = BigInt(value);
    if (v === 0n) bytes = Buffer.from([0]);
    else {
      const rev: number[] = [];
      while (v > 0n) {
        rev.unshift(Number(v & 0xffn));
        v >>= 8n;
      }
      bytes = Buffer.from(rev);
    }
  }
  while (bytes.length > 1 && bytes[0] === 0 && !(bytes[1]! & 0x80)) bytes = bytes.subarray(1);
  if (bytes[0]! & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return der(0x02, bytes);
}

export function derOid(oid: string): Buffer {
  const parts = oid.split('.').map(Number);
  const bytes = [40 * parts[0]! + parts[1]!];
  for (const p of parts.slice(2)) {
    const enc = [p & 0x7f];
    for (let v = p >> 7; v > 0; v >>= 7) enc.unshift(0x80 | (v & 0x7f));
    bytes.push(...enc);
  }
  return der(0x06, Buffer.from(bytes));
}

export function derGeneralizedTime(d: Date): Buffer {
  const s = d.toISOString().replace(/[-:]/g, '').replace('T', '').replace(/\.\d{3}/, '');
  return der(0x18, Buffer.from(s, 'ascii'));
}

export function parseGeneralizedTime(content: Buffer): Date {
  const s = content.toString('ascii');
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/.exec(s);
  if (!m) throw new Error(`bad GeneralizedTime ${s}`);
  return new Date(Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!));
}
