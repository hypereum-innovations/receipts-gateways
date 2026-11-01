// SPDX-License-Identifier: Apache-2.0
/**
 * SD-JWT (RFC 9901) for the JSON view of a receipt: selectively disclosable
 * claims. The issuer publishes `_sd` digests (SHA-256 of each disclosure);
 * the holder presents only the disclosures a receiver needs — amount and
 * date, not the end customer's name. The CBOR form of a receipt keeps its
 * own per-field salted commitments; this is the JSON-facing equivalent.
 */
import { createHash, createPublicKey, randomBytes, sign as cryptoSign, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { b64u, b64uDecode } from './keys.js';

type Claims = Record<string, unknown>;

export function makeDisclosure(name: string, value: unknown, salt: string = randomBytes(16).toString('base64url')): {
  disclosure: string;
  digest: string;
} {
  const disclosure = b64u(Buffer.from(JSON.stringify([salt, name, value]), 'utf8'));
  const digest = b64u(createHash('sha256').update(disclosure, 'ascii').digest());
  return { disclosure, digest };
}

function jwsSign(payload: Claims, privateKey: KeyObject, typ = 'dc+sd-jwt'): string {
  const enc = (o: unknown) => b64u(Buffer.from(JSON.stringify(o), 'utf8'));
  const input = `${enc({ alg: 'ES256', typ })}.${enc(payload)}`;
  const sig = cryptoSign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return `${input}.${b64u(sig)}`;
}

export interface IssuedSdJwt {
  sdJwt: string; // issuer JWS + "~" + disclosures + "~"
  disclosures: string[];
}

export function issueSdJwt(input: {
  issuerPrivateKey: KeyObject;
  issuer: string;
  plainClaims: Claims;
  disclosable: Claims;
  nowSeconds?: number;
}): IssuedSdJwt {
  const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  const disclosures: string[] = [];
  const sd: string[] = [];
  for (const [name, value] of Object.entries(input.disclosable).sort(([a], [b]) => (a < b ? -1 : 1))) {
    const d = makeDisclosure(name, value);
    disclosures.push(d.disclosure);
    sd.push(d.digest);
  }
  const payload: Claims = {
    ...input.plainClaims,
    iss: input.issuer,
    iat: now,
    _sd: sd.sort(),
    _sd_alg: 'sha-256',
  };
  const jws = jwsSign(payload, input.issuerPrivateKey);
  return { sdJwt: `${jws}~${disclosures.join('~')}~`, disclosures };
}

/** Present a subset of disclosures; the rest stay undisclosed digests. */
export function presentSdJwt(issued: IssuedSdJwt, revealNames: string[]): string {
  const kept = issued.disclosures.filter((d) => {
    const [, name] = JSON.parse(b64uDecode(d).toString('utf8')) as [string, string, unknown];
    return revealNames.includes(name);
  });
  const jws = issued.sdJwt.split('~')[0]!;
  return kept.length ? `${jws}~${kept.join('~')}~` : `${jws}~`;
}

export function verifySdJwt(
  presented: string,
  issuerPublicKey: KeyObject,
): { valid: boolean; claims: Claims; undisclosed: number; detail: string } {
  try {
    const parts = presented.split('~');
    const jws = parts[0]!;
    const disclosures = parts.slice(1).filter((p) => p.length > 0);
    const [headerB64, payloadB64, sigB64] = jws.split('.');
    const header = JSON.parse(b64uDecode(headerB64!).toString('utf8')) as { alg?: string };
    if (header.alg !== 'ES256') throw new Error('bad alg');
    const ok = cryptoVerify(
      'sha256',
      Buffer.from(`${headerB64}.${payloadB64}`),
      { key: issuerPublicKey.type === 'public' ? issuerPublicKey : createPublicKey(issuerPublicKey), dsaEncoding: 'ieee-p1363' },
      b64uDecode(sigB64!),
    );
    if (!ok) return { valid: false, claims: {}, undisclosed: 0, detail: 'issuer signature does not verify' };
    const payload = JSON.parse(b64uDecode(payloadB64!).toString('utf8')) as Claims;
    const sdDigests = new Set((payload['_sd'] as string[] | undefined) ?? []);
    if (payload['_sd_alg'] !== 'sha-256' && sdDigests.size > 0) throw new Error('unsupported _sd_alg');
    const claims: Claims = { ...payload };
    delete claims['_sd'];
    delete claims['_sd_alg'];
    let revealed = 0;
    for (const d of disclosures) {
      const digest = b64u(createHash('sha256').update(d, 'ascii').digest());
      if (!sdDigests.has(digest)) return { valid: false, claims: {}, undisclosed: 0, detail: 'disclosure digest not in _sd' };
      const [, name, value] = JSON.parse(b64uDecode(d).toString('utf8')) as [string, string, unknown];
      if (name === '_sd' || name === '_sd_alg' || name === '__proto__') throw new Error('reserved claim name in disclosure');
      claims[name] = value;
      revealed++;
    }
    return { valid: true, claims, undisclosed: sdDigests.size - revealed, detail: 'SD-JWT verified' };
  } catch (e) {
    return { valid: false, claims: {}, undisclosed: 0, detail: (e as Error).message };
  }
}
