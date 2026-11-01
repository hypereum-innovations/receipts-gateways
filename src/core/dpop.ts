// SPDX-License-Identifier: Apache-2.0
/**
 * DPoP (RFC 9449) sender-constrained, single-use action tokens, plus the
 * minimal ES256 JWT machinery they need. After a human approval, the decision
 * point mints a token bound to exactly one action digest, one audience and
 * the requester's key (cnf.jkt); every use needs a fresh DPoP proof whose
 * `ath` is the token hash and whose key thumbprint must equal cnf.jkt.
 */
import { createHash, createPublicKey, sign as cryptoSign, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { b64u, b64uDecode } from './keys.js';

function jwsHeader(payload: Record<string, unknown>, privateKey: KeyObject, typ: string, jwk?: object): string {
  const enc = (o: unknown) => b64u(Buffer.from(JSON.stringify(o), 'utf8'));
  const signingInput = `${enc({ alg: 'ES256', typ, ...(jwk ? { jwk } : {}) })}.${enc(payload)}`;
  const sig = cryptoSign('sha256', Buffer.from(signingInput), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${signingInput}.${b64u(sig)}`;
}

export function jwkThumbprint(jwk: { kty: string; crv?: string; x?: string; y?: string }): string {
  const members =
    jwk.kty === 'EC'
      ? { crv: jwk.crv, kty: 'EC', x: jwk.x, y: jwk.y }
      : { crv: jwk.crv, kty: 'OKP', x: jwk.x };
  return b64u(createHash('sha256').update(Buffer.from(JSON.stringify(members), 'utf8')).digest());
}

function publicJwk(key: KeyObject): { kty: string; crv?: string; x?: string; y?: string } {
  const pub = key.type === 'public' ? key : createPublicKey(key);
  return pub.export({ format: 'jwk' }) as never;
}

export interface ActionToken {
  token: string;
  jti: string;
}

export function mintActionToken(input: {
  issuerPrivateKey: KeyObject;
  issuer: string;
  subject: string;
  audience: string;
  actionDigest: string;
  holderPublicKey: KeyObject;
  ttlSeconds?: number;
  nowSeconds?: number;
  jti: string;
}): ActionToken {
  const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  const token = jwsHeader(
    {
      iss: input.issuer,
      sub: input.subject,
      aud: input.audience,
      iat: now,
      exp: now + Math.min(input.ttlSeconds ?? 300, 300), // tokens live five minutes at most
      jti: input.jti,
      hivemind_action_digest: input.actionDigest,
      cnf: { jkt: jwkThumbprint(publicJwk(input.holderPublicKey)) },
    },
    input.issuerPrivateKey,
    'at+jwt',
  );
  return { token, jti: input.jti };
}

export function createDpopProof(input: {
  holderPrivateKey: KeyObject;
  httpMethod: string;
  httpUri: string;
  accessToken: string;
  nowSeconds?: number;
  jti: string;
}): string {
  const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  return jwsHeader(
    {
      htm: input.httpMethod.toUpperCase(),
      htu: input.httpUri,
      iat: now,
      jti: input.jti,
      ath: b64u(createHash('sha256').update(input.accessToken, 'ascii').digest()),
    },
    input.holderPrivateKey,
    'dpop+jwt',
    publicJwk(input.holderPrivateKey),
  );
}

interface ParsedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Buffer;
}

function parseJwt(token: string): ParsedJwt {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('bad JWT compact form');
  return {
    header: JSON.parse(b64uDecode(parts[0]!).toString('utf8')) as Record<string, unknown>,
    payload: JSON.parse(b64uDecode(parts[1]!).toString('utf8')) as Record<string, unknown>,
    signingInput: `${parts[0]}.${parts[1]}`,
    signature: b64uDecode(parts[2]!),
  };
}

function verifyJwt(token: string, publicKey: KeyObject): ParsedJwt {
  const p = parseJwt(token);
  if (p.header['alg'] !== 'ES256') throw new Error('bad JWT alg');
  const ok = cryptoVerify(
    'sha256',
    Buffer.from(p.signingInput),
    { key: publicKey, dsaEncoding: 'ieee-p1363' },
    p.signature,
  );
  if (!ok) throw new Error('JWT signature does not verify');
  return p;
}

export class JtiStore {
  private seen = new Map<string, number>();
  /** Returns false when the jti was already used (single-use enforced). */
  consume(jti: string, expSeconds: number): boolean {
    if (this.seen.has(jti)) return false;
    this.seen.set(jti, expSeconds);
    const now = Math.floor(Date.now() / 1000);
    for (const [k, exp] of this.seen) if (exp < now) this.seen.delete(k);
    return true;
  }
}

export function verifyActionTokenWithDpop(input: {
  token: string;
  dpopProof: string;
  issuerPublicKey: KeyObject;
  audience: string;
  httpMethod: string;
  httpUri: string;
  expectedActionDigest: string;
  jtiStore: JtiStore;
  nowSeconds?: number;
}): { subject: string; jti: string } {
  const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  const token = verifyJwt(input.token, input.issuerPublicKey);
  const p = token.payload;
  if (String(p['aud']) !== input.audience) throw new Error('token audience mismatch');
  if (Number(p['exp']) < now) throw new Error('token expired');
  if (Number(p['iat']) > now + 30) throw new Error('token issued in the future');
  if (String(p['hivemind_action_digest']) !== input.expectedActionDigest)
    throw new Error('token is bound to a different action');
  const cnf = p['cnf'] as { jkt?: string } | undefined;
  if (!cnf?.jkt) throw new Error('token is not sender-constrained');

  const proofHeader = parseJwt(input.dpopProof);
  const jwk = proofHeader.header['jwk'] as never;
  if (!jwk) throw new Error('DPoP proof carries no jwk');
  const holderKey = createPublicKey({ format: 'jwk', key: jwk });
  const proof = verifyJwt(input.dpopProof, holderKey);
  if (jwkThumbprint(jwk as never) !== cnf.jkt) throw new Error('DPoP key does not match token cnf.jkt');
  if (String(proof.payload['htm']) !== input.httpMethod.toUpperCase()) throw new Error('DPoP htm mismatch');
  if (String(proof.payload['htu']) !== input.httpUri) throw new Error('DPoP htu mismatch');
  const ath = b64u(createHash('sha256').update(input.token, 'ascii').digest());
  if (String(proof.payload['ath']) !== ath) throw new Error('DPoP ath mismatch');
  if (Math.abs(now - Number(proof.payload['iat'])) > 300) throw new Error('DPoP proof too old');
  if (!input.jtiStore.consume(`token:${String(p['jti'])}`, Number(p['exp'])))
    throw new Error('action token already used (single-use)');
  if (!input.jtiStore.consume(`dpop:${String(proof.payload['jti'])}`, now + 300))
    throw new Error('DPoP proof replayed');
  return { subject: String(p['sub']), jti: String(p['jti']) };
}
