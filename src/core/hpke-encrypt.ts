/**
 * SPDX-License-Identifier: Apache-2.0
 *
 * HPKE (RFC 9180) Client-Side Encryption Half — Open-Source SDK / Client Module.
 *
 * Implements HPKE base mode DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM
 * client-side encryption (`hpkeEncryptForSubject`, `hpkeSeal`, `generateHpkeKeyPair`,
 * `serializePublicKey`, `deserializePublicKey`) with zero server-side KMS custody
 * or decryption keys.
 */
import {
  createCipheriv,
  createHash,
  createHmac,
  diffieHellman,
  generateKeyPairSync,
  createPublicKey,
  type KeyObject,
} from 'node:crypto';

export const KEM_ID = 0x0010; // DHKEM(P-256, HKDF-SHA256)
export const KDF_ID = 0x0001; // HKDF-SHA256
export const AEAD_ID = 0x0001; // AES-128-GCM
export const N_H = 32;
export const N_K = 16;
export const N_N = 12;

function i2osp(v: number, n: number): Buffer {
  const b = Buffer.alloc(n);
  b.writeUIntBE(v, 0, n);
  return b;
}

function hkdfExtract(salt: Buffer, ikm: Buffer): Buffer {
  return createHmac('sha256', salt).update(ikm).digest();
}

function hkdfExpand(prk: Buffer, info: Buffer, len: number): Buffer {
  const out: Buffer[] = [];
  let t: Buffer = Buffer.alloc(0);
  for (let i = 1; out.reduce((a, b) => a + b.length, 0) < len; i++) {
    t = createHmac('sha256', prk).update(Buffer.concat([t, info, Buffer.from([i])])).digest();
    out.push(t);
  }
  return Buffer.concat(out).subarray(0, len);
}

function labeledExtract(salt: Buffer, suiteId: Buffer, label: string, ikm: Buffer): Buffer {
  const prefixed = Buffer.concat([Buffer.from('HPKE-v1'), suiteId, Buffer.from(label), ikm]);
  return hkdfExtract(salt, prefixed);
}

function labeledExpand(prk: Buffer, suiteId: Buffer, label: string, info: Buffer, len: number): Buffer {
  const labeledInfo = Buffer.concat([i2osp(len, 2), Buffer.from('HPKE-v1'), suiteId, Buffer.from(label), info]);
  return hkdfExpand(prk, labeledInfo, len);
}

export function kemSuiteId(): Buffer {
  return Buffer.concat([Buffer.from('KEM'), i2osp(KEM_ID, 2)]);
}

export function hpkeSuiteId(): Buffer {
  return Buffer.concat([Buffer.from('HPKE'), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(AEAD_ID, 2)]);
}

export interface HpkeKeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
  publicKeyBytes: Buffer;
}

/**
 * Generates an ephemeral or recipient P-256 key pair and derives its uncompressed
 * 65-byte public key representation for RFC 9180 DHKEM(P-256, HKDF-SHA256).
 */
export function generateHpkeKeyPair(): HpkeKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    publicKey,
    privateKey,
    publicKeyBytes: serializePublicKey(publicKey),
  };
}

/** Alias preserved for existing callers. */
export function hpkeGenerateKeyPair(): { publicKey: KeyObject; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { publicKey, privateKey };
}

export function serializePublicKey(key: KeyObject): Buffer {
  const pub = key.type === 'public' ? key : createPublicKey(key);
  const jwk = pub.export({ format: 'jwk' }) as { x: string; y: string };
  return Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(jwk.x, 'base64url'),
    Buffer.from(jwk.y, 'base64url'),
  ]);
}

export function deserializePublicKey(bytes: Buffer): KeyObject {
  if (bytes.length !== 65 || bytes[0] !== 0x04) throw new Error('HPKE: bad P-256 public key');
  return createPublicKey({
    format: 'jwk',
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: bytes.subarray(1, 33).toString('base64url'),
      y: bytes.subarray(33, 65).toString('base64url'),
    },
  });
}

export function extractAndExpand(dh: Buffer, kemContext: Buffer): Buffer {
  const suite = kemSuiteId();
  const eaePrk = labeledExtract(Buffer.alloc(N_H), suite, 'eae_prk', dh);
  return labeledExpand(eaePrk, suite, 'shared_secret', kemContext, N_H);
}

function encap(recipientPublic: KeyObject): { sharedSecret: Buffer; enc: Buffer } {
  const eph = hpkeGenerateKeyPair();
  const dh = diffieHellman({ privateKey: eph.privateKey, publicKey: recipientPublic });
  const enc = serializePublicKey(eph.publicKey);
  const pkRm = serializePublicKey(recipientPublic);
  const kemContext = Buffer.concat([enc, pkRm]);
  return { sharedSecret: extractAndExpand(dh, kemContext), enc };
}

export function keySchedule(sharedSecret: Buffer, info: Buffer): { key: Buffer; nonce: Buffer } {
  const suite = hpkeSuiteId();
  const pskIdHash = labeledExtract(Buffer.alloc(N_H), suite, 'psk_id_hash', Buffer.alloc(0));
  const infoHash = labeledExtract(Buffer.alloc(N_H), suite, 'info_hash', info);
  const ksContext = Buffer.concat([Buffer.from([0x00]), pskIdHash, infoHash]);
  const secret = labeledExtract(sharedSecret, suite, 'secret', Buffer.alloc(0));
  return {
    key: labeledExpand(secret, suite, 'key', ksContext, N_K),
    nonce: labeledExpand(secret, suite, 'base_nonce', ksContext, N_N),
  };
}

export interface HpkeSealed {
  enc: Buffer;
  ciphertext: Buffer; // includes the 16-byte GCM tag, RFC form
}

export function hpkeSeal(
  recipientPublic: KeyObject,
  plaintext: Buffer,
  info: Buffer = Buffer.alloc(0),
  aad: Buffer = Buffer.alloc(0),
): HpkeSealed {
  const { sharedSecret, enc } = encap(recipientPublic);
  const { key, nonce } = keySchedule(sharedSecret, info);
  const cipher = createCipheriv('aes-128-gcm', key, nonce);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return { enc, ciphertext: ct };
}

export interface HpkeSubjectEnvelope {
  subjectId: string;
  suite: 'DHKEM(P-256,HKDF-SHA256)/HKDF-SHA256/AES-128-GCM';
  encBase64Url: string;
  ciphertextBase64Url: string;
  enc: Buffer;
  ciphertext: Buffer;
  ciphertextDigest: string;
  plaintextDigest: string;
}

/**
 * Pure client-side HPKE encryption for a specific GDPR / data subject (`subjectId`).
 * Binds `subjectId` into the HPKE `info` context (`hivemind:receipts:subject:<subjectId>`)
 * and optional `aad` so the ciphertext cannot be re-targeted to a different subject.
 */
export function hpkeEncryptForSubject(input: {
  subjectId: string;
  recipientPublicKey: KeyObject | Buffer;
  plaintext: Buffer | string | Record<string, unknown>;
  aad?: Buffer | string | undefined;
}): HpkeSubjectEnvelope {
  if (!input.subjectId || input.subjectId.trim() === '') {
    throw new Error('HPKE: subjectId is required for per-subject encryption');
  }
  const pubKey = Buffer.isBuffer(input.recipientPublicKey)
    ? deserializePublicKey(input.recipientPublicKey)
    : input.recipientPublicKey;

  const plaintextBuf = Buffer.isBuffer(input.plaintext)
    ? input.plaintext
    : typeof input.plaintext === 'string'
      ? Buffer.from(input.plaintext, 'utf8')
      : Buffer.from(JSON.stringify(input.plaintext), 'utf8');

  const infoBuf = Buffer.from(`hivemind:receipts:subject:${input.subjectId}`, 'utf8');
  const aadBuf =
    input.aad === undefined
      ? infoBuf
      : Buffer.isBuffer(input.aad)
        ? input.aad
        : Buffer.from(input.aad, 'utf8');

  const sealed = hpkeSeal(pubKey, plaintextBuf, infoBuf, aadBuf);
  const plaintextDigest = `sha256:${createHash('sha256').update(plaintextBuf).digest('hex')}`;
  const ciphertextDigest = `sha256:${createHash('sha256')
    .update(sealed.enc)
    .update(sealed.ciphertext)
    .digest('hex')}`;

  return {
    subjectId: input.subjectId,
    suite: 'DHKEM(P-256,HKDF-SHA256)/HKDF-SHA256/AES-128-GCM',
    encBase64Url: sealed.enc.toString('base64url'),
    ciphertextBase64Url: sealed.ciphertext.toString('base64url'),
    enc: sealed.enc,
    ciphertext: sealed.ciphertext,
    ciphertextDigest,
    plaintextDigest,
  };
}
