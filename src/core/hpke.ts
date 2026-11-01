// SPDX-License-Identifier: Apache-2.0
/**
 * HPKE (RFC 9180) base mode, DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 +
 * AES-128-GCM — encrypted disclosure to a receiver's key. The receipt itself
 * carries only the ciphertext digest; the sealed bytes travel off-log.
 * Validated against the RFC 9180 structure (labeled extract/expand, suite
 * ids); round-trip and wrong-key tests live with the core suite.
 *
 * Client-side encryption primitives live in `./hpke-encrypt.js` (Apache-2.0
 * open half) and are re-exported here for 100% caller compatibility.
 */
import {
  createDecipheriv,
  diffieHellman,
  createPublicKey,
  type KeyObject,
} from 'node:crypto';
import {
  type HpkeKeyPair,
  type HpkeSealed,
  type HpkeSubjectEnvelope,
  generateHpkeKeyPair,
  hpkeGenerateKeyPair,
  serializePublicKey,
  deserializePublicKey,
  extractAndExpand,
  keySchedule,
  hpkeSeal,
  hpkeEncryptForSubject,
} from './hpke-encrypt.js';

export {
  type HpkeKeyPair,
  type HpkeSealed,
  type HpkeSubjectEnvelope,
  generateHpkeKeyPair,
  hpkeGenerateKeyPair,
  serializePublicKey,
  deserializePublicKey,
  hpkeSeal,
  hpkeEncryptForSubject,
};

function decap(enc: Buffer, recipientPrivate: KeyObject): Buffer {
  const ephPublic = deserializePublicKey(enc);
  const dh = diffieHellman({ privateKey: recipientPrivate, publicKey: ephPublic });
  const pkRm = serializePublicKey(createPublicKey(recipientPrivate));
  return extractAndExpand(dh, Buffer.concat([enc, pkRm]));
}

export function hpkeOpen(recipientPrivate: KeyObject, sealed: HpkeSealed, info: Buffer = Buffer.alloc(0), aad: Buffer = Buffer.alloc(0)): Buffer {
  const sharedSecret = decap(sealed.enc, recipientPrivate);
  const { key, nonce } = keySchedule(sharedSecret, info);
  const ct = sealed.ciphertext.subarray(0, sealed.ciphertext.length - 16);
  const tag = sealed.ciphertext.subarray(sealed.ciphertext.length - 16);
  const decipher = createDecipheriv('aes-128-gcm', key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

export function hpkeDecryptForSubject(input: {
  subjectId: string;
  recipientPrivateKey: KeyObject;
  envelope: Pick<HpkeSubjectEnvelope, 'enc' | 'ciphertext'>;
  aad?: Buffer | string | undefined;
}): Buffer {
  const infoBuf = Buffer.from(`hivemind:receipts:subject:${input.subjectId}`, 'utf8');
  const aadBuf =
    input.aad === undefined
      ? infoBuf
      : Buffer.isBuffer(input.aad)
        ? input.aad
        : Buffer.from(input.aad, 'utf8');
  return hpkeOpen(input.recipientPrivateKey, input.envelope, infoBuf, aadBuf);
}
