// SPDX-License-Identifier: Apache-2.0
/**
 * ML-DSA (FIPS 204, RFC 9964 COSE ids -48/-49/-50) via @noble/post-quantum,
 * the audited JavaScript implementation. Node's crypto has no ML-DSA, so
 * this fills the verification gap for hybrid countersignatures and gives
 * non-KMS deployments a real signer. COSE keys use the AKP key type (7)
 * with the raw public key at label -1 per RFC 9964.
 *
 * Also implements NIST FIPS 204 deterministic keygen/signing and Post-Quantum
 * Certificate / Key Attestation chains (OID 2.16.840.1.101.3.4.3.18 id-ml-dsa-65,
 * pure PQ or hybrid ES256 + ML-DSA-65).
 */
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha224, sha256 as nobleSha256, sha384, sha512, sha512_224, sha512_256 } from '@noble/hashes/sha2.js';
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256 } from '@noble/hashes/sha3.js';
import { randomBytes, type KeyObject } from 'node:crypto';
import {
  COSE_ALG,
  sha256,
  verifyWithAlg,
  publicKeyFromCoseKey,
  decodeCoseKey,
  type CoseAlg,
  type ReceiptSigner,
} from './keys.js';
import { cborEncode, cborDecode, cborToPlain } from './cbor.js';

export const OID_ML_DSA_44 = '2.16.840.1.101.3.4.3.17';
export const OID_ML_DSA_65 = '2.16.840.1.101.3.4.3.18';
export const OID_ML_DSA_87 = '2.16.840.1.101.3.4.3.19';

export const ML_DSA_OIDS: Record<number, string> = {
  [COSE_ALG.MLDSA44]: OID_ML_DSA_44,
  [COSE_ALG.MLDSA65]: OID_ML_DSA_65,
  [COSE_ALG.MLDSA87]: OID_ML_DSA_87,
};

const VARIANTS = {
  [COSE_ALG.MLDSA44]: ml_dsa44,
  [COSE_ALG.MLDSA65]: ml_dsa65,
  [COSE_ALG.MLDSA87]: ml_dsa87,
} as const;

export interface MlDsaKeyPair {
  alg: CoseAlg;
  oid: string;
  seed: Buffer;
  publicKey: Buffer;
  secretKey: Buffer;
  pkHash: string;
  skHash: string;
}

/** Deterministic FIPS 204 ML-DSA key generation from a 32-byte seed. */
export function mlDsaKeygenFromSeed(
  seed32: Uint8Array,
  alg: CoseAlg = COSE_ALG.MLDSA65,
): MlDsaKeyPair {
  if (seed32.length !== 32) {
    throw new Error(`ML-DSA keygen seed must be 32 bytes, got ${seed32.length}`);
  }
  const variant = VARIANTS[alg as keyof typeof VARIANTS];
  if (!variant) throw new Error(`not an ML-DSA alg: ${alg}`);
  const { publicKey, secretKey } = variant.keygen(seed32);
  const pubBuf = Buffer.from(publicKey);
  const secBuf = Buffer.from(secretKey);
  return {
    alg,
    oid: ML_DSA_OIDS[alg] ?? OID_ML_DSA_65,
    seed: Buffer.from(seed32),
    publicKey: pubBuf,
    secretKey: secBuf,
    pkHash: sha256(pubBuf).toString('hex'),
    skHash: sha256(secBuf).toString('hex'),
  };
}

/** Random FIPS 204 ML-DSA key generation using 32 CSPRNG bytes. */
export function mlDsaKeygen(alg: CoseAlg = COSE_ALG.MLDSA65): MlDsaKeyPair {
  return mlDsaKeygenFromSeed(randomBytes(32), alg);
}

export type MlDsaPreHashAlg =
  | 'SHA2-224'
  | 'SHA2-256'
  | 'SHA2-384'
  | 'SHA2-512'
  | 'SHA2-512/224'
  | 'SHA2-512/256'
  | 'SHA3-224'
  | 'SHA3-256'
  | 'SHA3-384'
  | 'SHA3-512'
  | 'SHAKE-128'
  | 'SHAKE-256';

// DER tag+length + NIST hash OID arc 2.16.840.1.101.3.4.2.<id> per FIPS 204 Section 5.4 (Algorithms 4 & 5)
const NIST_HASH_OID_PREFIX = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02] as const;

const PREHASH_ALGS: Record<MlDsaPreHashAlg, { oid: Uint8Array; hash: (m: Uint8Array) => Uint8Array }> = {
  'SHA2-256': { oid: Uint8Array.from([...NIST_HASH_OID_PREFIX, 0x01]), hash: (m) => nobleSha256(m) },
  'SHA2-384': { oid: Uint8Array.from([...NIST_HASH_OID_PREFIX, 0x02]), hash: (m) => sha384(m) },
  'SHA2-512': { oid: Uint8Array.from([...NIST_HASH_OID_PREFIX, 0x03]), hash: (m) => sha512(m) },
  'SHA2-224': { oid: Uint8Array.from([...NIST_HASH_OID_PREFIX, 0x04]), hash: (m) => sha224(m) },
  'SHA2-512/224': { oid: Uint8Array.from([...NIST_HASH_OID_PREFIX, 0x05]), hash: (m) => sha512_224(m) },
  'SHA2-512/256': { oid: Uint8Array.from([...NIST_HASH_OID_PREFIX, 0x06]), hash: (m) => sha512_256(m) },
  'SHA3-224': { oid: Uint8Array.from([...NIST_HASH_OID_PREFIX, 0x07]), hash: (m) => sha3_224(m) },
  'SHA3-256': { oid: Uint8Array.from([...NIST_HASH_OID_PREFIX, 0x08]), hash: (m) => sha3_256(m) },
  'SHA3-384': { oid: Uint8Array.from([...NIST_HASH_OID_PREFIX, 0x09]), hash: (m) => sha3_384(m) },
  'SHA3-512': { oid: Uint8Array.from([...NIST_HASH_OID_PREFIX, 0x0a]), hash: (m) => sha3_512(m) },
  'SHAKE-128': { oid: Uint8Array.from([...NIST_HASH_OID_PREFIX, 0x0b]), hash: (m) => shake128(m, { dkLen: 32 }) },
  'SHAKE-256': { oid: Uint8Array.from([...NIST_HASH_OID_PREFIX, 0x0c]), hash: (m) => shake256(m, { dkLen: 64 }) },
};

function buildHashMlDsaMessage(preHash: string, msg: Uint8Array, context?: Uint8Array): Buffer {
  const entry = PREHASH_ALGS[preHash as MlDsaPreHashAlg];
  if (!entry) throw new Error(`unsupported HashML-DSA preHash algorithm: ${preHash}`);
  const ctx = context ?? new Uint8Array(0);
  if (ctx.length > 255) throw new RangeError('ML-DSA context must be at most 255 bytes');
  const ph = entry.hash(msg);
  return Buffer.concat([Buffer.from([0x01, ctx.length]), Buffer.from(ctx), Buffer.from(entry.oid), Buffer.from(ph)]);
}

export interface MlDsaSignOptions {
  deterministic?: boolean;
  extraEntropy?: Uint8Array | false;
  context?: Uint8Array;
  preHash?: MlDsaPreHashAlg | string;
  internal?: boolean;
  externalMu?: boolean;
}

export interface MlDsaVerifyOptions {
  context?: Uint8Array;
  preHash?: MlDsaPreHashAlg | string;
  internal?: boolean;
  externalMu?: boolean;
}

/** Sign a message with ML-DSA (FIPS 204 pure, HashML-DSA preHash, or internal/externalMu). */
export function mlDsaSign(
  alg: CoseAlg,
  secretKey: Uint8Array,
  msg: Uint8Array,
  opts: MlDsaSignOptions = {},
): Buffer {
  const variant = VARIANTS[alg as keyof typeof VARIANTS];
  if (!variant) throw new Error(`not an ML-DSA alg: ${alg}`);
  const extraEntropy =
    opts.extraEntropy !== undefined
      ? opts.extraEntropy
      : opts.deterministic === false
        ? randomBytes(32)
        : false;
  if (opts.internal || opts.externalMu !== undefined) {
    const sig = variant.internal.sign(msg, secretKey, {
      extraEntropy,
      externalMu: Boolean(opts.externalMu),
    });
    return Buffer.from(sig);
  }
  if (opts.preHash && opts.preHash !== 'pure' && opts.preHash !== 'none') {
    const mPrime = buildHashMlDsaMessage(opts.preHash, msg, opts.context);
    const sig = variant.internal.sign(mPrime, secretKey, { extraEntropy });
    return Buffer.from(sig);
  }
  const sig = variant.sign(msg, secretKey, {
    extraEntropy,
    ...(opts.context ? { context: opts.context } : {}),
  });
  return Buffer.from(sig);
}

export function mlDsaVerify(
  alg: CoseAlg,
  publicKey: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array,
  opts?: MlDsaVerifyOptions,
): boolean {
  const variant = VARIANTS[alg as keyof typeof VARIANTS];
  if (!variant) return false;
  try {
    if (opts?.internal || opts?.externalMu !== undefined) {
      return variant.internal.verify(sig, msg, publicKey, {
        externalMu: Boolean(opts.externalMu),
      });
    }
    if (opts?.preHash && opts.preHash !== 'pure' && opts.preHash !== 'none') {
      const mPrime = buildHashMlDsaMessage(opts.preHash, msg, opts.context);
      return variant.internal.verify(sig, mPrime, publicKey);
    }
    return variant.verify(sig, msg, publicKey, opts?.context ? { context: opts.context } : undefined);
  } catch {
    return false;
  }
}

export class MlDsaSigner implements ReceiptSigner {
  readonly alg: CoseAlg;
  readonly secretKey: Uint8Array;
  readonly publicKeyBytes: Uint8Array;
  constructor(seed32: Uint8Array, readonly kid: string, alg: CoseAlg = COSE_ALG.MLDSA65) {
    const variant = VARIANTS[alg as keyof typeof VARIANTS];
    if (!variant) throw new Error(`not an ML-DSA alg: ${alg}`);
    const { publicKey, secretKey } = variant.keygen(seed32);
    this.publicKeyBytes = publicKey;
    this.secretKey = secretKey;
    this.alg = alg;
  }
  async sign(data: Buffer): Promise<Buffer> {
    const variant = VARIANTS[this.alg as keyof typeof VARIANTS];
    return Buffer.from(variant.sign(data, this.secretKey, { extraEntropy: false }));
  }
  publicCoseKey(): Map<number, unknown> {
    const m = new Map<number, unknown>();
    m.set(1, 7); // AKP
    m.set(2, Buffer.from(this.kid, 'utf8'));
    m.set(3, this.alg);
    m.set(-1, Buffer.from(this.publicKeyBytes));
    return m;
  }
  publicKeyObject(): KeyObject {
    throw new Error('ML-DSA keys have no Node KeyObject; use publicKeyBytes with mlDsaVerify');
  }
}

/** Extract an AKP public key from a decoded COSE_Key map, if present. */
export function akpPublicKeyFromCose(
  coseKey: Map<unknown, unknown>,
): { kid: string; alg: CoseAlg; publicKey: Buffer } | null {
  if (coseKey.get(1) !== 7) return null;
  const raw = coseKey.get(-1);
  if (!(raw instanceof Uint8Array)) return null;
  const kidRaw = coseKey.get(2);
  return {
    kid: kidRaw instanceof Uint8Array ? Buffer.from(kidRaw).toString('utf8') : '',
    alg: Number(coseKey.get(3)) as CoseAlg,
    publicKey: Buffer.from(raw),
  };
}

// --- Post-Quantum Certificates / Key Attestations (Pure & Hybrid) ------------

export interface PqCertificateTbs {
  version: 3;
  serialNumber: string;
  issuer: string;
  subject: string;
  notBefore: string; // ISO-8601
  notAfter: string;  // ISO-8601
  isCA: boolean;
  algorithmOid: string; // e.g., OID_ML_DSA_65 ('2.16.840.1.101.3.4.3.18')
  coseAlg: CoseAlg;
  subjectPublicKey: Buffer;
  /** Optional classical COSE_Key (e.g. ES256) for composite/hybrid certificates. */
  classicalCoseKey?: Buffer;
}

export interface PqCertificate {
  tbs: PqCertificateTbs;
  tbsBytes: Buffer;
  pqSignature: Buffer;
  /** Present when issued as a hybrid (ES256 + ML-DSA-65) certificate. */
  classicalSignature?: Buffer;
  classicalAlg?: CoseAlg;
}

export function encodePqCertificateTbs(tbs: PqCertificateTbs): Buffer {
  return cborEncode({
    version: tbs.version,
    serial_number: tbs.serialNumber,
    issuer: tbs.issuer,
    subject: tbs.subject,
    not_before: tbs.notBefore,
    not_after: tbs.notAfter,
    is_ca: tbs.isCA,
    algorithm_oid: tbs.algorithmOid,
    cose_alg: tbs.coseAlg,
    subject_public_key: Buffer.from(tbs.subjectPublicKey),
    ...(tbs.classicalCoseKey ? { classical_cose_key: Buffer.from(tbs.classicalCoseKey) } : {}),
  } as never);
}

/**
 * Issue a Post-Quantum (pure ML-DSA-65 or hybrid ES256 + ML-DSA-65) certificate.
 * Carry NIST OID 2.16.840.1.101.3.4.3.18 (id-ml-dsa-65) in TBS.
 */
export async function issuePqCertificate(input: {
  serialNumber: string;
  issuer: string;
  subject: string;
  notBefore: string;
  notAfter: string;
  isCA: boolean;
  subjectPqPublicKey: Uint8Array;
  subjectCoseAlg?: CoseAlg;
  subjectClassicalSigner?: ReceiptSigner;
  issuerPqSigner: MlDsaSigner;
  issuerClassicalSigner?: ReceiptSigner;
}): Promise<PqCertificate> {
  const coseAlg = input.subjectCoseAlg ?? COSE_ALG.MLDSA65;
  const algorithmOid = ML_DSA_OIDS[coseAlg] ?? OID_ML_DSA_65;
  const classicalCoseKey = input.subjectClassicalSigner
    ? cborEncode(input.subjectClassicalSigner.publicCoseKey())
    : undefined;
  const tbs: PqCertificateTbs = {
    version: 3,
    serialNumber: input.serialNumber,
    issuer: input.issuer,
    subject: input.subject,
    notBefore: input.notBefore,
    notAfter: input.notAfter,
    isCA: input.isCA,
    algorithmOid,
    coseAlg,
    subjectPublicKey: Buffer.from(input.subjectPqPublicKey),
    ...(classicalCoseKey ? { classicalCoseKey } : {}),
  };
  const tbsBytes = encodePqCertificateTbs(tbs);
  const pqSignature = await input.issuerPqSigner.sign(tbsBytes);
  const classicalSignature = input.issuerClassicalSigner
    ? await input.issuerClassicalSigner.sign(tbsBytes)
    : undefined;
  return {
    tbs,
    tbsBytes,
    pqSignature,
    ...(classicalSignature
      ? { classicalSignature, classicalAlg: input.issuerClassicalSigner!.alg }
      : {}),
  };
}

export function encodePqCertificateCbor(cert: PqCertificate): Buffer {
  return cborEncode({
    tbs: cborToPlain(cborDecode(cert.tbsBytes)),
    tbs_bytes: cert.tbsBytes,
    pq_signature: cert.pqSignature,
    ...(cert.classicalSignature
      ? { classical_signature: cert.classicalSignature, classical_alg: cert.classicalAlg }
      : {}),
  } as never);
}

/**
 * Validate a Post-Quantum certificate chain (Root CA PQ -> Leaf PQ) and
 * optionally verify hybrid classical + PQ signatures on both certificates.
 */
export function verifyPqCertificateChain(
  caCert: PqCertificate,
  leafCert: PqCertificate,
  opts: { now?: Date; requireHybrid?: boolean } = {},
): { valid: boolean; detail: string } {
  const now = (opts.now ?? new Date()).getTime();
  // 1. Check CA constraints
  if (!caCert.tbs.isCA) return { valid: false, detail: 'root certificate is not a CA' };
  if (caCert.tbs.issuer !== caCert.tbs.subject) {
    return { valid: false, detail: 'root CA is not self-issued' };
  }
  if (caCert.tbs.algorithmOid !== (ML_DSA_OIDS[caCert.tbs.coseAlg] ?? OID_ML_DSA_65)) {
    return { valid: false, detail: 'root CA OID does not match ML-DSA algorithm' };
  }
  if (now < Date.parse(caCert.tbs.notBefore) || now > Date.parse(caCert.tbs.notAfter)) {
    return { valid: false, detail: 'root CA certificate outside validity window' };
  }
  if (!encodePqCertificateTbs(caCert.tbs).equals(caCert.tbsBytes)) {
    return { valid: false, detail: 'root CA TBS encoding mismatch' };
  }
  // Verify CA self-signature (ML-DSA)
  if (!mlDsaVerify(caCert.tbs.coseAlg, caCert.tbs.subjectPublicKey, caCert.tbsBytes, caCert.pqSignature)) {
    return { valid: false, detail: 'root CA ML-DSA signature invalid' };
  }
  if (opts.requireHybrid && (!caCert.classicalSignature || !caCert.tbs.classicalCoseKey)) {
    return { valid: false, detail: 'root CA missing required hybrid classical signature' };
  }
  if (caCert.classicalSignature) {
    if (!caCert.tbs.classicalCoseKey || !caCert.classicalAlg) {
      return { valid: false, detail: 'root CA missing classical public key for hybrid signature' };
    }
    const caClassicalPub = publicKeyFromCoseKey(decodeCoseKey(caCert.tbs.classicalCoseKey)).key;
    if (!verifyWithAlg(caCert.classicalAlg, caClassicalPub, caCert.tbsBytes, caCert.classicalSignature)) {
      return { valid: false, detail: 'root CA classical hybrid signature invalid' };
    }
  }

  // 2. Check Leaf constraints
  if (leafCert.tbs.isCA) return { valid: false, detail: 'leaf certificate must not have isCA=true' };
  if (leafCert.tbs.issuer !== caCert.tbs.subject) {
    return { valid: false, detail: 'leaf certificate issuer does not match CA subject' };
  }
  if (leafCert.tbs.algorithmOid !== (ML_DSA_OIDS[leafCert.tbs.coseAlg] ?? OID_ML_DSA_65)) {
    return { valid: false, detail: 'leaf OID does not match ML-DSA algorithm' };
  }
  if (now < Date.parse(leafCert.tbs.notBefore) || now > Date.parse(leafCert.tbs.notAfter)) {
    return { valid: false, detail: 'leaf certificate outside validity window' };
  }
  if (!encodePqCertificateTbs(leafCert.tbs).equals(leafCert.tbsBytes)) {
    return { valid: false, detail: 'leaf TBS encoding mismatch' };
  }
  // Verify Leaf PQ signature under CA's PQ public key
  if (!mlDsaVerify(caCert.tbs.coseAlg, caCert.tbs.subjectPublicKey, leafCert.tbsBytes, leafCert.pqSignature)) {
    return { valid: false, detail: 'leaf ML-DSA signature invalid under CA key' };
  }
  if (opts.requireHybrid && (!leafCert.classicalSignature || !leafCert.tbs.classicalCoseKey)) {
    return { valid: false, detail: 'leaf certificate missing required hybrid classical signature' };
  }
  if (leafCert.classicalSignature) {
    if (!caCert.tbs.classicalCoseKey || !leafCert.classicalAlg) {
      return { valid: false, detail: 'CA missing classical key to verify leaf hybrid signature' };
    }
    const caClassicalPub = publicKeyFromCoseKey(decodeCoseKey(caCert.tbs.classicalCoseKey)).key;
    if (!verifyWithAlg(leafCert.classicalAlg, caClassicalPub, leafCert.tbsBytes, leafCert.classicalSignature)) {
      return { valid: false, detail: 'leaf classical hybrid signature invalid under CA key' };
    }
  }

  return { valid: true, detail: `verified PQ chain (${leafCert.tbs.algorithmOid})` };
}
