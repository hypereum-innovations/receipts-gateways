// SPDX-License-Identifier: Apache-2.0
/**
 * Signing keys for Hivemind Receipts. One `ReceiptSigner` interface covers
 * local keys (dev/tests), AWS KMS keys (production custody), and ML-DSA keys
 * held in KMS (post-quantum countersignatures). COSE algorithm ids:
 * ES256 = -7, EdDSA = -8, ML-DSA-44/65/87 = -48/-49/-50 (RFC 9964).
 * Public keys travel as COSE_Key maps so every verifier sees the same bytes.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';
import { cborDecode, cborEncode } from './cbor.js';

export const COSE_ALG = {
  ES256: -7,
  EdDSA: -8,
  ES384: -35,
  MLDSA44: -48,
  MLDSA65: -49,
  MLDSA87: -50,
} as const;
export type CoseAlg = (typeof COSE_ALG)[keyof typeof COSE_ALG];

/**
 * Registered COSE signature algorithms accepted for customer-issued statements
 * [OWNER; default EdDSA, ES256, ES384].
 */
export const CUSTOMER_ISSUER_ALLOWED_ALGS: readonly CoseAlg[] = [
  COSE_ALG.EdDSA,
  COSE_ALG.ES256,
  COSE_ALG.ES384,
] as const;

/**
 * Keys operated by Hypereum (log checkpoint and receipt keys, Hivemind AX issuer keys)
 * are restricted to EdDSA (-8) only per Ruling R83.
 */
export const HYPEREUM_OPERATED_ALLOWED_ALGS: readonly CoseAlg[] = [
  COSE_ALG.EdDSA,
] as const;

export type ReceiptsMode = 'dev' | 'prod';

/**
 * Resolve the active key-custody mode (`RECEIPTS_MODE=dev|prod`).
 * - `'dev'` (default when unset in dev/test): file/env keys permitted, prints `"DEV KEYS"` at boot.
 * - `'prod'`: process refuses to start if any signing key comes from a PEM file, an env seed,
 *   `reconstructSecret`, or server-held raw HPKE private keys; requires KMS/HSM or FROST custody.
 */
export function getReceiptsMode(env: NodeJS.ProcessEnv = process.env): ReceiptsMode {
  const raw = env['RECEIPTS_MODE'];
  if (raw === undefined || raw === '' || raw === 'dev') return 'dev';
  if (raw === 'prod') return 'prod';
  throw new Error(`Invalid RECEIPTS_MODE "${raw}": must be 'dev' or 'prod'`);
}

export function assertDevKeyCustodyAllowed(source: string, env: NodeJS.ProcessEnv = process.env): void {
  if (getReceiptsMode(env) === 'prod') {
    throw new Error(
      `[RECEIPTS_MODE=prod] Key custody violation: refusing to use ${source} in prod mode (KMS/HSM or FROST required)`,
    );
  }
}

export function logDevKeysBanner(detail = 'file/env keys enabled for development'): string {
  const line = `DEV KEYS: RECEIPTS_MODE=dev (${detail})`;
  console.log(line);
  return line;
}

export function sha256(data: Uint8Array | string): Buffer {
  return createHash('sha256').update(data).digest();
}
export function b64u(buf: Uint8Array): string {
  return Buffer.from(buf).toString('base64url');
}
export function b64uDecode(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

export interface ReceiptSigner {
  readonly alg: CoseAlg;
  readonly kid: string;
  sign(data: Buffer): Promise<Buffer>;
  publicCoseKey(): Map<number, unknown>;
  publicKeyObject(): KeyObject;
}

export function coseKeyFromPublic(publicKey: KeyObject, kid?: string): Map<number, unknown> {
  const jwk = publicKey.export({ format: 'jwk' }) as {
    kty?: string;
    crv?: string;
    x?: string;
    y?: string;
  };
  const m = new Map<number, unknown>();
  if (jwk.kty === 'EC') {
    const isP384 = jwk.crv === 'P-384';
    m.set(1, 2); // kty EC2
    m.set(3, isP384 ? COSE_ALG.ES384 : COSE_ALG.ES256);
    m.set(-1, isP384 ? 2 : 1); // crv P-384 (2) or P-256 (1)
    m.set(-2, b64uDecode(jwk.x!));
    m.set(-3, b64uDecode(jwk.y!));
  } else if (jwk.kty === 'OKP') {
    m.set(1, 1); // kty OKP
    m.set(3, COSE_ALG.EdDSA);
    m.set(-1, 6); // crv Ed25519
    m.set(-2, b64uDecode(jwk.x!));
  } else throw new Error(`unsupported key type ${String(jwk.kty)}`);
  const resolvedKid = kid && kid.length > 0 ? kid : coseKeyThumbprint(publicKey);
  m.set(2, Buffer.from(resolvedKid, 'utf8'));
  return m;
}

/**
 * RFC 9679 COSE Key Thumbprint over the deterministic CBOR encoding (RFC 8949 §4.2.1)
 * of the required public key parameters ({1: kty, -1: crv, -2: x[, -3: y]}).
 */
export function coseKeyThumbprint(publicKey: KeyObject): string {
  const jwk = publicKey.export({ format: 'jwk' }) as {
    kty?: string;
    crv?: string;
    x?: string;
    y?: string;
  };
  const thumbprintMap = new Map<number, unknown>();
  if (jwk.kty === 'EC') {
    thumbprintMap.set(1, 2);
    thumbprintMap.set(-1, jwk.crv === 'P-384' ? 2 : 1);
    thumbprintMap.set(-2, b64uDecode(jwk.x!));
    thumbprintMap.set(-3, b64uDecode(jwk.y!));
  } else if (jwk.kty === 'OKP') {
    thumbprintMap.set(1, 1);
    thumbprintMap.set(-1, 6);
    thumbprintMap.set(-2, b64uDecode(jwk.x!));
  } else {
    throw new Error(`unsupported key type ${String(jwk.kty)}`);
  }
  return b64u(sha256(cborEncode(thumbprintMap)));
}

/** Compute the RFC 9679 COSE Key Thumbprint directly from a decoded COSE_Key map. */
export function coseKeyThumbprintFromCoseKey(coseKey: Map<unknown, unknown>): string {
  const kty = Number(coseKey.get(1));
  const crv = Number(coseKey.get(-1));
  const x = Buffer.from(coseKey.get(-2) as Uint8Array);
  const thumbprintMap = new Map<number, unknown>([
    [1, kty],
    [-1, crv],
    [-2, x],
  ]);
  if (kty === 2) {
    thumbprintMap.set(-3, Buffer.from(coseKey.get(-3) as Uint8Array));
  }
  return b64u(sha256(cborEncode(thumbprintMap)));
}

export function publicKeyFromCoseKey(coseKey: Map<unknown, unknown>): { key: KeyObject; alg: CoseAlg; kid: string } {
  const kty = coseKey.get(1);
  const kidRaw = coseKey.get(2);
  const rawKidStr = kidRaw instanceof Uint8Array ? Buffer.from(kidRaw).toString('utf8') : String(kidRaw ?? '');
  const kid = rawKidStr.length > 0 ? rawKidStr : coseKeyThumbprintFromCoseKey(coseKey);
  if (kty === 2) {
    const crv = Number(coseKey.get(-1));
    const isP384 = crv === 2;
    return {
      alg: isP384 ? COSE_ALG.ES384 : COSE_ALG.ES256,
      kid,
      key: createPublicKey({
        format: 'jwk',
        key: {
          kty: 'EC',
          crv: isP384 ? 'P-384' : 'P-256',
          x: b64u(coseKey.get(-2) as Uint8Array),
          y: b64u(coseKey.get(-3) as Uint8Array),
        },
      }),
    };
  }
  if (kty === 1) {
    return {
      alg: COSE_ALG.EdDSA,
      kid,
      key: createPublicKey({
        format: 'jwk',
        key: { kty: 'OKP', crv: 'Ed25519', x: b64u(coseKey.get(-2) as Uint8Array) },
      }),
    };
  }
  throw new Error(`unsupported COSE key type ${String(kty)}`);
}

export function verifyWithAlg(alg: CoseAlg, key: KeyObject, data: Buffer, sig: Buffer): boolean {
  if (alg === COSE_ALG.ES256)
    return cryptoVerify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, sig);
  if (alg === COSE_ALG.ES384)
    return cryptoVerify('sha384', data, { key, dsaEncoding: 'ieee-p1363' }, sig);
  if (alg === COSE_ALG.EdDSA) return cryptoVerify(null, data, key, sig);
  throw new Error(`algorithm ${alg} needs a KMS-backed verifier in this runtime`);
}

export class LocalSigner implements ReceiptSigner {
  readonly alg: CoseAlg;
  readonly kid: string;
  constructor(
    private readonly privateKey: KeyObject,
    kid?: string,
  ) {
    const pub = createPublicKey(privateKey);
    const jwk = pub.export({ format: 'jwk' }) as { kty?: string; crv?: string };
    this.alg =
      jwk.kty === 'OKP'
        ? COSE_ALG.EdDSA
        : jwk.crv === 'P-384'
          ? COSE_ALG.ES384
          : COSE_ALG.ES256;
    this.kid = kid && kid.length > 0 ? kid : coseKeyThumbprint(pub);
  }
  static generate(kind: 'ES256' | 'ES384' | 'Ed25519', kid?: string): LocalSigner {
    const { privateKey } =
      kind === 'Ed25519'
        ? generateKeyPairSync('ed25519')
        : generateKeyPairSync('ec', { namedCurve: kind === 'ES384' ? 'P-384' : 'P-256' });
    return new LocalSigner(privateKey, kid);
  }
  static fromPem(pem: string, kid?: string, env: NodeJS.ProcessEnv = process.env): LocalSigner {
    assertDevKeyCustodyAllowed(`LocalSigner.fromPem (PEM private key for ${kid ?? 'thumbprint'})`, env);
    return new LocalSigner(createPrivateKey(pem), kid);
  }
  exportPrivatePem(env: NodeJS.ProcessEnv = process.env): string {
    assertDevKeyCustodyAllowed(`LocalSigner.exportPrivatePem (raw PEM private key export for ${this.kid})`, env);
    return this.privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;
  }
  async sign(data: Buffer): Promise<Buffer> {
    if (this.alg === COSE_ALG.EdDSA) return cryptoSign(null, data, this.privateKey);
    if (this.alg === COSE_ALG.ES384)
      return cryptoSign('sha384', data, { key: this.privateKey, dsaEncoding: 'ieee-p1363' });
    return cryptoSign('sha256', data, { key: this.privateKey, dsaEncoding: 'ieee-p1363' });
  }
  publicKeyObject(): KeyObject {
    return createPublicKey(this.privateKey);
  }
  publicCoseKey(): Map<number, unknown> {
    return coseKeyFromPublic(this.publicKeyObject(), this.kid);
  }
  thumbprint(): string {
    return coseKeyThumbprint(this.publicKeyObject());
  }
}

/**
 * Hardware KMS / CloudHSM signer. Uses the repository's existing @aws-sdk/client-kms.
 * - ES256 (`COSE_ALG.ES256` = -7): signs with `ECDSA_SHA_256` over the SHA-256 digest,
 *   converting DER to IEEE P1363.
 * - EdDSA (`COSE_ALG.EdDSA` = -8): signs raw messages with `ED25519_SHA_512` (PureEd25519 on
 *   ECC_NIST_EDWARDS25519 / CloudHSM).
 * - ML-DSA (`COSE_ALG.MLDSA44/65/87`): signs raw messages with `ML_DSA_SHAKE_256` (FIPS 204).
 * The SDK is loaded lazily so local verification never needs network access.
 */
export const KMS_ED25519_KEY_SPEC = 'ECC_NIST_EDWARDS25519' as const;
export const KMS_ED25519_SIGNING_ALGORITHM = 'ED25519_SHA_512' as const;
export const KMS_ED25519_MESSAGE_TYPE = 'RAW' as const;

/**
 * Ruling R83 (supersedes R82) & SP-RECEIPTS-FIX-04 Item 4:
 * - Every published keyring entry and receipt uses `kid = coseKeyThumbprint(publicKey)` (RFC 9679).
 * - No KMS ARN, account ID, or region string is embedded in public artifacts.
 */
export const PRODUCTION_RECEIPTS_KMS_ALIAS = 'alias/hivemind-receipts-signing' as const;
export const PRODUCTION_RECEIPTS_KMS_KEY_ID = '6ba57522-5cb3-47db-9554-1346754a83ff' as const;
export const PRODUCTION_RECEIPTS_KID = '4rNCv0rPePZkoNgP5CZzsYoltOKkLPO8zbV7E0CPRRo' as const;

export const NONPROD_CONFORMANCE_KMS_KEY_ID = '04c641ee-a4e6-49c9-a91c-4393a65fa46d' as const;
export const NONPROD_CONFORMANCE_KID = '7qZtsGuOy1CEt_-3lzTbqb2lNAmwFtQm4cx9OL3FmUA' as const;

export const RETIRED_P256_KMS_KEY_ID = 'd2902780-e901-46e6-8ae4-03be619a078a' as const;

export class KmsSigner implements ReceiptSigner {
  private client: unknown = null;
  private pub: KeyObject | null = null;
  private readonly region: string | undefined;
  private readonly explicitKid: string | undefined;
  readonly kid: string;
  constructor(
    readonly keyId: string,
    readonly alg: CoseAlg = COSE_ALG.EdDSA,
    kid?: string,
    region?: string,
    clientOverride?: unknown,
  ) {
    if (keyId.includes(RETIRED_P256_KMS_KEY_ID)) {
      throw new Error(
        `KMS P-256 key ${RETIRED_P256_KMS_KEY_ID} is retired per Ruling R83; use Ed25519 key ${PRODUCTION_RECEIPTS_KMS_ALIAS}`,
      );
    }
    const parts = keyId.split(':');
    const parsedRegion = parts.length >= 6 && parts[3] ? parts[3] : undefined;
    this.region = region ?? parsedRegion ?? process.env['AWS_REGION'];
    const cleanKid = kid && kid.length > 0 && !kid.includes(':') ? kid : undefined;
    this.explicitKid = cleanKid;
    this.kid = cleanKid ?? (keyId.includes(NONPROD_CONFORMANCE_KMS_KEY_ID) ? NONPROD_CONFORMANCE_KID : PRODUCTION_RECEIPTS_KID);
    if (clientOverride) this.client = clientOverride;
  }
  preloadPublicKey(pub: KeyObject): this {
    this.pub = pub;
    if (!this.explicitKid) {
      (this as { kid: string }).kid = coseKeyThumbprint(pub);
    }
    return this;
  }
  private async kms(): Promise<{ client: never; SignCommand: never; GetPublicKeyCommand: never }> {
    const mod = (await import('@aws-sdk/client-kms')) as unknown as {
      KMSClient: new (o: { region?: string }) => never;
      SignCommand: never;
      GetPublicKeyCommand: never;
    };
    if (!this.client) this.client = new mod.KMSClient(this.region ? { region: this.region } : {});
    return { client: this.client as never, SignCommand: mod.SignCommand, GetPublicKeyCommand: mod.GetPublicKeyCommand };
  }
  kmsAlg(): string {
    if (this.alg === COSE_ALG.ES256) return 'ECDSA_SHA_256';
    if (this.alg === COSE_ALG.ES384) return 'ECDSA_SHA_384';
    if (this.alg === COSE_ALG.EdDSA) return KMS_ED25519_SIGNING_ALGORITHM;
    if (this.alg === COSE_ALG.MLDSA44 || this.alg === COSE_ALG.MLDSA65 || this.alg === COSE_ALG.MLDSA87)
      return 'ML_DSA_SHAKE_256';
    throw new Error(`KMS does not serve COSE alg ${this.alg} here`);
  }
  async sign(data: Buffer): Promise<Buffer> {
    const { client, SignCommand } = await this.kms();
    const algName = this.kmsAlg();
    if (algName === 'ED25519_PH_SHA_512') {
      throw new Error('ED25519_PH_SHA_512 is forbidden; Ed25519 KMS signing requires ED25519_SHA_512 with MessageType RAW');
    }
    const isRawMsg = algName === 'ML_DSA_SHAKE_256' || algName === KMS_ED25519_SIGNING_ALGORITHM;
    const cmd = new (SignCommand as new (i: unknown) => unknown)({
      KeyId: this.keyId,
      Message: isRawMsg ? data : sha256(data),
      MessageType: isRawMsg ? KMS_ED25519_MESSAGE_TYPE : 'DIGEST',
      SigningAlgorithm: algName,
    });
    const out = (await (client as { send(c: unknown): Promise<{ Signature?: Uint8Array }> }).send(cmd)) as {
      Signature?: Uint8Array;
    };
    if (!out.Signature) throw new Error('KMS returned no signature');
    const raw = Buffer.from(out.Signature);
    if (this.alg === COSE_ALG.ES256) return derEcdsaToP1363(raw, 32);
    if (this.alg === COSE_ALG.ES384) return derEcdsaToP1363(raw, 48);
    return raw;
  }
  async loadPublicKey(): Promise<KeyObject> {
    if (this.pub) return this.pub;
    const { client, GetPublicKeyCommand } = await this.kms();
    const cmd = new (GetPublicKeyCommand as new (i: unknown) => unknown)({ KeyId: this.keyId });
    const out = (await (client as { send(c: unknown): Promise<{ PublicKey?: Uint8Array; KeySpec?: string }> }).send(
      cmd,
    )) as {
      PublicKey?: Uint8Array;
      KeySpec?: string;
    };
    if (!out.PublicKey) throw new Error('KMS returned no public key');
    if (out.KeySpec === KMS_ED25519_KEY_SPEC && this.alg !== COSE_ALG.EdDSA) {
      (this as { alg: CoseAlg }).alg = COSE_ALG.EdDSA;
    }
    if (this.alg === COSE_ALG.EdDSA && out.KeySpec && out.KeySpec !== KMS_ED25519_KEY_SPEC) {
      throw new Error(`KMS Ed25519 log signer requires KeySpec ${KMS_ED25519_KEY_SPEC}, got ${out.KeySpec}`);
    }
    this.pub = createPublicKey({ key: Buffer.from(out.PublicKey), format: 'der', type: 'spki' });
    if (this.alg === COSE_ALG.EdDSA && this.pub.asymmetricKeyType !== 'ed25519') {
      throw new Error(`KMS Ed25519 log signer public key must be ed25519, got ${String(this.pub.asymmetricKeyType)}`);
    }
    if (!this.explicitKid) {
      (this as { kid: string }).kid = coseKeyThumbprint(this.pub);
    }
    return this.pub;
  }
  publicKeyObject(): KeyObject {
    if (!this.pub) throw new Error('KmsSigner.loadPublicKey() must be awaited first');
    return this.pub;
  }
  publicCoseKey(): Map<number, unknown> {
    return coseKeyFromPublic(this.publicKeyObject(), this.kid);
  }
}

export function derEcdsaToP1363(der: Buffer, partLen: number): Buffer {
  // Strict DER: exact sequence length, INTEGER tags, no trailing data,
  // minimal positive encoding. (Wycheproof's InvalidEncoding class is the
  // reason lenient conversion is not acceptable here.)
  let i = 0;
  if (der[i++] !== 0x30) throw new Error('bad DER signature');
  let seqLen = der[i++]!;
  if (seqLen & 0x80) {
    const n = seqLen & 0x7f;
    if (n === 0 || n > 2) throw new Error('bad DER length');
    seqLen = 0;
    for (let k = 0; k < n; k++) seqLen = seqLen * 256 + der[i++]!;
  }
  if (i + seqLen !== der.length) throw new Error('DER signature: trailing or missing data');
  const parts: Buffer[] = [];
  for (let p = 0; p < 2; p++) {
    if (der[i++] !== 0x02) throw new Error('bad DER integer');
    let len = der[i++]!;
    if (len & 0x80) throw new Error('bad DER integer length');
    if (len === 0 || len > partLen + 1) throw new Error('DER integer out of range');
    let v: Buffer = der.subarray(i, i + len);
    i += len;
    if (v[0]! & 0x80) throw new Error('DER integer is negative');
    if (len > 1 && v[0] === 0 && !(v[1]! & 0x80)) throw new Error('DER integer not minimal');
    while (v.length > 1 && v[0] === 0) v = v.subarray(1);
    if (v.length > partLen) throw new Error('DER integer too large');
    parts.push(Buffer.concat([Buffer.alloc(partLen - v.length), v]));
  }
  if (i !== der.length) throw new Error('DER signature: trailing data');
  return Buffer.concat(parts);
}

export function p1363ToDerEcdsa(raw: Buffer): Buffer {
  const half = raw.length / 2;
  const ints = [raw.subarray(0, half), raw.subarray(half)].map((v) => {
    let b = Buffer.from(v);
    while (b.length > 1 && b[0] === 0) b = b.subarray(1);
    if (b[0]! & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
    return Buffer.concat([Buffer.from([0x02, b.length]), b]);
  });
  const body = Buffer.concat(ints);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

/** Decode a COSE_Key carried in a statement header or trust-root file. */
export function decodeCoseKey(bytes: Uint8Array): Map<unknown, unknown> {
  const v = cborDecode(bytes);
  if (!(v instanceof Map)) throw new Error('COSE_Key must be a CBOR map');
  return v as Map<unknown, unknown>;
}

// Crockford base32 ULID (action_id): 48-bit time + 80-bit randomness.
const ULID_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export function ulid(now = Date.now(), random: (n: number) => Buffer): string {
  let t = BigInt(now);
  let time = '';
  for (let i = 0; i < 10; i++) {
    time = ULID_ALPHABET[Number(t % 32n)]! + time;
    t /= 32n;
  }
  const rnd = random(10);
  let r = 0n;
  for (const b of rnd) r = (r << 8n) | BigInt(b);
  let rand = '';
  for (let i = 0; i < 16; i++) {
    rand = ULID_ALPHABET[Number(r % 32n)]! + rand;
    r /= 32n;
  }
  return time + rand;
}
export const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
