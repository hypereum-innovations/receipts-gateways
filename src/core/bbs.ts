// SPDX-License-Identifier: Apache-2.0
/**
 * BBS Multi-Message Signatures & Zero-Knowledge Selective Disclosure Proofs on BLS12-381.
 *
 * Implements the IETF CFRG BBS signature scheme (`draft-irtf-cfrg-bbs-signatures-09`)
 * for ciphersuite `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_` on pairing-friendly
 * curve BLS12-381 (`@noble/curves/bls12-381`):
 *  - Public key in G2 (`W = BP2 * sk`, 96 bytes compressed)
 *  - Fixed point `P1` and extensible message generators `(Q_1, H_1, ..., H_L)` in G1 (48 bytes compressed)
 *    derived via `expand_message_xmd` + `hash_to_curve` (`BLS12381G1_XMD:SHA-256_SSWU_RO_`)
 *  - Signature `(A, e)` (80 bytes standard IETF `SignatureToOctets`) where:
 *      `domain = hash_to_scalar((PK, L, Q_1, H_1..H_L, ciphersuite_id, header))`
 *      `B = P_1 + Q_1 * domain + sum_{i=1..L} H_i * m_i`
 *      `e = hash_to_scalar(serialize((SK, m_1..m_L, domain)))`
 *      `A = B * (sk + e)^(-1)`
 *  - Verification via pairing equation:
 *      `e(A, W + BP2 * e) == e(B, BP2)`
 *  - Unlinkable Zero-Knowledge Selective Disclosure Proof (`CoreProofGen` / `CoreProofVerify`):
 *    Randomizes `(A, B)` with fresh blinding scalars `(r1, r2)` (`r3 = r2^-1`):
 *      `D = B * r2`
 *      `A_bar = A * (r1 * r2)`
 *      `B_bar = D * r1 - A_bar * e`
 *    and proves in zero knowledge via Fiat-Shamir Schnorr commitments `(T1, T2)` Knowledge of
 *    `(e, r1, r3, {m_j}_{j in U})` bound to `header` and `presentation_header` (`nonce`).
 */
import { randomBytes } from 'node:crypto';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { expand_message_xmd } from '@noble/curves/abstract/hash-to-curve.js';
import { sha256 } from '@noble/hashes/sha2.js';
import type { Capsule } from './capsule.js';

const G1 = bls12_381.G1;
const G2 = bls12_381.G2;
const Fr = bls12_381.fields.Fr;
const Fp12 = bls12_381.fields.Fp12;
const CURVE_ORDER = Fr.ORDER;

export const BBS_CORE_CIPHERSUITE_ID = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_';
export const BBS_API_ID = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_';
export const BBS_CIPHERSUITE_ID = BBS_API_ID;
export const BBS_DRAFT_REVISION = 'draft-irtf-cfrg-bbs-signatures-09';
export const BBS_P1_HEX =
  'a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9';

const SUITE_ID_BYTES = Buffer.from(BBS_CIPHERSUITE_ID, 'utf8');
const DEFAULT_KEYGEN_DST = Buffer.from(`${BBS_CIPHERSUITE_ID}KEYGEN_DST_`, 'utf8');
const DEFAULT_H2S_DST = Buffer.from(`${BBS_CIPHERSUITE_ID}H2S_`, 'utf8');
const DEFAULT_MAP_MSG_DST = Buffer.from(`${BBS_CIPHERSUITE_ID}MAP_MSG_TO_SCALAR_AS_HASH_`, 'utf8');
const SIG_GENERATOR_SEED_DST = Buffer.from(`${BBS_CIPHERSUITE_ID}SIG_GENERATOR_SEED_`, 'utf8');
const SIG_GENERATOR_DST = Buffer.from(`${BBS_CIPHERSUITE_ID}SIG_GENERATOR_DST_`, 'utf8');
const MESSAGE_GENERATOR_SEED = Buffer.from(`${BBS_CIPHERSUITE_ID}MESSAGE_GENERATOR_SEED`, 'utf8');

type G1Point = InstanceType<typeof G1.Point>;

const P1_POINT: G1Point = G1.Point.fromHex(BBS_P1_HEX);

export interface BbsKeyPair {
  /** 32-byte scalar mod r (big-endian) */
  secretKey: Buffer;
  /** 96-byte compressed G2 point */
  publicKey: Buffer;
}

export interface BbsSignature {
  /** 48-byte compressed G1 point */
  A: Buffer;
  /** 32-byte scalar mod r */
  e: bigint;
  /** Optional 32-byte legacy wrapper scalar (0n for pure IETF 80-byte signatures) */
  s: bigint;
  /** 80-byte IETF signature `A (48) || e (32)` (or 112-byte legacy-wrapped when randomSeed Uint8Array passed) */
  bytes: Buffer;
  /** Always 80-byte IETF `SignatureToOctets` `A (48) || e (32)` */
  ietfBytes: Buffer;
}

export interface BbsProofRandomScalars {
  r1: bigint;
  r2: bigint;
  eTilde: bigint;
  r1Tilde: bigint;
  r3Tilde: bigint;
  mTildeScalars: readonly bigint[];
}

export interface BbsSelectiveDisclosureProof {
  /** 48-byte compressed G1 point `A_bar` (aliased as `APrime` for backward compatibility) */
  APrime: Buffer;
  /** 48-byte compressed G1 point `B_bar` (aliased as `ABar` for backward compatibility) */
  ABar: Buffer;
  /** 48-byte compressed G1 point `B_bar` */
  BBar: Buffer;
  /** 48-byte compressed G1 point `D = B * r2` */
  D: Buffer;
  /** Schnorr Fiat-Shamir challenge scalar `c` */
  c: bigint;
  eHat: bigint;
  r1Hat: bigint;
  r2Hat: bigint;
  r3Hat: bigint;
  sHat: bigint;
  /** One response scalar per undisclosed message index (in ascending index order) */
  undisclosedResponses: bigint[];
  /** Sorted disclosed 0-based message indices */
  disclosedIndices: number[];
  /** Total number of messages `L` in the signed vector */
  totalMessageCount: number;
  /** Serialized proof bytes (raw IETF octets when presentationHeader/randomScalars used, or framed when legacy) */
  proofBytes: Buffer;
  /** Always raw IETF `ProofToOctets`: `A_bar || B_bar || D || e_hat || r1_hat || r3_hat || m_hat_1..U || c` */
  ietfProofBytes: Buffer;
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((acc, c) => acc + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

function i2osp(value: number | bigint, length: number): Uint8Array {
  let v = BigInt(value);
  if (v < 0n) throw new Error('i2osp requires non-negative integer');
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v > 0n) throw new Error(`i2osp overflow for length ${length}`);
  return out;
}

function os2ip(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]!);
  }
  return result;
}

function scalarToBytes(s: bigint): Buffer {
  const canonical = Fr.create(s);
  return Buffer.from(i2osp(canonical, 32));
}

function bytesToScalar(buf: Uint8Array, allowZero = false): bigint {
  if (buf.length !== 32) {
    throw new Error(`Invalid BLS12-381 scalar length: expected 32, got ${buf.length}`);
  }
  const s = os2ip(buf);
  if (s >= CURVE_ORDER) {
    throw new Error('BLS12-381 scalar out of canonical range (>= r)');
  }
  if (!allowZero && s === 0n) {
    throw new Error('Invalid zero scalar in BBS proof/signature');
  }
  return s;
}

/**
 * IETF BBS `hash_to_scalar(msg_octets, dst)`:
 * `uniform_bytes = expand_message_xmd(msg_octets, dst, 48)` -> `OS2IP(uniform_bytes) mod r`.
 */
export function hashToScalar(
  msgBytes: Uint8Array,
  dst: Uint8Array = DEFAULT_H2S_DST,
): bigint {
  const uniform = expand_message_xmd(msgBytes, dst, 48, sha256 as never);
  return os2ip(uniform) % CURVE_ORDER;
}

export function bbsHashToScalar(
  msgBytes: Uint8Array,
  dst: Uint8Array = DEFAULT_H2S_DST,
): bigint {
  return hashToScalar(msgBytes, dst);
}

/**
 * Implements `seeded_random_scalars(SEED, dst, count)` per `draft-irtf-cfrg-bbs-signatures-09` §A.1.2:
 * `out_len = 48 * count`, `v = expand_message_xmd(SEED, dst, out_len)`,
 * `r_i = OS2IP(v[48*(i-1)..48*i]) mod r`.
 */
export function bbsMockedRandomScalars(
  seed: Uint8Array,
  dst: Uint8Array,
  count: number,
): bigint[] {
  const outLen = 48 * count;
  const v = expand_message_xmd(seed, dst, outLen, sha256 as never);
  const scalars: bigint[] = [];
  for (let i = 0; i < count; i++) {
    const chunk = v.subarray(i * 48, (i + 1) * 48);
    scalars.push(os2ip(chunk) % CURVE_ORDER);
  }
  return scalars;
}

function hashToNonZeroScalar(
  msgBytes: Uint8Array,
  dst: Uint8Array = DEFAULT_H2S_DST,
): bigint {
  let counter = 0;
  while (true) {
    const input = counter === 0 ? msgBytes : concatBytes(msgBytes, Uint8Array.of(counter));
    const s = hashToScalar(input, dst);
    if (s !== 0n) return s;
    counter++;
  }
}

/**
 * Returns the fixed ciphersuite generator `P1` in G1 (`BBS_P1_HEX`).
 */
export function bbsP1(): G1Point {
  return P1_POINT;
}

/**
 * Deterministic generator derivation `create_generators(count + 1)` in G1 (`[Q_1, H_1, ..., H_count]`)
 * per `draft-irtf-cfrg-bbs-signatures-09` Section 4.2.
 */
const generatorCache: G1Point[] = [];

export function bbsGenerators(messageCount: number): G1Point[] {
  const needed = messageCount + 1; // Q_1 + H_1..H_L
  if (generatorCache.length < needed) {
    let v = expand_message_xmd(MESSAGE_GENERATOR_SEED, SIG_GENERATOR_SEED_DST, 48, sha256 as never);
    for (let i = 1; i <= needed; i++) {
      v = expand_message_xmd(concatBytes(v, i2osp(i, 8)), SIG_GENERATOR_SEED_DST, 48, sha256 as never);
      if (i > generatorCache.length) {
        const pt = G1.hashToCurve(v, { DST: SIG_GENERATOR_DST }) as unknown as G1Point;
        generatorCache.push(pt);
      }
    }
  }
  return generatorCache.slice(0, needed);
}

/**
 * Maps an arbitrary message byte string to a scalar in `Fr` (`MapMessageToScalarAsHash`)
 * per `draft-irtf-cfrg-bbs-signatures-09` Section 4.3.
 */
export function bbsMessageToScalar(
  msg: Uint8Array,
  dst: Uint8Array = DEFAULT_MAP_MSG_DST,
): bigint {
  return hashToScalar(msg, dst);
}

/**
 * Computes `domain = calculate_domain(PK, Q_1, (H_1, ..., H_L), header)`
 * per `draft-irtf-cfrg-bbs-signatures-09` Section 4.5.
 */
export function calculateBbsDomain(
  publicKey: Uint8Array,
  q1: G1Point,
  hPoints: readonly G1Point[],
  header: Uint8Array = new Uint8Array(0),
): bigint {
  const L = hPoints.length;
  const domOctets = concatBytes(
    publicKey,
    i2osp(L, 8),
    q1.toBytes(true),
    ...hPoints.map((h) => h.toBytes(true)),
    SUITE_ID_BYTES,
    i2osp(header.length, 8),
    header,
  );
  return hashToScalar(domOctets, DEFAULT_H2S_DST);
}

/**
 * Generates a BLS12-381 keypair for BBS signatures (`KeyGen` + `SkToPk`)
 * per `draft-irtf-cfrg-bbs-signatures-09` Section 3.3 / 4.4.
 */
export function bbsKeygen(
  seed?: Uint8Array,
  keyInfo: Uint8Array = new Uint8Array(0),
  keyDst: Uint8Array = DEFAULT_KEYGEN_DST,
): BbsKeyPair {
  const ikm = seed ?? randomBytes(32);
  if (ikm.length < 32) {
    throw new Error('BBS keygen requires at least 32 bytes of key material');
  }
  const deriveInput = concatBytes(ikm, i2osp(keyInfo.length, 2), keyInfo);
  const sk = hashToScalar(deriveInput, keyDst);
  if (sk === 0n) {
    throw new Error('BBS keygen produced zero scalar');
  }
  const pkPoint = G2.Point.BASE.multiply(sk);
  return {
    secretKey: scalarToBytes(sk),
    publicKey: Buffer.from(pkPoint.toBytes(true)),
  };
}

/**
 * Encodes a BBS signature into 80 bytes: `A (48) || e (32)`.
 */
export function encodeBbsSignature(A: Uint8Array, e: bigint): Buffer {
  return Buffer.from(concatBytes(A, scalarToBytes(e)));
}

/**
 * Decodes an 80-byte IETF BBS signature `A (48) || e (32)`
 * (or a 112-byte legacy-wrapped signature `A (48) || e (32) || s (32)`).
 */
export function decodeBbsSignature(bytes: Uint8Array): BbsSignature {
  if (bytes.length !== 80 && bytes.length !== 112) {
    throw new Error(`Invalid BBS signature length: expected 80 (or 112), got ${bytes.length}`);
  }
  const A = Buffer.from(bytes.subarray(0, 48));
  const e = bytesToScalar(bytes.subarray(48, 80));
  const ietfBytes = Buffer.from(bytes.subarray(0, 80));
  let s = 0n;
  if (bytes.length === 112) {
    s = bytesToScalar(bytes.subarray(80, 112));
  }
  return {
    A,
    e,
    s,
    bytes: Buffer.from(bytes),
    ietfBytes,
  };
}

/**
 * Signs an ordered vector of messages `(m_1, ..., m_L)` under `secretKey` (`CoreSign`)
 * per `draft-irtf-cfrg-bbs-signatures-09` Section 3.4.1 / 4.6.
 *
 * If the 3rd argument is `{ header?: Uint8Array }` or omitted, `sig.bytes` is the
 * 80-byte IETF signature `A (48) || e (32)`. If the 3rd argument is a `Uint8Array`
 * (legacy `randomSeed`), `sig.bytes` includes a 32-byte auxiliary scalar `s` (112 bytes)
 * while `sig.ietfBytes` holds the 80-byte IETF signature.
 */
export function bbsSign(
  messages: readonly Uint8Array[],
  secretKey: Uint8Array,
  randomSeedOrOpts?: Uint8Array | { header?: Uint8Array },
  headerOpt?: Uint8Array,
): BbsSignature {
  const sk = bytesToScalar(secretKey);
  const pkBytes = Buffer.from(G2.Point.BASE.multiply(sk).toBytes(true));
  const isLegacySeed = randomSeedOrOpts instanceof Uint8Array;
  const header = isLegacySeed
    ? (headerOpt ?? new Uint8Array(0))
    : (randomSeedOrOpts?.header ?? headerOpt ?? new Uint8Array(0));

  const gens = bbsGenerators(messages.length);
  const Q1 = gens[0]!;
  const H = gens.slice(1);
  const domain = calculateBbsDomain(pkBytes, Q1, H, header);
  const msgScalars = messages.map((m) => bbsMessageToScalar(m));

  const e = hashToScalar(
    concatBytes(
      scalarToBytes(sk),
      ...msgScalars.map((m) => scalarToBytes(m)),
      scalarToBytes(domain),
    ),
    DEFAULT_H2S_DST,
  );

  // B = P_1 + Q_1 * domain + sum_{i=1..L} H_i * m_i
  let B = P1_POINT.add(Q1.multiply(domain));
  for (let i = 0; i < messages.length; i++) {
    const mi = msgScalars[i]!;
    if (mi !== 0n) {
      B = B.add(H[i]!.multiply(mi));
    }
  }

  const denom = Fr.add(sk, e);
  if (denom === 0n) {
    throw new Error('BBS signing degenerate scalar (sk + e == 0 mod r)');
  }
  const invDenom = Fr.inv(denom);
  const APoint = B.multiply(invDenom);
  const A = Buffer.from(APoint.toBytes(true));
  const ietfBytes = encodeBbsSignature(A, e);

  if (isLegacySeed) {
    const s = hashToNonZeroScalar(concatBytes(ietfBytes, randomSeedOrOpts), DEFAULT_H2S_DST);
    const bytes = Buffer.from(concatBytes(ietfBytes, scalarToBytes(s)));
    return { A, e, s, bytes, ietfBytes };
  }

  return {
    A,
    e,
    s: 0n,
    bytes: ietfBytes,
    ietfBytes,
  };
}

/**
 * Verifies a BBS signature over all messages `(m_1, ..., m_L)` (`CoreVerify`)
 * per `draft-irtf-cfrg-bbs-signatures-09` Section 3.4.2:
 *   `e(A, W + BP2 * e) == e(B, BP2)`
 */
export function bbsVerify(
  messages: readonly Uint8Array[],
  signature: BbsSignature | Uint8Array,
  publicKey: Uint8Array,
  header: Uint8Array = new Uint8Array(0),
): boolean {
  try {
    const sig = signature instanceof Uint8Array ? decodeBbsSignature(signature) : signature;
    if (publicKey.length !== 96) return false;
    const W = G2.Point.fromHex(Buffer.from(publicKey).toString('hex'));
    W.assertValidity();
    if (W.equals(G2.Point.ZERO)) return false;

    const A = G1.Point.fromHex(sig.A.toString('hex'));
    A.assertValidity();
    if (A.equals(G1.Point.ZERO)) return false;

    const gens = bbsGenerators(messages.length);
    const Q1 = gens[0]!;
    const H = gens.slice(1);
    const domain = calculateBbsDomain(publicKey, Q1, H, header);
    const msgScalars = messages.map((m) => bbsMessageToScalar(m));

    let B = P1_POINT.add(Q1.multiply(domain));
    for (let i = 0; i < messages.length; i++) {
      const mi = msgScalars[i]!;
      if (mi !== 0n) {
        B = B.add(H[i]!.multiply(mi));
      }
    }

    const lhs = bls12_381.pairing(A, W.add(G2.Point.BASE.multiply(sig.e)));
    const rhs = bls12_381.pairing(B, G2.Point.BASE);
    return Fp12.eql(lhs, rhs);
  } catch {
    return false;
  }
}

function computeProofChallenge(params: {
  A_bar: Uint8Array;
  B_bar: Uint8Array;
  D: Uint8Array;
  T1: Uint8Array;
  T2: Uint8Array;
  disclosedIndices: readonly number[];
  disclosedScalars: readonly bigint[];
  domain: bigint;
  presentationHeader: Uint8Array;
}): bigint {
  const R = params.disclosedIndices.length;
  const pairs: Uint8Array[] = [];
  for (let k = 0; k < R; k++) {
    pairs.push(i2osp(params.disclosedIndices[k]!, 8));
    pairs.push(scalarToBytes(params.disclosedScalars[k]!));
  }
  const cArr = concatBytes(
    i2osp(R, 8),
    ...pairs,
    params.A_bar,
    params.B_bar,
    params.D,
    params.T1,
    params.T2,
    scalarToBytes(params.domain),
    i2osp(params.presentationHeader.length, 8),
    params.presentationHeader,
  );
  return hashToScalar(cArr, DEFAULT_H2S_DST);
}

/**
 * Creates a Zero-Knowledge Selective Disclosure Proof (`CoreProofGen`)
 * per `draft-irtf-cfrg-bbs-signatures-09` Section 3.4.3 / 4.7.
 */
export function bbsCreateProof(input: {
  publicKey: Uint8Array;
  signature: BbsSignature | Uint8Array;
  messages: readonly Uint8Array[];
  disclosedIndices: readonly number[];
  nonce?: Uint8Array;
  header?: Uint8Array;
  presentationHeader?: Uint8Array;
  randomSeed?: Uint8Array;
  randomScalars?: BbsProofRandomScalars;
}): BbsSelectiveDisclosureProof {
  const sig =
    input.signature instanceof Uint8Array
      ? decodeBbsSignature(input.signature)
      : input.signature;
  const L = input.messages.length;
  const sortedDisclosed = [...new Set(input.disclosedIndices)].sort((a, b) => a - b);
  for (const idx of sortedDisclosed) {
    if (!Number.isInteger(idx) || idx < 0 || idx >= L) {
      throw new Error(`Invalid disclosed message index ${idx} for message count ${L}`);
    }
  }
  const disclosedSet = new Set(sortedDisclosed);
  const undisclosedIndices: number[] = [];
  for (let i = 0; i < L; i++) {
    if (!disclosedSet.has(i)) undisclosedIndices.push(i);
  }
  const U = undisclosedIndices.length;

  const header = input.header ?? new Uint8Array(0);
  const presentationHeader = input.presentationHeader ?? input.nonce ?? new Uint8Array(0);
  const isRawIetfMode =
    input.presentationHeader !== undefined || input.randomScalars !== undefined;

  const gens = bbsGenerators(L);
  const Q1 = gens[0]!;
  const H = gens.slice(1);
  const domain = calculateBbsDomain(input.publicKey, Q1, H, header);
  const msgScalars = input.messages.map((m) => bbsMessageToScalar(m));

  let B = P1_POINT.add(Q1.multiply(domain));
  for (let i = 0; i < L; i++) {
    const mi = msgScalars[i]!;
    if (mi !== 0n) {
      B = B.add(H[i]!.multiply(mi));
    }
  }

  const A = G1.Point.fromHex(sig.A.toString('hex'));
  A.assertValidity();

  let r1: bigint;
  let r2: bigint;
  let eTilde: bigint;
  let r1Tilde: bigint;
  let r3Tilde: bigint;
  let mTilde: bigint[];

  if (input.randomScalars) {
    r1 = input.randomScalars.r1;
    r2 = input.randomScalars.r2;
    eTilde = input.randomScalars.eTilde;
    r1Tilde = input.randomScalars.r1Tilde;
    r3Tilde = input.randomScalars.r3Tilde;
    mTilde = [...input.randomScalars.mTildeScalars];
  } else {
    const seed = input.randomSeed ?? randomBytes(32);
    const prf = (tag: string, idx = 0) =>
      hashToNonZeroScalar(
        concatBytes(
          seed,
          Buffer.from(tag, 'utf8'),
          Uint8Array.of((idx >> 8) & 0xff, idx & 0xff),
          presentationHeader,
        ),
        DEFAULT_H2S_DST,
      );
    r1 = prf('r1');
    r2 = prf('r2');
    eTilde = prf('e_tilde');
    r1Tilde = prf('r1_tilde');
    r3Tilde = prf('r3_tilde');
    mTilde = undisclosedIndices.map((idx) => prf('m_tilde', idx));
  }

  const r3 = Fr.inv(r2);
  const DPoint = B.multiply(r2);
  const ABarPoint = A.multiply(Fr.mul(r1, r2));
  const BBarPoint = DPoint.multiply(r1).add(ABarPoint.multiply(Fr.neg(sig.e)));

  // Commitments T1, T2:
  // T1 = A_bar * e_tilde + D * r1_tilde
  // T2 = D * r3_tilde + sum_{j in U} H_j * m_tilde_j
  const T1Point = ABarPoint.multiply(eTilde).add(DPoint.multiply(r1Tilde));
  let T2Point = DPoint.multiply(r3Tilde);
  for (let k = 0; k < U; k++) {
    const idx = undisclosedIndices[k]!;
    T2Point = T2Point.add(H[idx]!.multiply(mTilde[k]!));
  }

  const ABarBytes = Buffer.from(ABarPoint.toBytes(true));
  const BBarBytes = Buffer.from(BBarPoint.toBytes(true));
  const DBytes = Buffer.from(DPoint.toBytes(true));
  const T1Bytes = Buffer.from(T1Point.toBytes(true));
  const T2Bytes = Buffer.from(T2Point.toBytes(true));

  const disclosedScalars = sortedDisclosed.map((idx) => msgScalars[idx]!);
  const c = computeProofChallenge({
    A_bar: ABarBytes,
    B_bar: BBarBytes,
    D: DBytes,
    T1: T1Bytes,
    T2: T2Bytes,
    disclosedIndices: sortedDisclosed,
    disclosedScalars,
    domain,
    presentationHeader,
  });

  // Responses per draft-irtf-cfrg-bbs-signatures-09 Section 4.7:
  // e_hat = e_tilde + c * e
  // r1_hat = r1_tilde - c * r1
  // r3_hat = r3_tilde - c * r3
  // m_hat_j = m_tilde_j + c * msg_j
  const eHat = Fr.add(eTilde, Fr.mul(c, sig.e));
  const r1Hat = Fr.sub(r1Tilde, Fr.mul(c, r1));
  const r3Hat = Fr.sub(r3Tilde, Fr.mul(c, r3));
  const undisclosedResponses = undisclosedIndices.map((idx, k) =>
    Fr.add(mTilde[k]!, Fr.mul(c, msgScalars[idx]!)),
  );

  const ietfProofBytes = Buffer.from(
    concatBytes(
      ABarBytes,
      BBarBytes,
      DBytes,
      scalarToBytes(eHat),
      scalarToBytes(r1Hat),
      scalarToBytes(r3Hat),
      ...undisclosedResponses.map((m) => scalarToBytes(m)),
      scalarToBytes(c),
    ),
  );

  const proofBase = {
    APrime: ABarBytes,
    ABar: BBarBytes,
    BBar: BBarBytes,
    D: DBytes,
    c,
    eHat,
    r1Hat,
    r2Hat: r3Hat,
    r3Hat,
    sHat: r3Hat,
    undisclosedResponses,
    disclosedIndices: sortedDisclosed,
    totalMessageCount: L,
    ietfProofBytes,
  };

  const proofBytes = isRawIetfMode ? ietfProofBytes : encodeBbsProof(proofBase);
  return {
    ...proofBase,
    proofBytes,
  };
}

/**
 * Encodes a `BbsSelectiveDisclosureProof` with a compact 6+2R byte metadata prefix
 * followed by the raw IETF proof octets so `decodeBbsProof` can recover `disclosedIndices`
 * and `totalMessageCount` when called without external parameters.
 */
export function encodeBbsProof(
  p: Omit<BbsSelectiveDisclosureProof, 'proofBytes'>,
): Buffer {
  const R = p.disclosedIndices.length;
  const U = p.undisclosedResponses.length;
  const header = Buffer.alloc(2 + 2 + R * 2 + 2);
  header.writeUInt16BE(p.totalMessageCount, 0);
  header.writeUInt16BE(R, 2);
  for (let i = 0; i < R; i++) {
    header.writeUInt16BE(p.disclosedIndices[i]!, 4 + i * 2);
  }
  header.writeUInt16BE(U, 4 + R * 2);

  return Buffer.from(concatBytes(header, p.ietfProofBytes));
}

/**
 * Decodes either a raw IETF `OctetsToProof` buffer (identified by compressed G1 bit `0x80`
 * on byte 0) or a metadata-prefixed proof buffer from `encodeBbsProof`.
 */
export function decodeBbsProof(
  bytes: Uint8Array,
  disclosedIndicesHint?: readonly number[],
): BbsSelectiveDisclosureProof {
  if (bytes.length < 272) {
    throw new Error(`BBS proof too short: ${bytes.length} bytes`);
  }

  let rawIetf: Uint8Array;
  let disclosedIndices: number[];
  let totalMessageCount: number;

  // Compressed BLS12-381 G1 points always have the compression bit (0x80) set in byte 0,
  // whereas the framed u16BE totalMessageCount (< 32768) always has bit 0x80 == 0.
  if ((bytes[0]! & 0x80) !== 0) {
    rawIetf = bytes;
    if ((rawIetf.length - 144) % 32 !== 0) {
      throw new Error(`Invalid raw IETF BBS proof length: ${rawIetf.length}`);
    }
    const numScalars = (rawIetf.length - 144) / 32;
    if (numScalars < 4) {
      throw new Error(`Invalid scalar count in BBS proof: ${numScalars}`);
    }
    const U = numScalars - 4;
    disclosedIndices = disclosedIndicesHint ? [...disclosedIndicesHint] : [];
    totalMessageCount = disclosedIndices.length + U;
  } else {
    totalMessageCount = (bytes[0]! << 8) | bytes[1]!;
    const R = (bytes[2]! << 8) | bytes[3]!;
    const headerLen = 6 + R * 2;
    if (bytes.length < headerLen + 272) {
      throw new Error('Truncated framed BBS proof header');
    }
    disclosedIndices = [];
    for (let i = 0; i < R; i++) {
      const off = 4 + i * 2;
      disclosedIndices.push((bytes[off]! << 8) | bytes[off + 1]!);
    }
    const U = (bytes[4 + R * 2]! << 8) | bytes[5 + R * 2]!;
    if (R + U !== totalMessageCount) {
      throw new Error('BBS proof R + U != totalMessageCount');
    }
    rawIetf = bytes.subarray(headerLen);
    if (rawIetf.length !== 144 + (4 + U) * 32) {
      throw new Error(`Invalid framed BBS proof body length: ${rawIetf.length}`);
    }
  }

  const U = (rawIetf.length - 144) / 32 - 4;
  const ABar = Buffer.from(rawIetf.subarray(0, 48));
  const BBar = Buffer.from(rawIetf.subarray(48, 96));
  const D = Buffer.from(rawIetf.subarray(96, 144));
  let offset = 144;
  const eHat = bytesToScalar(rawIetf.subarray(offset, offset + 32), true);
  offset += 32;
  const r1Hat = bytesToScalar(rawIetf.subarray(offset, offset + 32), true);
  offset += 32;
  const r3Hat = bytesToScalar(rawIetf.subarray(offset, offset + 32), true);
  offset += 32;
  const undisclosedResponses: bigint[] = [];
  for (let j = 0; j < U; j++) {
    undisclosedResponses.push(bytesToScalar(rawIetf.subarray(offset, offset + 32), true));
    offset += 32;
  }
  const c = bytesToScalar(rawIetf.subarray(offset, offset + 32));

  return {
    APrime: ABar,
    ABar: BBar,
    BBar,
    D,
    c,
    eHat,
    r1Hat,
    r2Hat: r3Hat,
    r3Hat,
    sHat: r3Hat,
    undisclosedResponses,
    disclosedIndices,
    totalMessageCount,
    proofBytes: Buffer.from(bytes),
    ietfProofBytes: Buffer.from(rawIetf),
  };
}

/**
 * Verifies a Zero-Knowledge Selective Disclosure Proof (`CoreProofVerify`)
 * per `draft-irtf-cfrg-bbs-signatures-09` Section 3.4.4 / 4.8.
 */
export function bbsVerifyProof(input: {
  publicKey: Uint8Array;
  proof: BbsSelectiveDisclosureProof | Uint8Array;
  disclosedMessages: ReadonlyMap<number, Uint8Array>;
  totalMessageCount?: number;
  nonce?: Uint8Array;
  header?: Uint8Array;
  presentationHeader?: Uint8Array;
}): boolean {
  try {
    if (input.publicKey.length !== 96) return false;
    const W = G2.Point.fromHex(Buffer.from(input.publicKey).toString('hex'));
    W.assertValidity();
    if (W.equals(G2.Point.ZERO)) return false;

    const mapIndices = [...input.disclosedMessages.keys()];
    for (let k = 1; k < mapIndices.length; k++) {
      if (mapIndices[k]! <= mapIndices[k - 1]!) {
        // IETF CoreProofVerify requires disclosed_indexes in strictly ascending order
        return false;
      }
    }

    const proof =
      input.proof instanceof Uint8Array
        ? decodeBbsProof(input.proof, mapIndices)
        : input.proof;

    const U = proof.undisclosedResponses.length;
    const R = mapIndices.length;
    const L = input.totalMessageCount ?? R + U;
    if (L <= 0 || R + U !== L) return false;

    if (
      proof.disclosedIndices.length > 0 &&
      (proof.disclosedIndices.length !== R ||
        proof.disclosedIndices.some((idx, k) => idx !== mapIndices[k]))
    ) {
      return false;
    }

    for (const idx of mapIndices) {
      if (!Number.isInteger(idx) || idx < 0 || idx >= L) return false;
    }

    const ABarPoint = G1.Point.fromHex(proof.APrime.toString('hex'));
    const BBarPoint = G1.Point.fromHex(proof.BBar.toString('hex'));
    const DPoint = G1.Point.fromHex(proof.D.toString('hex'));
    ABarPoint.assertValidity();
    BBarPoint.assertValidity();
    DPoint.assertValidity();
    if (
      ABarPoint.equals(G1.Point.ZERO) ||
      BBarPoint.equals(G1.Point.ZERO) ||
      DPoint.equals(G1.Point.ZERO)
    ) {
      return false;
    }

    const header = input.header ?? new Uint8Array(0);
    const presentationHeader = input.presentationHeader ?? input.nonce ?? new Uint8Array(0);

    const gens = bbsGenerators(L);
    const Q1 = gens[0]!;
    const H = gens.slice(1);
    const domain = calculateBbsDomain(input.publicKey, Q1, H, header);

    const disclosedSet = new Set(mapIndices);
    const undisclosedIndices: number[] = [];
    for (let i = 0; i < L; i++) {
      if (!disclosedSet.has(i)) undisclosedIndices.push(i);
    }
    if (undisclosedIndices.length !== U) return false;

    const disclosedScalars = mapIndices.map((idx) =>
      bbsMessageToScalar(input.disclosedMessages.get(idx)!),
    );

    // B_v = P_1 + Q_1 * domain + sum_{i in D} H_i * msg_i
    let Bv = P1_POINT.add(Q1.multiply(domain));
    for (let k = 0; k < R; k++) {
      const idx = mapIndices[k]!;
      const mi = disclosedScalars[k]!;
      if (mi !== 0n) {
        Bv = Bv.add(H[idx]!.multiply(mi));
      }
    }

    // Reconstruct Schnorr commitments:
    // T1 = B_bar * c + A_bar * e_hat + D * r1_hat
    // T2 = B_v * c + D * r3_hat + sum_{j in U} H_j * m_hat_j
    const T1Point = BBarPoint.multiply(proof.c)
      .add(ABarPoint.multiply(proof.eHat))
      .add(DPoint.multiply(proof.r1Hat));
    let T2Point = Bv.multiply(proof.c).add(DPoint.multiply(proof.r3Hat));
    for (let j = 0; j < U; j++) {
      const idx = undisclosedIndices[j]!;
      const mHat = proof.undisclosedResponses[j]!;
      if (mHat !== 0n) {
        T2Point = T2Point.add(H[idx]!.multiply(mHat));
      }
    }

    const expectedC = computeProofChallenge({
      A_bar: proof.APrime,
      B_bar: proof.BBar,
      D: proof.D,
      T1: Buffer.from(T1Point.toBytes(true)),
      T2: Buffer.from(T2Point.toBytes(true)),
      disclosedIndices: mapIndices,
      disclosedScalars,
      domain,
      presentationHeader,
    });
    if (expectedC !== proof.c) return false;

    // Pairing check: e(A_bar, W) * e(B_bar, -BP2) == 1_GT  <=>  e(A_bar, W) == e(B_bar, BP2)
    const lhs = bls12_381.pairing(ABarPoint, W);
    const rhs = bls12_381.pairing(BBarPoint, G2.Point.BASE);
    return Fp12.eql(lhs, rhs);
  } catch {
    return false;
  }
}

/**
 * Canonical capsule-to-message-vector mapping for BBS selective disclosure.
 */
export const CAPSULE_BBS_ATTRIBUTE_NAMES = [
  'capsule_id',
  'action_id',
  'timestamp_ns',
  'principal.subject',
  'principal.agent_id',
  'operation.kind',
  'operation.method',
  'operation.target',
  'request_digest',
  'verdict_class',
  'effect.status',
] as const;

export function capsuleToBbsMessages(capsule: Capsule): Buffer[] {
  return [
    Buffer.from(`capsule_id=${capsule.capsule_id}`, 'utf8'),
    Buffer.from(`action_id=${capsule.action_id}`, 'utf8'),
    Buffer.from(`issued_at=${capsule.issued_at}`, 'utf8'),
    Buffer.from(`principal.subject_commitment=${capsule.principal?.subject_commitment ?? ''}`, 'utf8'),
    Buffer.from(`agent.spiffe_id=${capsule.agent?.spiffe_id ?? ''}`, 'utf8'),
    Buffer.from(`operation.kind=${capsule.operation.kind}`, 'utf8'),
    Buffer.from(`operation.method=${capsule.operation.method}`, 'utf8'),
    Buffer.from(`operation.target_commitment=${capsule.operation.target_commitment ?? ''}`, 'utf8'),
    Buffer.from(
      `request_digest=${Buffer.from(capsule.request_digest).toString('hex')}`,
      'utf8',
    ),
    Buffer.from(`verdict_class=${capsule.verdict_class}`, 'utf8'),
    Buffer.from(`effect.status=${capsule.effect?.status ?? 'none'}`, 'utf8'),
  ];
}
