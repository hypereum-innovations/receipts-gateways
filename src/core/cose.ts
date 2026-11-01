// SPDX-License-Identifier: Apache-2.0
/**
 * COSE_Sign1 (RFC 9052), CWT claims header (RFC 9597), COSE receipts
 * (RFC 9942) and countersignatures (RFC 9338) — the receipt envelope.
 *
 * Statement protected header: alg(1), content-type(3), kid(4), CWT claims(15)
 * {iss(1), sub(2), iat(6)}. Detached-payload statements put the SHA-256 of the
 * payload in header label -6800 is NOT used; instead payload=null and the
 * detached digest is pinned by the capsule_id inside the signed claims map
 * extension (see capsule.ts) — verifiers refuse a detached payload whose
 * digest differs.
 * Receipts ride in the statement's unprotected header at label 394. Each
 * receipt is itself a COSE_Sign1 signed by the log: protected header carries
 * vds(395)=1 and vdp(396) = {-1: inclusion proof, -2: consistency proof?},
 * payload is null and the signature's external_aad is the leaf hash, so the
 * log's signature binds (leaf, treeSize via proof, checkpoint root via the
 * inclusion proof the verifier recomputes). Countersignatures (label 7,
 * "counter signature") hold the post-quantum second signature over the
 * RFC 9338 Countersign_structure.
 */
import { CborTag, cborDecode, cborEncode } from './cbor.js';
import { leafHash, verifyInclusion, type InclusionProof, VDS_RFC9162_SHA256 } from './merkle.js';
import {
  COSE_ALG,
  HYPEREUM_OPERATED_ALLOWED_ALGS,
  sha256,
  verifyWithAlg,
  type CoseAlg,
  type ReceiptSigner,
} from './keys.js';
import type { KeyObject } from 'node:crypto';

export const COSE_LABEL = {
  alg: 1,
  contentType: 3,
  kid: 4,
  counterSignature: 7,
  cwtClaims: 15,
  receipts: 394,
  vds: 395,
  vdp: 396,
  inclusionProof: -1,
  consistencyProof: -2,
} as const;

export const CONTENT_TYPE_CAPSULE = 'application/vnd.hivemind.agent-action-capsule+cbor';
export const CONTENT_TYPE_STATEMENT_GENERIC = 'application/cose';
/** SCRAPI media types (draft-ietf-scitt-scrapi): statement and receipt bodies. */
export const MEDIA_TYPE_SCITT_STATEMENT = 'application/scitt-statement+cose';
export const CONTENT_TYPE_SCITT_RECEIPT = 'application/scitt-receipt+cose';

export interface CwtClaims {
  iss: string;
  sub: string;
  iat: number; // seconds
}

function headerMap(entries: Array<[number, unknown]>): Map<number, unknown> {
  return new Map(entries);
}

export function sigStructure(
  context: 'Signature1' | 'CounterSignature',
  protectedBytes: Buffer,
  externalAad: Buffer,
  payload: Buffer | null,
): Buffer {
  return cborEncode([context, protectedBytes, externalAad, payload ?? Buffer.alloc(0)]);
}

export interface Sign1Options {
  contentType?: string;
  cwt?: CwtClaims;
  extraProtected?: Map<number, unknown>;
  extraUnprotected?: Map<number, unknown>;
  externalAad?: Buffer;
  detached?: boolean;
}

/** Sign and return the tagged (18) COSE_Sign1 bytes. */
export async function coseSign1(
  signer: ReceiptSigner,
  payload: Buffer,
  opts: Sign1Options = {},
): Promise<Buffer> {
  const prot = headerMap([
    [COSE_LABEL.alg, signer.alg],
    [COSE_LABEL.kid, Buffer.from(signer.kid, 'utf8')],
  ]);
  if (opts.contentType) prot.set(COSE_LABEL.contentType, opts.contentType);
  if (opts.cwt) {
    prot.set(
      COSE_LABEL.cwtClaims,
      headerMap([
        [1, opts.cwt.iss],
        [2, opts.cwt.sub],
        [6, opts.cwt.iat],
      ]),
    );
  }
  if (opts.extraProtected) for (const [k, v] of opts.extraProtected) prot.set(k, v);
  const protBytes = cborEncode(prot);
  const toSign = sigStructure('Signature1', protBytes, opts.externalAad ?? Buffer.alloc(0), payload);
  const sig = await signer.sign(toSign);
  const unprot = opts.extraUnprotected ?? new Map<number, unknown>();
  return cborEncode(
    new CborTag(18, [protBytes, unprot, opts.detached ? null : payload, sig] as never),
  );
}

export interface ParsedSign1 {
  raw: Buffer;
  protectedBytes: Buffer;
  protectedHeader: Map<unknown, unknown>;
  unprotected: Map<unknown, unknown>;
  payload: Buffer | null;
  signature: Buffer;
  alg: CoseAlg;
  kid: string;
  cwt: CwtClaims | null;
}

export function parseSign1(bytes: Uint8Array): ParsedSign1 {
  let v = cborDecode(bytes);
  if (v instanceof CborTag) {
    if (v.tag !== 18) throw new Error(`expected COSE_Sign1 tag 18, got ${v.tag}`);
    v = v.value;
  }
  if (!Array.isArray(v) || v.length !== 4) throw new Error('COSE_Sign1 must be an array of 4');
  const [protBytesRaw, unprotRaw, payloadRaw, sigRaw] = v as unknown[];
  if (!(protBytesRaw instanceof Uint8Array)) throw new Error('protected header must be bstr');
  const protBytes = Buffer.from(protBytesRaw);
  const protDecoded = protBytes.length === 0 ? new Map() : cborDecode(protBytes);
  if (!(protDecoded instanceof Map)) throw new Error('protected header must decode to a map');
  const unprotected =
    unprotRaw instanceof Map ? (unprotRaw as Map<unknown, unknown>) : new Map<unknown, unknown>();
  if (!(sigRaw instanceof Uint8Array)) throw new Error('signature must be bstr');
  const payload =
    payloadRaw === null ? null : payloadRaw instanceof Uint8Array ? Buffer.from(payloadRaw) : (() => {
      throw new Error('payload must be bstr or null');
    })();
  const cwtRaw = protDecoded.get(COSE_LABEL.cwtClaims);
  let cwt: CwtClaims | null = null;
  if (cwtRaw instanceof Map) {
    cwt = {
      iss: String(cwtRaw.get(1) ?? ''),
      sub: String(cwtRaw.get(2) ?? ''),
      iat: Number(cwtRaw.get(6) ?? 0),
    };
  }
  const kidRaw = protDecoded.get(COSE_LABEL.kid);
  return {
    raw: Buffer.from(bytes),
    protectedBytes: protBytes,
    protectedHeader: protDecoded as Map<unknown, unknown>,
    unprotected,
    payload,
    signature: Buffer.from(sigRaw as Uint8Array),
    alg: Number(protDecoded.get(COSE_LABEL.alg)) as CoseAlg,
    kid: kidRaw instanceof Uint8Array ? Buffer.from(kidRaw).toString('utf8') : String(kidRaw ?? ''),
    cwt,
  };
}

export function verifySign1(
  parsed: ParsedSign1,
  publicKey: KeyObject,
  opts: { externalAad?: Buffer; detachedPayload?: Buffer } = {},
): boolean {
  const payload = parsed.payload ?? opts.detachedPayload;
  if (!payload) throw new Error('detached COSE_Sign1 needs the detached payload to verify');
  const toVerify = sigStructure(
    'Signature1',
    parsed.protectedBytes,
    opts.externalAad ?? Buffer.alloc(0),
    payload,
  );
  try {
    return verifyWithAlg(parsed.alg, publicKey, toVerify, parsed.signature);
  } catch {
    return false;
  }
}

/** RFC 9338 countersignature ("CounterSignature" context) over a finished COSE_Sign1. */
export async function addCountersignature(
  statementBytes: Buffer,
  counterSigner: ReceiptSigner,
): Promise<Buffer> {
  const parsed = parseSign1(statementBytes);
  const counterProt = headerMap([
    [COSE_LABEL.alg, counterSigner.alg],
    [COSE_LABEL.kid, Buffer.from(counterSigner.kid, 'utf8')],
  ]);
  const counterProtBytes = cborEncode(counterProt);
  // Countersign_structure payload is the target signature value.
  const toSign = cborEncode([
    'CounterSignature',
    parsed.protectedBytes,
    counterProtBytes,
    Buffer.alloc(0),
    parsed.signature,
  ]);
  const sig = await counterSigner.sign(toSign);
  const counterSigArray = [counterProtBytes, new Map(), sig];
  const unprot = new Map(parsed.unprotected as Map<number, unknown>);
  const existing = unprot.get(COSE_LABEL.counterSignature);
  unprot.set(
    COSE_LABEL.counterSignature,
    Array.isArray(existing) ? [...existing, counterSigArray] : [counterSigArray],
  );
  return cborEncode(
    new CborTag(18, [parsed.protectedBytes, unprot, parsed.payload, parsed.signature] as never),
  );
}

export function verifyCountersignature(
  parsed: ParsedSign1,
  counterKid: string,
  publicKey: KeyObject,
  alg: CoseAlg,
): boolean {
  const raw = (parsed.unprotected as Map<unknown, unknown>).get(COSE_LABEL.counterSignature);
  if (!Array.isArray(raw)) return false;
  for (const entry of raw) {
    if (!Array.isArray(entry) || entry.length !== 3) continue;
    const [protBytesRaw, , sigRaw] = entry as unknown[];
    if (!(protBytesRaw instanceof Uint8Array) || !(sigRaw instanceof Uint8Array)) continue;
    const protBytes = Buffer.from(protBytesRaw);
    const prot = cborDecode(protBytes);
    if (!(prot instanceof Map)) continue;
    const kidRaw = prot.get(COSE_LABEL.kid);
    const kid = kidRaw instanceof Uint8Array ? Buffer.from(kidRaw).toString('utf8') : '';
    if (kid !== counterKid || Number(prot.get(COSE_LABEL.alg)) !== alg) continue;
    const toVerify = cborEncode([
      'CounterSignature',
      parsed.protectedBytes,
      protBytes,
      Buffer.alloc(0),
      parsed.signature,
    ]);
    try {
      if (verifyWithAlg(alg, publicKey, toVerify, Buffer.from(sigRaw as Uint8Array))) return true;
    } catch {
      /* try next */
    }
  }
  return false;
}

// --- RFC 9942 receipts ------------------------------------------------------

export interface ScittReceipt {
  bytes: Buffer;
  inclusion: InclusionProof;
  logKid: string;
  alg: CoseAlg;
}

/**
 * Issue an RFC 9942 Receipt of Inclusion: protected header {alg, kid,
 * vds=1}; unprotected header {396: {-1: [bstr .cbor [treeSize, leafIndex,
 * [path]]]}}; the signature covers the Merkle root as the detached payload
 * (RFC 9942 section 5.2.1) - the root the inclusion proof recomputes is an
 * input to this function so issuer and verifier can never disagree on it.
 */
export async function issueReceipt(
  logSigner: ReceiptSigner,
  statementBytes: Buffer,
  proof: InclusionProof,
  root?: Buffer,
  opts: { issuerOrigin?: string; iat?: number } = {},
): Promise<Buffer> {
  if (!HYPEREUM_OPERATED_ALLOWED_ALGS.includes(logSigner.alg)) {
    throw new Error(
      `issueReceipt: log receipt key must use EdDSA (-8) per Ruling R83, got alg ${String(logSigner.alg)}`,
    );
  }
  const leaf = leafHash(statementBytes);
  const merkleRoot = root ?? computeRootFromProof(leaf, proof);
  if (!verifyInclusion(leaf, proof, merkleRoot)) throw new Error('issueReceipt: proof does not recompute the root');
  const proofContent = cborEncode([proof.treeSize, proof.leafIndex, proof.hashes] as never);
  const vdp = new Map<number, unknown>([
    [COSE_LABEL.inclusionProof, [proofContent]],
  ]);
  // RFC 9943: the receipt is itself a signed statement of the Transparency
  // Service; its protected header carries CWT claims (RFC 9597) with
  // iss = service origin, sub = the registered statement's subject (falling
  // back to its leaf digest), iat = registration time.
  let subject = `sha256:${sha256(statementBytes).toString('hex')}`;
  try {
    const st = parseSign1(statementBytes);
    if (st.cwt?.sub) subject = st.cwt.sub;
  } catch { /* detached/foreign statement: leaf digest identifies it */ }
  return coseSign1(logSigner, merkleRoot, {
    contentType: CONTENT_TYPE_SCITT_RECEIPT,
    cwt: {
      iss: opts.issuerOrigin ?? logSigner.kid,
      sub: subject,
      iat: opts.iat ?? Math.floor(Date.now() / 1000),
    },
    extraProtected: new Map<number, unknown>([[COSE_LABEL.vds, VDS_RFC9162_SHA256]]),
    extraUnprotected: new Map<number, unknown>([[COSE_LABEL.vdp, vdp]]),
    detached: true,
  });
}

function computeRootFromProof(leaf: Buffer, proof: InclusionProof): Buffer {
  // Recompute the root by folding the audit path (mirror of verifyInclusion).
  let fn = proof.leafIndex;
  let sn = proof.treeSize - 1;
  let r = leaf;
  for (const p of proof.hashes) {
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHashBuf(p, r);
      while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      r = nodeHashBuf(r, p);
    }
    fn >>= 1; sn >>= 1;
  }
  return r;
}

function nodeHashBuf(left: Buffer, right: Buffer): Buffer {
  return sha256(Buffer.concat([Buffer.from([1]), left, right]));
}

export function parseReceipt(bytes: Uint8Array): ScittReceipt {
  const p = parseSign1(bytes);
  const vds = p.protectedHeader.get(COSE_LABEL.vds);
  if (vds !== VDS_RFC9162_SHA256) throw new Error(`unsupported VDS ${String(vds)}`);
  const vdp = (p.unprotected as Map<unknown, unknown>).get(COSE_LABEL.vdp) ??
    p.protectedHeader.get(COSE_LABEL.vdp);
  if (!(vdp instanceof Map)) throw new Error('receipt missing vdp');
  const inc = vdp.get(COSE_LABEL.inclusionProof);
  if (!Array.isArray(inc) || inc.length < 1) throw new Error('receipt missing inclusion proof');
  const first = inc[0] as unknown;
  let treeSize: number, leafIndex: number, hashes: Buffer[];
  if (first instanceof Uint8Array) {
    // RFC 9942 form: array of bstr-wrapped CBOR proof contents.
    const content = cborDecode(Buffer.from(first)) as unknown[];
    treeSize = Number(content[0]);
    leafIndex = Number(content[1]);
    hashes = (content[2] as Uint8Array[]).map((h) => Buffer.from(h));
  } else {
    // Pre-conformance inline form (accepted on read for old dev receipts).
    treeSize = Number(inc[0]);
    leafIndex = Number(inc[1]);
    hashes = (inc.slice(2) as Uint8Array[]).map((h) => Buffer.from(h));
  }
  return {
    bytes: Buffer.from(bytes),
    inclusion: { treeSize, leafIndex, hashes },
    logKid: p.kid,
    alg: p.alg,
  };
}

/**
 * Verify a receipt per RFC 9942 section 5.2.1: apply the inclusion proof to
 * the candidate entry bytes; the recomputed root becomes the (detached)
 * payload whose signature the log made. Both steps must pass.
 */
export function verifyReceipt(
  receiptBytes: Uint8Array,
  statementBytes: Buffer,
  checkpointRoot: Buffer,
  logPublicKey: KeyObject,
): boolean {
  try {
    const receipt = parseReceipt(receiptBytes);
    const p = parseSign1(receipt.bytes);
    if (!HYPEREUM_OPERATED_ALLOWED_ALGS.includes(receipt.alg) || p.alg !== COSE_ALG.EdDSA) {
      return false;
    }
    if (logPublicKey.asymmetricKeyType !== 'ed25519') {
      return false;
    }
    const leaf = leafHash(statementBytes);
    if (!verifyInclusion(leaf, receipt.inclusion, checkpointRoot)) return false;
    return verifySign1(p, logPublicKey, { detachedPayload: checkpointRoot });
  } catch {
    return false;
  }
}

/** Attach receipts (label 394) + any RFC 3161 tokens (label -25900, private) to a statement. */
export const TIMESTAMP_TOKEN_LABEL = -25900;
export function attachReceipts(statementBytes: Buffer, receiptByteList: Buffer[]): Buffer {
  const parsed = parseSign1(statementBytes);
  const unprot = new Map(parsed.unprotected as Map<number, unknown>);
  unprot.set(COSE_LABEL.receipts, receiptByteList);
  return cborEncode(
    new CborTag(18, [parsed.protectedBytes, unprot, parsed.payload, parsed.signature] as never),
  );
}

export function extractReceipts(statementBytes: Uint8Array): Buffer[] {
  const parsed = parseSign1(Buffer.from(statementBytes));
  const raw = (parsed.unprotected as Map<unknown, unknown>).get(COSE_LABEL.receipts);
  if (!Array.isArray(raw)) return [];
  return raw.filter((r): r is Uint8Array => r instanceof Uint8Array).map((r) => Buffer.from(r));
}

/** The signed-statement bytes WITHOUT unprotected receipts — what the log leaf commits to. */
export function statementLeafBytes(statementBytes: Uint8Array): Buffer {
  const parsed = parseSign1(Buffer.from(statementBytes));
  const unprot = new Map(parsed.unprotected as Map<number, unknown>);
  unprot.delete(COSE_LABEL.receipts);
  unprot.delete(TIMESTAMP_TOKEN_LABEL);
  return cborEncode(
    new CborTag(18, [parsed.protectedBytes, unprot, parsed.payload, parsed.signature] as never),
  );
}

import { mlDsaVerify } from './mldsa.js';

/** ML-DSA (RFC 9964) countersignature verification, same Countersign_structure. */
export function verifyCountersignatureMlDsa(
  parsed: ParsedSign1,
  counterKid: string,
  publicKey: Buffer,
  alg: CoseAlg,
): boolean {
  const raw = (parsed.unprotected as Map<unknown, unknown>).get(COSE_LABEL.counterSignature);
  if (!Array.isArray(raw)) return false;
  for (const entry of raw) {
    if (!Array.isArray(entry) || entry.length !== 3) continue;
    const [protBytesRaw, , sigRaw] = entry as unknown[];
    if (!(protBytesRaw instanceof Uint8Array) || !(sigRaw instanceof Uint8Array)) continue;
    const protBytes = Buffer.from(protBytesRaw);
    const prot = cborDecode(protBytes);
    if (!(prot instanceof Map)) continue;
    const kidRaw = prot.get(COSE_LABEL.kid);
    const kid = kidRaw instanceof Uint8Array ? Buffer.from(kidRaw).toString('utf8') : '';
    if (kid !== counterKid || Number(prot.get(COSE_LABEL.alg)) !== alg) continue;
    const toVerify = cborEncode([
      'CounterSignature',
      parsed.protectedBytes,
      protBytes,
      Buffer.alloc(0),
      parsed.signature,
    ]);
    if (mlDsaVerify(alg, publicKey, toVerify, Buffer.from(sigRaw as Uint8Array))) return true;
  }
  return false;
}
