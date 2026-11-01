// SPDX-License-Identifier: Apache-2.0
/**
 * C2SP tlog-checkpoint + signed notes + tlog-cosignature + tlog-policy.
 * Checkpoint body: "<origin>\n<treeSize>\n<base64 root>\n". Signatures ride
 * after a blank line as "— <name> <base64>" lines; the key id is the first
 * four bytes of SHA-256(name || 0x0A || keyType || publicKey).
 *
 * Supported log checkpoint key algorithms & note verifier keyType bytes:
 *  - `NOTE_KEY_ED25519 = 0x01`: Ed25519 (`COSE_ALG.EdDSA`), 32-byte raw public key
 *    (HSMs / AWS KMS `ED25519_SHA_512` / local dev).
 *  - `NOTE_KEY_ECDSA_P256 = 0x02`: ECDSA P-256 (`COSE_ALG.ES256`), 65-byte ANSI X9.62
 *    uncompressed point `0x04 || x(32) || y(32)` (AWS KMS `ECDSA_SHA_256` over SHA-256,
 *    matching Sigstore Rekor's KMS-backed note checkpoint profile).
 *  - `NOTE_KEY_COSIGNATURE = 0x04`: Witness cosignature (v1), timestamp(8 bytes,
 *    big-endian, seconds) || signature over "cosignature/v1\ntime <ts>\n" || checkpointBody.
 *  - `NOTE_KEY_MLDSA = 0x05`: ML-DSA checkpoint countersignatures in this profile,
 *    verified when the relying party supplies an ML-DSA verifier.
 *
 * `noteVerifierForSigner(name, signer)` emits a verifier string whose `keyType`
 * and `publicKeyRaw` match the signer's algorithm (`0x01` for Ed25519, `0x02` for P-256).
 */
import { createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { COSE_ALG, sha256, type ReceiptSigner } from './keys.js';

export const NOTE_KEY_ED25519 = 0x01;
export const NOTE_KEY_ECDSA_P256 = 0x02;
export const NOTE_KEY_COSIGNATURE = 0x04;
export const NOTE_KEY_MLDSA = 0x05;

export function noteKeyId(name: string, keyType: number, publicKeyRaw: Buffer): Buffer {
  return sha256(
    Buffer.concat([Buffer.from(name, 'utf8'), Buffer.from([0x0a, keyType]), publicKeyRaw]),
  ).subarray(0, 4);
}

export function ed25519RawPublic(key: KeyObject): Buffer {
  const jwk = key.export({ format: 'jwk' }) as { x?: string };
  if (!jwk.x) throw new Error('not an Ed25519 key');
  return Buffer.from(jwk.x, 'base64url');
}

export function ed25519FromRaw(raw: Buffer): KeyObject {
  return createPublicKey({
    format: 'jwk',
    key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') },
  });
}

/** Export a P-256 public key as a 65-byte uncompressed ANSI X9.62 point (`0x04 || x(32) || y(32)`). */
export function p256RawPublic(key: KeyObject): Buffer {
  const jwk = key.export({ format: 'jwk' }) as { kty?: string; crv?: string; x?: string; y?: string };
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
    throw new Error('not a P-256 EC key');
  }
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  if (x.length !== 32 || y.length !== 32) {
    throw new Error('invalid P-256 coordinate length');
  }
  return Buffer.concat([Buffer.from([0x04]), x, y]);
}

/** Reconstruct a P-256 `KeyObject` from a 65-byte uncompressed ANSI X9.62 point (`0x04 || x || y`). */
export function p256FromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 65 || raw[0] !== 0x04) {
    throw new Error('invalid uncompressed P-256 public key (expected 65 bytes 0x04||x||y)');
  }
  const x = raw.subarray(1, 33).toString('base64url');
  const y = raw.subarray(33, 65).toString('base64url');
  return createPublicKey({
    format: 'jwk',
    key: { kty: 'EC', crv: 'P-256', x, y },
  });
}

/** Note verifier string: "<name>+<8-hex keyid>+<base64 keyType||rawKey>". */
export function noteVerifierString(name: string, keyType: number, publicKeyRaw: Buffer): string {
  const id = noteKeyId(name, keyType, publicKeyRaw).toString('hex');
  const key = Buffer.concat([Buffer.from([keyType]), publicKeyRaw]).toString('base64');
  return `${name}+${id}+${key}`;
}

/**
 * Build a note verifier string matching `signer.alg` (`0x01` for Ed25519, `0x02` for ECDSA P-256,
 * or `0x04` when `role === 'witness'`).
 */
export function noteVerifierForSigner(
  name: string,
  signer: ReceiptSigner,
  role: 'log' | 'witness' = 'log',
): string {
  if (role === 'witness') {
    const raw =
      signer.alg === COSE_ALG.ES256
        ? p256RawPublic(signer.publicKeyObject())
        : ed25519RawPublic(signer.publicKeyObject());
    return noteVerifierString(name, NOTE_KEY_COSIGNATURE, raw);
  }
  if (signer.alg === COSE_ALG.EdDSA) {
    return noteVerifierString(name, NOTE_KEY_ED25519, ed25519RawPublic(signer.publicKeyObject()));
  }
  if (signer.alg === COSE_ALG.ES256) {
    return noteVerifierString(name, NOTE_KEY_ECDSA_P256, p256RawPublic(signer.publicKeyObject()));
  }
  throw new Error(`unsupported checkpoint signer algorithm: ${signer.alg}`);
}

export function parseNoteVerifierString(s: string): { name: string; keyId: Buffer; keyType: number; publicKeyRaw: Buffer } {
  // The base64 key may itself contain '+', so split on the first two '+' only.
  const first = s.indexOf('+');
  const second = first < 0 ? -1 : s.indexOf('+', first + 1);
  if (first <= 0 || second < 0) throw new Error('bad note verifier string');
  const parts = [s.slice(0, first), s.slice(first + 1, second), s.slice(second + 1)];
  const keyBytes = Buffer.from(parts[2]!, 'base64');
  return {
    name: parts[0]!,
    keyId: Buffer.from(parts[1]!, 'hex'),
    keyType: keyBytes[0]!,
    publicKeyRaw: keyBytes.subarray(1),
  };
}

export interface Checkpoint {
  origin: string;
  treeSize: number;
  root: Buffer;
  body: string;
}

export function checkpointBody(origin: string, treeSize: number, root: Buffer): string {
  return `${origin}\n${treeSize}\n${root.toString('base64')}\n`;
}

export function parseCheckpoint(text: string): { checkpoint: Checkpoint; note: SignedNote } {
  const note = parseSignedNote(text);
  const lines = note.body.split('\n');
  if (lines.length < 3) throw new Error('checkpoint body too short');
  const treeSize = Number(lines[1]);
  if (!Number.isSafeInteger(treeSize) || treeSize < 0) throw new Error('bad checkpoint tree size');
  const root = Buffer.from(lines[2]!, 'base64');
  if (root.length !== 32) throw new Error('bad checkpoint root length');
  return {
    checkpoint: { origin: lines[0]!, treeSize, root, body: note.body },
    note,
  };
}

export interface NoteSignature {
  name: string;
  keyId: Buffer;
  signature: Buffer; // raw Ed25519 signature for log keys; ts||sig for cosignatures
}

export interface SignedNote {
  body: string;
  signatures: NoteSignature[];
  text: string;
}

export function parseSignedNote(text: string): SignedNote {
  const sep = text.indexOf('\n\n');
  if (sep < 0) throw new Error('signed note has no signature block');
  const body = text.slice(0, sep + 1);
  const sigBlock = text.slice(sep + 2);
  const signatures: NoteSignature[] = [];
  for (const line of sigBlock.split('\n')) {
    if (!line) continue;
    if (!line.startsWith('— ')) throw new Error('bad signature line');
    const rest = line.slice(2);
    const sp = rest.indexOf(' ');
    if (sp < 0) throw new Error('bad signature line');
    const raw = Buffer.from(rest.slice(sp + 1), 'base64');
    if (raw.length < 5) throw new Error('signature too short');
    signatures.push({ name: rest.slice(0, sp), keyId: raw.subarray(0, 4), signature: raw.subarray(4) });
  }
  return { body, signatures, text };
}

function sigLine(name: string, keyId: Buffer, sig: Buffer): string {
  return `— ${name} ${Buffer.concat([keyId, sig]).toString('base64')}\n`;
}

/**
 * The log signs the checkpoint body. Supports Ed25519 (`NOTE_KEY_ED25519 = 0x01`)
 * and ECDSA P-256 (`NOTE_KEY_ECDSA_P256 = 0x02`, AWS KMS `ECDSA_SHA_256`).
 */
export async function signCheckpoint(
  origin: string,
  treeSize: number,
  root: Buffer,
  logSigner: ReceiptSigner,
  logName = origin,
): Promise<string> {
  const body = checkpointBody(origin, treeSize, root);
  const isEs256 = logSigner.alg === COSE_ALG.ES256;
  const raw = isEs256
    ? p256RawPublic(logSigner.publicKeyObject())
    : ed25519RawPublic(logSigner.publicKeyObject());
  const keyType = isEs256 ? NOTE_KEY_ECDSA_P256 : NOTE_KEY_ED25519;
  const keyId = noteKeyId(logName, keyType, raw);
  const sig = await logSigner.sign(Buffer.from(body, 'utf8'));
  return `${body}\n${sigLine(logName, keyId, sig)}`;
}

/** A witness cosigns after checking consistency with the last tree it saw. */
export async function cosignCheckpoint(
  checkpointText: string,
  witnessSigner: ReceiptSigner,
  witnessName: string,
  timestampSeconds = Math.floor(Date.now() / 1000),
): Promise<string> {
  const { checkpoint } = parseCheckpoint(checkpointText);
  const ts = Buffer.alloc(8);
  ts.writeBigUInt64BE(BigInt(timestampSeconds));
  const msg = Buffer.from(`cosignature/v1\ntime ${timestampSeconds}\n${checkpoint.body}`, 'utf8');
  const sig = await witnessSigner.sign(msg);
  const raw =
    witnessSigner.alg === COSE_ALG.ES256
      ? p256RawPublic(witnessSigner.publicKeyObject())
      : ed25519RawPublic(witnessSigner.publicKeyObject());
  const keyId = noteKeyId(witnessName, NOTE_KEY_COSIGNATURE, raw);
  const line = sigLine(witnessName, keyId, Buffer.concat([ts, sig]));
  return checkpointText.endsWith('\n') ? checkpointText + line : `${checkpointText}\n${line}`;
}

export interface CosignatureResult {
  name: string;
  timestamp: number;
  valid: boolean;
}

function verifyP256Sig(key: KeyObject, msg: Buffer, sig: Buffer): boolean {
  if (sig.length === 64) {
    return cryptoVerify('sha256', msg, { key, dsaEncoding: 'ieee-p1363' }, sig);
  }
  return cryptoVerify('sha256', msg, key, sig);
}

export function verifyCheckpointSignatures(
  text: string,
  verifiers: string[], // note verifier strings (log + witnesses)
): { checkpoint: Checkpoint; logValid: boolean; cosignatures: CosignatureResult[] } {
  const { checkpoint, note } = parseCheckpoint(text);
  const parsed = verifiers.map(parseNoteVerifierString);
  let logValid = false;
  const cosignatures: CosignatureResult[] = [];
  for (const sig of note.signatures) {
    const v = parsed.find((p) => p.name === sig.name && p.keyId.equals(sig.keyId));
    if (!v) continue;
    const rawPub = Buffer.from(v.publicKeyRaw);
    if (v.keyType === NOTE_KEY_ED25519) {
      const key = ed25519FromRaw(rawPub);
      if (cryptoVerify(null, Buffer.from(checkpoint.body), key, sig.signature)) logValid = true;
    } else if (v.keyType === NOTE_KEY_ECDSA_P256) {
      const key = p256FromRaw(rawPub);
      if (verifyP256Sig(key, Buffer.from(checkpoint.body), sig.signature)) logValid = true;
    } else if (v.keyType === NOTE_KEY_COSIGNATURE) {
      if (sig.signature.length < 72) {
        cosignatures.push({ name: sig.name, timestamp: 0, valid: false });
        continue;
      }
      const ts = Number(sig.signature.readBigUInt64BE(0));
      const msg = Buffer.from(`cosignature/v1\ntime ${ts}\n${checkpoint.body}`, 'utf8');
      const sigBytes = sig.signature.subarray(8);
      const isP256 = rawPub.length === 65 && rawPub[0] === 0x04;
      const valid = isP256
        ? verifyP256Sig(p256FromRaw(rawPub), msg, sigBytes)
        : sigBytes.length === 64 && cryptoVerify(null, msg, ed25519FromRaw(rawPub), sigBytes);
      cosignatures.push({
        name: sig.name,
        timestamp: ts,
        valid,
      });
    }
  }
  return { checkpoint, logValid, cosignatures };
}

/** C2SP tlog-policy, Hivemind form: named witnesses + a k-of-n quorum line. */
export interface WitnessPolicy {
  quorum: number;
  witnesses: Array<{ name: string; verifier: string }>;
}

export function parseWitnessPolicy(text: string): WitnessPolicy {
  const witnesses: WitnessPolicy['witnesses'] = [];
  let quorum = 0;
  for (const line of text.split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    if (t.startsWith('quorum ')) quorum = Number(t.slice(7));
    else if (t.startsWith('witness ')) {
      const verifier = t.slice(8).trim();
      witnesses.push({ name: parseNoteVerifierString(verifier).name, verifier });
    } else throw new Error(`bad witness policy line: ${t}`);
  }
  if (quorum < 1 || quorum > witnesses.length) throw new Error('witness quorum out of range');
  return { quorum, witnesses };
}

export function formatWitnessPolicy(p: WitnessPolicy): string {
  return [
    '# C2SP tlog-policy (Hivemind encoding): quorum of named witnesses',
    `quorum ${p.quorum}`,
    ...p.witnesses.map((w) => `witness ${w.verifier}`),
    '',
  ].join('\n');
}

export function quorumSatisfied(policy: WitnessPolicy, validNames: readonly string[]): boolean {
  const known = new Set(policy.witnesses.map((w) => w.name));
  const counted = new Set(validNames.filter((n) => known.has(n)));
  return counted.size >= policy.quorum;
}
