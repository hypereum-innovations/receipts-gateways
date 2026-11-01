// SPDX-License-Identifier: Apache-2.0
/**
 * Trust-root distribution with TUF semantics (as Sigstore ships its keys):
 * a root role signed by a threshold of root keys authorizes the targets,
 * snapshot and timestamp roles; versions are monotonic (rollback is
 * rejected), expirations are enforced, and every target file (log keys,
 * witness keys, TSA roots, CA root, EU Trusted List snapshot) is pinned by
 * SHA-256 in signed metadata. Canonical JSON (sorted keys) is the signed
 * form. This is a deliberately small TUF: the security properties that
 * matter here — threshold root rotation, rollback and freeze resistance —
 * are all enforced client-side.
 */
import { sign as cryptoSign, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { ed25519FromRaw } from './checkpoint.js';
import { jcsStringify } from './cbor.js';
import { sha256 } from './keys.js';

export interface TufSignature {
  keyid: string;
  sig: string; // hex Ed25519 over canonical signed body
}

export interface TufSigned<T> {
  signed: T;
  signatures: TufSignature[];
}

export interface RootBody {
  _type: 'root';
  version: number;
  expires: string;
  keys: Record<string, { keytype: 'ed25519'; public: string }>; // keyid -> hex raw key
  roles: Record<'root' | 'targets' | 'snapshot' | 'timestamp', { keyids: string[]; threshold: number }>;
}

export interface TargetsBody {
  _type: 'targets';
  version: number;
  expires: string;
  targets: Record<string, { length: number; hashes: { sha256: string }; custom?: Record<string, unknown> }>;
}

export interface MetaBody {
  _type: 'snapshot' | 'timestamp';
  version: number;
  expires: string;
  meta: Record<string, { version: number; length: number; hashes: { sha256: string } }>;
}

export function keyidOfRaw(rawEd25519: Buffer): string {
  return sha256(Buffer.concat([Buffer.from('ed25519:'), rawEd25519])).toString('hex').slice(0, 16);
}

export function signTuf<T extends object>(
  body: T,
  signers: Array<{ keyid: string; privateKey: KeyObject }>,
): TufSigned<T> {
  const canonical = Buffer.from(jcsStringify(body), 'utf8');
  return {
    signed: body,
    signatures: signers.map((s) => ({
      keyid: s.keyid,
      sig: cryptoSign(null, canonical, s.privateKey).toString('hex'),
    })),
  };
}

function countValid<T>(doc: TufSigned<T>, root: RootBody, role: keyof RootBody['roles']): number {
  const spec = root.roles[role];
  const canonical = Buffer.from(jcsStringify(doc.signed), 'utf8');
  const validKeyids = new Set<string>();
  for (const sig of doc.signatures) {
    if (!spec.keyids.includes(sig.keyid)) continue;
    const key = root.keys[sig.keyid];
    if (!key) continue;
    try {
      if (cryptoVerify(null, canonical, ed25519FromRaw(Buffer.from(key.public, 'hex')), Buffer.from(sig.sig, 'hex')))
        validKeyids.add(sig.keyid);
    } catch {
      /* invalid signature simply doesn't count */
    }
  }
  return validKeyids.size;
}

function assertFresh(expires: string, now: Date, what: string): void {
  if (new Date(expires).getTime() < now.getTime()) throw new Error(`TUF: ${what} metadata expired at ${expires}`);
}

export interface LoadedTrustRoots {
  rootVersion: number;
  targetsVersion: number;
  files: Map<string, Buffer>;
}

/**
 * Full client update: root (threshold, version must be >= pinned), timestamp,
 * snapshot, targets, then every target file hash-checked. Any rollback,
 * expiry or hash mismatch aborts with the previous state untouched.
 */
export function loadTrustRoots(input: {
  pinnedRoot: TufSigned<RootBody>;
  newRoot?: TufSigned<RootBody>;
  timestamp: TufSigned<MetaBody>;
  snapshot: TufSigned<MetaBody>;
  targets: TufSigned<TargetsBody>;
  files: Map<string, Buffer>;
  now?: Date;
}): LoadedTrustRoots {
  const now = input.now ?? new Date();
  let root = input.pinnedRoot.signed;
  // The pinned root is trusted by pinning; a NEW root must be signed by both old and new thresholds.
  if (input.newRoot) {
    const candidate = input.newRoot;
    if (candidate.signed.version < root.version) throw new Error('TUF: root rollback rejected');
    if (candidate.signed.version > root.version) {
      if (countValid(candidate, root, 'root') < root.roles.root.threshold)
        throw new Error('TUF: new root lacks old-root threshold signatures');
      if (countValid(candidate, candidate.signed, 'root') < candidate.signed.roles.root.threshold)
        throw new Error('TUF: new root lacks self-threshold signatures');
      root = candidate.signed;
    }
  }
  assertFresh(root.expires, now, 'root');
  for (const [doc, role] of [
    [input.timestamp, 'timestamp'],
    [input.snapshot, 'snapshot'],
    [input.targets, 'targets'],
  ] as const) {
    if (countValid(doc as never, root, role) < root.roles[role].threshold)
      throw new Error(`TUF: ${role} metadata below signature threshold`);
    assertFresh((doc.signed as { expires: string }).expires, now, role);
  }
  // Cross-check versions through timestamp -> snapshot -> targets.
  const snapMeta = input.timestamp.signed.meta['snapshot.json'];
  if (snapMeta && snapMeta.version !== input.snapshot.signed.version)
    throw new Error('TUF: snapshot version mismatch with timestamp metadata');
  const tgtMeta = input.snapshot.signed.meta['targets.json'];
  if (tgtMeta && tgtMeta.version !== input.targets.signed.version)
    throw new Error('TUF: targets version mismatch with snapshot metadata');
  const files = new Map<string, Buffer>();
  for (const [name, info] of Object.entries(input.targets.signed.targets)) {
    const data = input.files.get(name);
    if (!data) throw new Error(`TUF: missing target file ${name}`);
    if (data.length !== info.length) throw new Error(`TUF: length mismatch for ${name}`);
    if (sha256(data).toString('hex') !== info.hashes.sha256) throw new Error(`TUF: hash mismatch for ${name}`);
    files.set(name, data);
  }
  return { rootVersion: root.version, targetsVersion: input.targets.signed.version, files };
}
