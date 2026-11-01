// SPDX-License-Identifier: Apache-2.0
/**
 * RFC 9162 SHA-256 Merkle tree — the RFC9162_SHA256 verifiable data structure
 * (value 1 in the RFC 9942 registry). Leaf hash H(0x00||data), node hash
 * H(0x01||left||right), largest-power-of-two split, no padding. Inclusion and
 * consistency proofs follow RFC 9162 §2.1; verification is the iterative form
 * every C2SP client implements. The same code serves the public log, causal
 * graph roots and 4,096-capsule batches.
 */
import { sha256 } from './keys.js';

export const VDS_RFC9162_SHA256 = 1;
const EMPTY_ROOT = sha256(new Uint8Array(0));

export function leafHash(data: Uint8Array): Buffer {
  return sha256(Buffer.concat([Buffer.from([0x00]), data]));
}
function nodeHash(left: Buffer, right: Buffer): Buffer {
  return sha256(Buffer.concat([Buffer.from([0x01]), left, right]));
}
function largestPow2LessThan(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** Merkle Tree Hash over leaf hashes. */
export function mth(leaves: readonly Buffer[]): Buffer {
  if (leaves.length === 0) return Buffer.from(EMPTY_ROOT);
  if (leaves.length === 1) return Buffer.from(leaves[0]!);
  const k = largestPow2LessThan(leaves.length);
  return nodeHash(mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}

export function rootFromLeafData(data: readonly Uint8Array[]): Buffer {
  return mth(data.map(leafHash));
}

function auditPath(m: number, leaves: readonly Buffer[]): Buffer[] {
  if (leaves.length === 1) return [];
  const k = largestPow2LessThan(leaves.length);
  if (m < k) return [...auditPath(m, leaves.slice(0, k)), mth(leaves.slice(k))];
  return [...auditPath(m - k, leaves.slice(k)), mth(leaves.slice(0, k))];
}

export interface InclusionProof {
  treeSize: number;
  leafIndex: number;
  hashes: Buffer[];
}

export function inclusionProof(leafIndex: number, leaves: readonly Buffer[]): InclusionProof {
  if (leafIndex < 0 || leafIndex >= leaves.length) throw new Error('leaf index out of range');
  return { treeSize: leaves.length, leafIndex, hashes: auditPath(leafIndex, leaves) };
}

/** RFC 9162 §2.1.3.2 verification. `leaf` is the leaf hash (already H(0x00||data)). */
export function verifyInclusion(leaf: Buffer, proof: InclusionProof, root: Buffer): boolean {
  const { treeSize, leafIndex, hashes } = proof;
  if (leafIndex >= treeSize || treeSize < 1) return false;
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leaf;
  for (const p of hashes) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      while (fn % 2 === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && r.equals(root);
}

function subproof(m: number, leaves: readonly Buffer[], complete: boolean): Buffer[] {
  const n = leaves.length;
  if (m === n) return complete ? [] : [mth(leaves)];
  const k = largestPow2LessThan(n);
  if (m <= k) return [...subproof(m, leaves.slice(0, k), complete), mth(leaves.slice(k))];
  return [...subproof(m - k, leaves.slice(k), false), mth(leaves.slice(0, k))];
}

export interface ConsistencyProof {
  firstSize: number;
  secondSize: number;
  hashes: Buffer[];
}

export function consistencyProof(firstSize: number, leaves: readonly Buffer[]): ConsistencyProof {
  if (firstSize < 1 || firstSize > leaves.length) throw new Error('consistency size out of range');
  if (firstSize === leaves.length) return { firstSize, secondSize: leaves.length, hashes: [] };
  return { firstSize, secondSize: leaves.length, hashes: subproof(firstSize, leaves, true) };
}

/** RFC 9162 §2.1.4.2 verification against both roots. */
export function verifyConsistency(
  proof: ConsistencyProof,
  firstRoot: Buffer,
  secondRoot: Buffer,
): boolean {
  const { firstSize, secondSize } = proof;
  let hashes = proof.hashes;
  if (firstSize === secondSize) return hashes.length === 0 && firstRoot.equals(secondRoot);
  if (firstSize < 1 || firstSize >= secondSize) return false;
  // When firstSize is an exact power of two (1 included), prepend firstRoot.
  if ((firstSize & (firstSize - 1)) === 0) hashes = [firstRoot, ...hashes];
  if (hashes.length === 0) return false;
  let fn = firstSize - 1;
  let sn = secondSize - 1;
  while (fn % 2 === 1) {
    fn >>= 1;
    sn >>= 1;
  }
  let fr = hashes[0]!;
  let sr = hashes[0]!;
  for (const c of hashes.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return fr.equals(firstRoot) && sr.equals(secondRoot) && sn === 0;
}

/** Tile-level helper (C2SP tlog-tiles): hash of a level-`level` tile from its 256 child hashes. */
export function tileHash(childHashes: readonly Buffer[]): Buffer {
  if (childHashes.length === 0 || (childHashes.length & (childHashes.length - 1)) !== 0)
    throw new Error('tile children must be a non-empty power of two');
  let level = [...childHashes];
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) next.push(nodeHash(level[i]!, level[i + 1]!));
    level = next;
  }
  return level[0]!;
}

export const EMPTY_TREE_ROOT_HEX = EMPTY_ROOT.toString('hex');
