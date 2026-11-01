// SPDX-License-Identifier: Apache-2.0
/**
 * Merkle batching: a high-volume issuer signs ONE statement over a batch of up
 * to 4,096 capsule payloads. Leaf i = H(0x00 || capsuleBytes_i) (RFC 9162 leaf
 * over the canonical capsule bytes, capsule_id inside binds content). The
 * batch statement payload commits to (root, count, profile, issuer window);
 * each capsule keeps individual verifiability through its inclusion path.
 */
import { cborDecode, cborEncode } from './cbor.js';
import { inclusionProof, leafHash, mth, verifyInclusion, type InclusionProof } from './merkle.js';
import { parseCapsule } from './capsule.js';

export const BATCH_PROFILE_URI = 'urn:hivemind:receipts:capsule-batch:1';
export const BATCH_MEDIA_TYPE = 'application/vnd.hivemind.agent-action-capsule-batch+cbor';
export const MAX_BATCH = 4096;

export interface BatchPayload {
  profile: typeof BATCH_PROFILE_URI;
  batch_root: string;
  count: number;
  first_action_id: string;
  last_action_id: string;
  window_start: string;
  window_end: string;
}

export function buildBatch(capsuleBytesList: Buffer[]): {
  payload: BatchPayload;
  payloadBytes: Buffer;
  leaves: Buffer[];
  proofFor: (index: number) => InclusionProof;
} {
  if (capsuleBytesList.length === 0 || capsuleBytesList.length > MAX_BATCH)
    throw new Error(`batch size must be 1..${MAX_BATCH}`);
  const capsules = capsuleBytesList.map((b) => parseCapsule(b));
  const leaves = capsuleBytesList.map((b) => leafHash(b));
  const root = mth(leaves);
  const payload: BatchPayload = {
    profile: BATCH_PROFILE_URI,
    batch_root: `sha256:${root.toString('hex')}`,
    count: capsules.length,
    first_action_id: capsules[0]!.action_id,
    last_action_id: capsules[capsules.length - 1]!.action_id,
    window_start: capsules[0]!.issued_at,
    window_end: capsules[capsules.length - 1]!.issued_at,
  };
  return {
    payload,
    payloadBytes: cborEncode(payload as never),
    leaves,
    proofFor: (i) => inclusionProof(i, leaves),
  };
}

export function parseBatchPayload(bytes: Uint8Array): BatchPayload {
  const v = cborDecode(bytes);
  if (!(v instanceof Map)) throw new Error('batch payload must be a map');
  const get = (k: string) => v.get(k);
  if (get('profile') !== BATCH_PROFILE_URI) throw new Error('bad batch profile');
  const payload = {
    profile: BATCH_PROFILE_URI,
    batch_root: String(get('batch_root')),
    count: Number(get('count')),
    first_action_id: String(get('first_action_id')),
    last_action_id: String(get('last_action_id')),
    window_start: String(get('window_start')),
    window_end: String(get('window_end')),
  } as BatchPayload;
  if (payload.count < 1 || payload.count > MAX_BATCH) throw new Error('batch count out of range');
  return payload;
}

export function verifyBatchInclusion(
  capsuleBytes: Buffer,
  proof: InclusionProof,
  batchRootDigest: string,
): boolean {
  const rootHex = batchRootDigest.replace(/^sha256:/, '');
  return verifyInclusion(leafHash(capsuleBytes), proof, Buffer.from(rootHex, 'hex'));
}
