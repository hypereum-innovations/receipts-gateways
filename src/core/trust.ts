// SPDX-License-Identifier: Apache-2.0
/** Trust-root file helpers shared by the CLI, SDKs and the browser verifier. */
import { cborEncode } from './cbor.js';
import { ed25519RawPublic, noteVerifierString, NOTE_KEY_COSIGNATURE, NOTE_KEY_ED25519 } from './checkpoint.js';
import type { ReceiptSigner } from './keys.js';
import type { TrustRoots } from './verify.js';

export { LocalSigner, decodeCoseKey, publicKeyFromCoseKey } from './keys.js';

export function cborEncodeTrustKey(signer: ReceiptSigner): Buffer {
  return cborEncode(signer.publicCoseKey());
}

export interface TrustFileShape {
  issuers: Array<{ kid: string; cose_key: string; tier: 'T0' | 'T1' | 'T2' | 'T3'; display: string }>;
  log_keys: Array<{ kid: string; cose_key: string }>;
  note_verifiers: string[];
  witness_policy?: { quorum: number; witnesses: Array<{ name: string; verifier: string }> };
  counter_signers?: Array<{ kid: string; cose_key: string }>;
}

export function buildTrustFile(input: {
  issuers: Array<{ signer: ReceiptSigner; tier: 'T0' | 'T1' | 'T2' | 'T3'; display: string }>;
  logSigner: ReceiptSigner;
  logName: string;
  witnesses: Array<{ name: string; signer: ReceiptSigner }>;
  quorum: number;
  counterSigners?: ReceiptSigner[];
}): TrustFileShape {
  const witnessVerifiers = input.witnesses.map((w) =>
    noteVerifierString(w.name, NOTE_KEY_COSIGNATURE, ed25519RawPublic(w.signer.publicKeyObject())),
  );
  return {
    issuers: input.issuers.map((i) => ({
      kid: i.signer.kid,
      cose_key: cborEncodeTrustKey(i.signer).toString('base64url'),
      tier: i.tier,
      display: i.display,
    })),
    log_keys: [{ kid: input.logSigner.kid, cose_key: cborEncodeTrustKey(input.logSigner).toString('base64url') }],
    note_verifiers: [
      noteVerifierString(input.logName, NOTE_KEY_ED25519, ed25519RawPublic(input.logSigner.publicKeyObject())),
      ...witnessVerifiers,
    ],
    witness_policy: {
      quorum: input.quorum,
      witnesses: input.witnesses.map((w, i) => ({ name: w.name, verifier: witnessVerifiers[i]! })),
    },
    ...(input.counterSigners?.length
      ? { counter_signers: input.counterSigners.map((s) => ({ kid: s.kid, cose_key: cborEncodeTrustKey(s).toString('base64url') })) }
      : {}),
  };
}

export function emptyTrust(): TrustRoots {
  return { issuers: new Map(), logKeys: new Map(), noteVerifiers: [], witnessPolicy: null };
}

export const PRODUCTION_WITNESS_QUORUM = 3;
export const PRODUCTION_WITNESS_TOTAL = 5;

/**
 * Build production TrustRoots enforcing the mandatory 3-of-5 witness quorum
 * policy (or a caller-supplied >=3 quorum over >=5 independent witnesses).
 */
export function createProductionTrustRoots(input: {
  issuers: Array<{ signer: ReceiptSigner; tier: 'T0' | 'T1' | 'T2' | 'T3'; display: string }>;
  logSigner: ReceiptSigner;
  logName: string;
  witnesses: Array<{ name: string; signer: ReceiptSigner }>;
  quorum?: number;
}): { trustRoots: TrustRoots; trustFile: TrustFileShape } {
  const quorum = input.quorum ?? PRODUCTION_WITNESS_QUORUM;
  if (input.witnesses.length < PRODUCTION_WITNESS_TOTAL) {
    throw new Error(
      `production trust policy requires at least ${PRODUCTION_WITNESS_TOTAL} witnesses, got ${input.witnesses.length}`,
    );
  }
  if (quorum < PRODUCTION_WITNESS_QUORUM || quorum > input.witnesses.length) {
    throw new Error(
      `production witness quorum must be in [${PRODUCTION_WITNESS_QUORUM}..${input.witnesses.length}], got ${quorum}`,
    );
  }
  const trustFile = buildTrustFile({
    issuers: input.issuers,
    logSigner: input.logSigner,
    logName: input.logName,
    witnesses: input.witnesses,
    quorum,
  });
  const issuersMap: TrustRoots['issuers'] = new Map();
  for (const i of input.issuers) {
    issuersMap.set(i.signer.kid, {
      kid: i.signer.kid,
      key: i.signer.publicKeyObject(),
      alg: i.signer.alg,
      tier: i.tier,
      display: i.display,
    });
  }
  const logKeysMap: TrustRoots['logKeys'] = new Map([
    [
      input.logSigner.kid,
      {
        kid: input.logSigner.kid,
        key: input.logSigner.publicKeyObject(),
        alg: input.logSigner.alg,
      },
    ],
  ]);
  return {
    trustRoots: {
      issuers: issuersMap,
      logKeys: logKeysMap,
      noteVerifiers: trustFile.note_verifiers,
      witnessPolicy: trustFile.witness_policy ?? null,
    },
    trustFile,
  };
}
