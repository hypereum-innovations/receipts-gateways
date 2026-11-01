// SPDX-License-Identifier: Apache-2.0
/**
 * Bounded TypeScript check (BFS finite-state exploration in TypeScript, not TLC)
 * for the Hivemind Receipts protocol (`docs/receipts/HivemindReceipts.tla`,
 * configured via `docs/receipts/HivemindReceipts.cfg` and recorded in `docs/receipts/FORMAL-MODEL-RUN.json`).
 *
 * Explores bounded protocol states across honest and Byzantine/adversarial
 * transitions (`IssueCapsule`, `AppendToLog`, `AdversaryPublishConflictingCheckpoint`,
 * `WitnessCosign`, `VerifyBundle`) and checks the four safety invariants:
 *  - `INV_NoUnsignedRegistered`
 *  - `INV_AnchoredRequiresVerifiedReceipt`
 *  - `INV_NoSplitViewWithWitnessQuorum`
 *  - `INV_ConfirmedEffectHasObservedDigest`
 */

export type ModelVerdict = 'executed' | 'blocked';
export type ModelEffectStatus = 'confirmed' | 'asserted' | 'none';
export type ModelLedgerMode = 'standalone' | 'anchored';
export type ModelRoot = 'root_A' | 'root_B';

export interface ModelCapsule {
  cid: string;
  verdict: ModelVerdict;
  effectStatus: ModelEffectStatus;
  hasRespDigest: boolean;
  ledgerMode: ModelLedgerMode;
}

export interface ModelStatement {
  cid: string;
  signedByTrustedIssuer: boolean;
}

export interface ModelLogEntry {
  cid: string;
  treeSize: number;
  root: ModelRoot;
}

export interface ModelCheckpoint {
  treeSize: number;
  root: ModelRoot;
  logSigned: boolean;
}

export interface ModelWitnessCosig {
  witness: string;
  treeSize: number;
  root: ModelRoot;
}

export interface ModelVerifiedBundle {
  cid: string;
  verdict: ModelVerdict;
  effectStatus: ModelEffectStatus;
  hasRespDigest: boolean;
  ledgerMode: ModelLedgerMode;
  signedByTrustedIssuer: boolean;
  receiptVerified: boolean;
  treeSize: number;
  root: ModelRoot;
}

export interface ProtocolState {
  capsules: ModelCapsule[];
  statements: ModelStatement[];
  logEntries: ModelLogEntry[];
  checkpoints: ModelCheckpoint[];
  witnessCosigs: ModelWitnessCosig[];
  verifiedBundles: ModelVerifiedBundle[];
}

export interface InvariantCheckResult {
  INV_NoUnsignedRegistered: boolean;
  INV_AnchoredRequiresVerifiedReceipt: boolean;
  INV_NoSplitViewWithWitnessQuorum: boolean;
  INV_ConfirmedEffectHasObservedDigest: boolean;
  allHold: boolean;
  violatedInvariant?: string;
}

export interface ModelCheckConfig {
  witnesses?: readonly string[];
  honestWitnesses?: readonly string[];
  witnessQuorum?: number;
  /** Optional fault injection to check that the bounded TypeScript check catches guard violations. */
  disableGuard?: 'unsigned' | 'anchored' | 'split_view' | 'confirmed';
}

export interface ModelCheckReport {
  ok: boolean;
  exploredStates: number;
  exploredTransitions: number;
  invariantsChecked: string[];
  violatedInvariant?: string;
  counterexampleTrace?: string[];
}

const DEFAULT_WITNESSES = ['w1', 'w2', 'w3', 'w4', 'w5'] as const;
const DEFAULT_HONEST_WITNESSES = ['w1', 'w2', 'w3', 'w4', 'w5'] as const; // C2SP non-equivocating witnesses (2*Q - N = 1 > 0)
const DEFAULT_QUORUM = 3;

export function initProtocolState(): ProtocolState {
  return {
    capsules: [],
    statements: [],
    logEntries: [],
    checkpoints: [],
    witnessCosigs: [],
    verifiedBundles: [],
  };
}

function canonicalStateKey(s: ProtocolState): string {
  const caps = s.capsules
    .map((c) => `${c.cid}:${c.verdict}:${c.effectStatus}:${c.hasRespDigest ? 1 : 0}:${c.ledgerMode}`)
    .sort()
    .join(',');
  const stmts = s.statements
    .map((st) => `${st.cid}:${st.signedByTrustedIssuer ? 1 : 0}`)
    .sort()
    .join(',');
  const logs = s.logEntries
    .map((l) => `${l.cid}@${l.treeSize}:${l.root}`)
    .sort()
    .join(',');
  const cps = s.checkpoints
    .map((cp) => `${cp.treeSize}:${cp.root}:${cp.logSigned ? 1 : 0}`)
    .sort()
    .join(',');
  const cosigs = s.witnessCosigs
    .map((cs) => `${cs.witness}@${cs.treeSize}:${cs.root}`)
    .sort()
    .join(',');
  const vbs = s.verifiedBundles
    .map(
      (vb) =>
        `${vb.cid}:${vb.verdict}:${vb.effectStatus}:${vb.hasRespDigest ? 1 : 0}:${vb.ledgerMode}:${vb.signedByTrustedIssuer ? 1 : 0}:${vb.receiptVerified ? 1 : 0}@${vb.treeSize}:${vb.root}`,
    )
    .sort()
    .join(',');
  return `C[${caps}]|S[${stmts}]|L[${logs}]|CP[${cps}]|W[${cosigs}]|V[${vbs}]`;
}

function quorumReached(
  state: ProtocolState,
  treeSize: number,
  root: ModelRoot,
  quorum: number,
  witnessSet: ReadonlySet<string>,
): boolean {
  const signers = new Set<string>();
  for (const cs of state.witnessCosigs) {
    if (cs.treeSize === treeSize && cs.root === root && witnessSet.has(cs.witness)) {
      signers.add(cs.witness);
    }
  }
  return signers.size >= quorum;
}

/** Check all four TLA+ safety invariants on a concrete protocol state. */
export function evaluateInvariants(
  state: ProtocolState,
  config: ModelCheckConfig = {},
): InvariantCheckResult {
  const witnesses = new Set(config.witnesses ?? DEFAULT_WITNESSES);
  const quorum = config.witnessQuorum ?? DEFAULT_QUORUM;

  // 1. INV_NoUnsignedRegistered
  const INV_NoUnsignedRegistered =
    state.logEntries.every((le) =>
      state.statements.some((s) => s.cid === le.cid && s.signedByTrustedIssuer),
    ) && state.verifiedBundles.every((vb) => vb.signedByTrustedIssuer);

  // 2. INV_AnchoredRequiresVerifiedReceipt
  const INV_AnchoredRequiresVerifiedReceipt = state.verifiedBundles.every((vb) => {
    if (vb.ledgerMode !== 'anchored') return true;
    const inLog = state.logEntries.some(
      (le) => le.cid === vb.cid && le.treeSize === vb.treeSize && le.root === vb.root,
    );
    const inCp = state.checkpoints.some(
      (cp) => cp.treeSize === vb.treeSize && cp.root === vb.root && cp.logSigned,
    );
    const hasQuorum = quorumReached(state, vb.treeSize, vb.root, quorum, witnesses);
    return vb.receiptVerified && inLog && inCp && hasQuorum;
  });

  // 3. INV_NoSplitViewWithWitnessQuorum
  let INV_NoSplitViewWithWitnessQuorum = true;
  for (const cp1 of state.checkpoints) {
    for (const cp2 of state.checkpoints) {
      if (
        cp1.treeSize === cp2.treeSize &&
        quorumReached(state, cp1.treeSize, cp1.root, quorum, witnesses) &&
        quorumReached(state, cp2.treeSize, cp2.root, quorum, witnesses) &&
        cp1.root !== cp2.root
      ) {
        INV_NoSplitViewWithWitnessQuorum = false;
      }
    }
  }

  // 4. INV_ConfirmedEffectHasObservedDigest
  const INV_ConfirmedEffectHasObservedDigest =
    state.capsules.every((c) =>
      c.effectStatus === 'confirmed' ? c.verdict === 'executed' && c.hasRespDigest : true,
    ) &&
    state.verifiedBundles.every((vb) =>
      vb.effectStatus === 'confirmed' ? vb.verdict === 'executed' && vb.hasRespDigest : true,
    );

  const allHold =
    INV_NoUnsignedRegistered &&
    INV_AnchoredRequiresVerifiedReceipt &&
    INV_NoSplitViewWithWitnessQuorum &&
    INV_ConfirmedEffectHasObservedDigest;

  let violatedInvariant: string | undefined;
  if (!INV_NoUnsignedRegistered) violatedInvariant = 'INV_NoUnsignedRegistered';
  else if (!INV_AnchoredRequiresVerifiedReceipt) violatedInvariant = 'INV_AnchoredRequiresVerifiedReceipt';
  else if (!INV_NoSplitViewWithWitnessQuorum) violatedInvariant = 'INV_NoSplitViewWithWitnessQuorum';
  else if (!INV_ConfirmedEffectHasObservedDigest) violatedInvariant = 'INV_ConfirmedEffectHasObservedDigest';

  return {
    INV_NoUnsignedRegistered,
    INV_AnchoredRequiresVerifiedReceipt,
    INV_NoSplitViewWithWitnessQuorum,
    INV_ConfirmedEffectHasObservedDigest,
    allHold,
    ...(violatedInvariant ? { violatedInvariant } : {}),
  };
}

function validCapsuleSemantics(
  verdict: ModelVerdict,
  effectStatus: ModelEffectStatus,
  hasRespDigest: boolean,
  disableConfirmedGuard: boolean,
): boolean {
  if (disableConfirmedGuard) return true;
  if (effectStatus === 'confirmed' && (verdict !== 'executed' || !hasRespDigest)) return false;
  if (verdict !== 'executed' && effectStatus === 'confirmed') return false;
  return true;
}

/** Generate all valid successor transitions (Next) from `state`. */
export function nextTransitions(
  state: ProtocolState,
  config: ModelCheckConfig = {},
): Array<{ action: string; state: ProtocolState }> {
  const witnesses = config.witnesses ?? DEFAULT_WITNESSES;
  const honestSet = new Set(config.honestWitnesses ?? DEFAULT_HONEST_WITNESSES);
  const witnessSet = new Set(witnesses);
  const quorum = config.witnessQuorum ?? DEFAULT_QUORUM;
  const out: Array<{ action: string; state: ProtocolState }> = [];

  // 1. IssueCapsule transitions for c1 (honest & adversarial combinations)
  if (state.capsules.length === 0) {
    const candidateSpecs: Array<{
      cid: string;
      verdict: ModelVerdict;
      effectStatus: ModelEffectStatus;
      hasRespDigest: boolean;
      ledgerMode: ModelLedgerMode;
      signedOk: boolean;
    }> = [
      { cid: 'c1', verdict: 'executed', effectStatus: 'confirmed', hasRespDigest: true, ledgerMode: 'anchored', signedOk: true },
      { cid: 'c1', verdict: 'executed', effectStatus: 'confirmed', hasRespDigest: true, ledgerMode: 'anchored', signedOk: false },
      { cid: 'c1', verdict: 'executed', effectStatus: 'confirmed', hasRespDigest: false, ledgerMode: 'standalone', signedOk: true },
      { cid: 'c1', verdict: 'blocked', effectStatus: 'none', hasRespDigest: false, ledgerMode: 'anchored', signedOk: true },
      { cid: 'c1', verdict: 'blocked', effectStatus: 'confirmed', hasRespDigest: true, ledgerMode: 'standalone', signedOk: true },
    ];
    for (const spec of candidateSpecs) {
      if (
        !validCapsuleSemantics(
          spec.verdict,
          spec.effectStatus,
          spec.hasRespDigest,
          config.disableGuard === 'confirmed',
        )
      ) {
        continue;
      }
      out.push({
        action: `IssueCapsule(${spec.cid},${spec.verdict},${spec.effectStatus},resp=${spec.hasRespDigest},mode=${spec.ledgerMode},sig=${spec.signedOk})`,
        state: {
          ...state,
          capsules: [
            ...state.capsules,
            {
              cid: spec.cid,
              verdict: spec.verdict,
              effectStatus: spec.effectStatus,
              hasRespDigest: spec.hasRespDigest,
              ledgerMode: spec.ledgerMode,
            },
          ],
          statements: [
            ...state.statements,
            { cid: spec.cid, signedByTrustedIssuer: spec.signedOk },
          ],
        },
      });
    }
  }

  // 2. AppendToLog(c1, treeSize=1, root_A)
  for (const stmt of state.statements) {
    const canAppend = config.disableGuard === 'unsigned' ? true : stmt.signedByTrustedIssuer;
    if (!canAppend) continue;
    const alreadyLogged = state.logEntries.some(
      (le) => le.cid === stmt.cid && le.treeSize === 1 && le.root === 'root_A',
    );
    if (!alreadyLogged) {
      const hasCp = state.checkpoints.some((cp) => cp.treeSize === 1 && cp.root === 'root_A');
      out.push({
        action: `AppendToLog(${stmt.cid},size=1,root_A)`,
        state: {
          ...state,
          logEntries: [...state.logEntries, { cid: stmt.cid, treeSize: 1, root: 'root_A' }],
          checkpoints: hasCp
            ? state.checkpoints
            : [...state.checkpoints, { treeSize: 1, root: 'root_A', logSigned: true }],
        },
      });
    }
  }

  // 3. AdversaryPublishConflictingCheckpoint(treeSize=1, root_B) when root_A checkpoint exists
  if (
    state.checkpoints.some((cp) => cp.treeSize === 1 && cp.root === 'root_A') &&
    !state.checkpoints.some((cp) => cp.treeSize === 1 && cp.root === 'root_B')
  ) {
    out.push({
      action: 'AdversaryPublishConflictingCheckpoint(size=1,root_B)',
      state: {
        ...state,
        checkpoints: [...state.checkpoints, { treeSize: 1, root: 'root_B', logSigned: true }],
      },
    });
  }

  // 4. WitnessCosign(w, treeSize=1, root)
  for (const cp of state.checkpoints) {
    if (!cp.logSigned) continue;
    for (const w of witnesses) {
      const alreadyCosignedThis = state.witnessCosigs.some(
        (cs) => cs.witness === w && cs.treeSize === cp.treeSize && cs.root === cp.root,
      );
      if (alreadyCosignedThis) continue;
      const isHonest = config.disableGuard === 'split_view' ? false : honestSet.has(w);
      const signedConflicting = state.witnessCosigs.some(
        (cs) => cs.witness === w && cs.treeSize === cp.treeSize && cs.root !== cp.root,
      );
      if (isHonest && signedConflicting) continue;
      out.push({
        action: `WitnessCosign(${w},size=${cp.treeSize},${cp.root})`,
        state: {
          ...state,
          witnessCosigs: [
            ...state.witnessCosigs,
            { witness: w, treeSize: cp.treeSize, root: cp.root },
          ],
        },
      });
    }
  }

  // 5. VerifyBundle(cid, hasReceipt, treeSize=1, root_A)
  for (const cap of state.capsules) {
    const stmt = state.statements.find((s) => s.cid === cap.cid);
    if (!stmt) continue;
    const sigGuardOk = config.disableGuard === 'unsigned' ? true : stmt.signedByTrustedIssuer;
    if (!sigGuardOk) continue;

    for (const hasReceipt of [false, true]) {
      const inLog = state.logEntries.some(
        (le) => le.cid === cap.cid && le.treeSize === 1 && le.root === 'root_A',
      );
      const inCp = state.checkpoints.some(
        (cp) => cp.treeSize === 1 && cp.root === 'root_A' && cp.logSigned,
      );
      const hasQ = quorumReached(state, 1, 'root_A', quorum, witnessSet);
      const receiptGuardOk = !hasReceipt || (inLog && inCp && hasQ);
      if (!receiptGuardOk) continue;

      const anchoredGuardOk =
        config.disableGuard === 'anchored'
          ? true
          : cap.ledgerMode !== 'anchored' || hasReceipt;
      if (!anchoredGuardOk) continue;

      const alreadyVerified = state.verifiedBundles.some(
        (vb) => vb.cid === cap.cid && vb.receiptVerified === hasReceipt,
      );
      if (alreadyVerified) continue;

      out.push({
        action: `VerifyBundle(${cap.cid},receipt=${hasReceipt},size=1,root_A)`,
        state: {
          ...state,
          verifiedBundles: [
            ...state.verifiedBundles,
            {
              cid: cap.cid,
              verdict: cap.verdict,
              effectStatus: cap.effectStatus,
              hasRespDigest: cap.hasRespDigest,
              ledgerMode: cap.ledgerMode,
              signedByTrustedIssuer: stmt.signedByTrustedIssuer,
              receiptVerified: hasReceipt,
              treeSize: 1,
              root: 'root_A',
            },
          ],
        },
      });
    }
  }

  return out;
}

/**
 * Run the bounded TypeScript check across the bounded state space via BFS and
 * evaluate all four safety invariants (`INV_NoUnsignedRegistered`,
 * `INV_AnchoredRequiresVerifiedReceipt`, `INV_NoSplitViewWithWitnessQuorum`,
 * `INV_ConfirmedEffectHasObservedDigest`).
 */
export function runFormalModelChecker(config: ModelCheckConfig = {}): ModelCheckReport {
  const initial = initProtocolState();
  const visited = new Set<string>([canonicalStateKey(initial)]);
  const queue: Array<{ state: ProtocolState; trace: string[] }> = [{ state: initial, trace: ['Init'] }];
  let exploredStates = 0;
  let exploredTransitions = 0;

  const invariantsChecked = [
    'INV_NoUnsignedRegistered',
    'INV_AnchoredRequiresVerifiedReceipt',
    'INV_NoSplitViewWithWitnessQuorum',
    'INV_ConfirmedEffectHasObservedDigest',
  ];

  while (queue.length > 0) {
    const current = queue.shift()!;
    exploredStates++;

    const inv = evaluateInvariants(current.state, config);
    if (!inv.allHold) {
      return {
        ok: false,
        exploredStates,
        exploredTransitions,
        invariantsChecked,
        ...(inv.violatedInvariant ? { violatedInvariant: inv.violatedInvariant } : {}),
        counterexampleTrace: current.trace,
      };
    }

    const nexts = nextTransitions(current.state, config);
    for (const step of nexts) {
      exploredTransitions++;
      const key = canonicalStateKey(step.state);
      if (!visited.has(key)) {
        visited.add(key);
        queue.push({ state: step.state, trace: [...current.trace, step.action] });
      }
    }
  }

  return {
    ok: true,
    exploredStates,
    exploredTransitions,
    invariantsChecked,
  };
}
