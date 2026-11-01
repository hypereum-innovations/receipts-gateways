// SPDX-License-Identifier: Apache-2.0
/**
 * Causal Trace DAG (`TraceDag` & `analyzeTraceDag`).
 *
 * Reconstructs and audits the multi-agent causal execution graph across
 * capsules from `capsule_id`, `prev_capsule_hash`, `parent_capsule_hashes`,
 * `causality.parent_capsule_ids`, `intent_capsule_id`, `outcome_capsule_id`,
 * and `cross_org_refs`.
 *
 * Verifies:
 *  - Acyclicity (`has_cycles`, `cycle_nodes`)
 *  - Referential integrity (`orphan_references` / `orphan_refs` for missing parent/intent hashes)
 *  - 3-Phase pairing (`unclosed_intents` for `intent` without `outcome`,
 *    `unpaired_outcomes` for `outcome` without matching `intent`)
 *  - Deterministic topological ordering (`topological_order`)
 *  - Critical path (`critical_path`, `critical_path_length`)
 *  - Cross-organization boundary links (`cross_org_edges`)
 */
import type { Capsule, CrossOrgRef, Digest } from './capsule.js';

export type CausalEdgeKind =
  | 'prev_capsule_hash'
  | 'parent_capsule_hash'
  | 'intent_capsule_id'
  | 'outcome_capsule_id';

export interface CausalEdge {
  /** Parent / predecessor capsule ID (earlier in causal time). */
  from: Digest;
  /** Child / successor capsule ID (later in causal time, depends on `from`). */
  to: Digest;
  kind: CausalEdgeKind;
}

export interface OrphanReference {
  /** Capsule that holds the dangling reference. */
  capsule_id: Digest;
  from_capsule_id: Digest;
  /** Missing referenced capsule digest/ID. */
  missing_target_id: Digest;
  target_id: Digest;
  kind: CausalEdgeKind;
}

export interface CrossOrgBoundaryEdge extends CrossOrgRef {
  from_capsule_id: Digest;
  capsule_id: Digest;
}

export interface TraceDagNode {
  capsule: Capsule;
  capsule_id: Digest;
  parents: Digest[];
  children: Digest[];
  cross_org_refs: CrossOrgRef[];
}

export interface TraceDagAnalysis {
  node_count: number;
  edge_count: number;
  has_cycles: boolean;
  cycle_nodes: Digest[];
  roots: Digest[];
  leaves: Digest[];
  topological_order: Digest[];
  topological_sort: Digest[];
  critical_path: Digest[];
  critical_path_length: number;
  orphan_references: OrphanReference[];
  orphan_refs: OrphanReference[];
  orphan_capsule_ids: Digest[];
  unclosed_intents: Digest[];
  unpaired_outcomes: Digest[];
  confirmations: Digest[];
  cross_org_edges: CrossOrgBoundaryEdge[];
  cross_org_boundary_edges: CrossOrgBoundaryEdge[];
  edges: CausalEdge[];
}

export class TraceDag {
  private readonly capsules = new Map<Digest, Capsule>();
  private readonly insertionOrder: Digest[] = [];

  constructor(initialCapsules: Capsule[] = []) {
    for (const c of initialCapsules) {
      this.addCapsule(c);
    }
  }

  addCapsule(capsule: Capsule): void {
    if (!this.capsules.has(capsule.capsule_id)) {
      this.insertionOrder.push(capsule.capsule_id);
    }
    this.capsules.set(capsule.capsule_id, capsule);
  }

  size(): number {
    return this.capsules.size;
  }

  getCapsule(capsuleId: Digest): Capsule | undefined {
    return this.capsules.get(capsuleId);
  }

  private collectRawReferences(capsule: Capsule): Array<{ parentId: Digest; kind: CausalEdgeKind }> {
    const refs: Array<{ parentId: Digest; kind: CausalEdgeKind }> = [];
    const seen = new Set<string>();
    const add = (parentId: string | undefined, kind: CausalEdgeKind) => {
      if (!parentId) return;
      const key = `${parentId}:${kind}`;
      if (seen.has(key)) return;
      seen.add(key);
      refs.push({ parentId, kind });
    };

    add(capsule.prev_capsule_hash, 'prev_capsule_hash');
    add(capsule.intent_capsule_id, 'intent_capsule_id');
    add(capsule.outcome_capsule_id, 'outcome_capsule_id');
    for (const p of capsule.parent_capsule_hashes ?? []) {
      add(p, 'parent_capsule_hash');
    }
    for (const p of capsule.causality?.parent_capsule_ids ?? []) {
      add(p, 'parent_capsule_hash');
    }
    return refs;
  }

  getParents(capsuleId: Digest): Digest[] {
    const c = this.capsules.get(capsuleId);
    if (!c) return [];
    const parents = new Set<Digest>();
    for (const ref of this.collectRawReferences(c)) {
      if (this.capsules.has(ref.parentId)) {
        parents.add(ref.parentId);
      }
    }
    return [...parents];
  }

  getChildren(capsuleId: Digest): Digest[] {
    const children: Digest[] = [];
    for (const id of this.insertionOrder) {
      const parents = this.getParents(id);
      if (parents.includes(capsuleId)) {
        children.push(id);
      }
    }
    return children;
  }

  getNode(capsuleId: Digest): TraceDagNode | undefined {
    const c = this.capsules.get(capsuleId);
    if (!c) return undefined;
    return {
      capsule: c,
      capsule_id: c.capsule_id,
      parents: this.getParents(capsuleId),
      children: this.getChildren(capsuleId),
      cross_org_refs: c.cross_org_refs ?? [],
    };
  }

  getAncestors(capsuleId: Digest): Digest[] {
    const visited = new Set<Digest>();
    const queue = [...this.getParents(capsuleId)];
    while (queue.length > 0) {
      const curr = queue.shift()!;
      if (visited.has(curr)) continue;
      visited.add(curr);
      for (const p of this.getParents(curr)) {
        if (!visited.has(p)) queue.push(p);
      }
    }
    return [...visited];
  }

  getDescendants(capsuleId: Digest): Digest[] {
    const visited = new Set<Digest>();
    const queue = [...this.getChildren(capsuleId)];
    while (queue.length > 0) {
      const curr = queue.shift()!;
      if (visited.has(curr)) continue;
      visited.add(curr);
      for (const ch of this.getChildren(curr)) {
        if (!visited.has(ch)) queue.push(ch);
      }
    }
    return [...visited];
  }

  topologicalSort(): { order: Digest[]; has_cycles: boolean; cycle_nodes: Digest[] } {
    const inDegree = new Map<Digest, number>();
    const adj = new Map<Digest, Digest[]>();

    for (const id of this.insertionOrder) {
      inDegree.set(id, 0);
      adj.set(id, []);
    }

    for (const id of this.insertionOrder) {
      const parents = this.getParents(id);
      inDegree.set(id, parents.length);
      for (const p of parents) {
        adj.get(p)!.push(id);
      }
    }

    const ready: Digest[] = [];
    for (const id of this.insertionOrder) {
      if ((inDegree.get(id) ?? 0) === 0) {
        ready.push(id);
      }
    }

    const order: Digest[] = [];
    while (ready.length > 0) {
      const curr = ready.shift()!;
      order.push(curr);
      for (const child of adj.get(curr) ?? []) {
        const nextDeg = (inDegree.get(child) ?? 1) - 1;
        inDegree.set(child, nextDeg);
        if (nextDeg === 0) {
          ready.push(child);
        }
      }
    }

    const cycle_nodes = this.insertionOrder.filter((id) => !order.includes(id));
    return {
      order,
      has_cycles: cycle_nodes.length > 0,
      cycle_nodes,
    };
  }

  criticalPath(): Digest[] {
    const { order } = this.topologicalSort();
    if (order.length === 0) return [];

    const dist = new Map<Digest, number>();
    const prev = new Map<Digest, Digest | null>();

    for (const id of order) {
      dist.set(id, 1);
      prev.set(id, null);
    }

    for (const id of order) {
      const d = dist.get(id) ?? 1;
      for (const child of this.getChildren(id)) {
        if (!dist.has(child)) continue;
        const cand = d + 1;
        if (cand > (dist.get(child) ?? 0)) {
          dist.set(child, cand);
          prev.set(child, id);
        }
      }
    }

    let bestEnd: Digest = order[0]!;
    let bestLen = 0;
    for (const id of order) {
      const d = dist.get(id) ?? 0;
      if (d > bestLen) {
        bestLen = d;
        bestEnd = id;
      }
    }

    const path: Digest[] = [];
    let curr: Digest | null = bestEnd;
    while (curr !== null) {
      path.unshift(curr);
      curr = prev.get(curr) ?? null;
    }
    return path;
  }

  analyze(): TraceDagAnalysis {
    const edges: CausalEdge[] = [];
    const orphan_references: OrphanReference[] = [];
    const orphanIdsSet = new Set<Digest>();
    const cross_org_edges: CrossOrgBoundaryEdge[] = [];
    const intentIds = new Set<Digest>();
    const closedIntents = new Set<Digest>();
    const unpaired_outcomes: Digest[] = [];
    const confirmations: Digest[] = [];

    for (const id of this.insertionOrder) {
      const c = this.capsules.get(id)!;
      if (c.phase === 'intent') {
        intentIds.add(id);
      }
      if (c.phase === 'confirmation') {
        confirmations.push(id);
      }
      for (const ref of c.cross_org_refs ?? []) {
        cross_org_edges.push({
          from_capsule_id: id,
          capsule_id: id,
          origin: ref.origin,
          leaf_index: ref.leaf_index,
          statement_digest: ref.statement_digest,
        });
      }

      const rawRefs = this.collectRawReferences(c);
      const seenParentEdge = new Set<Digest>();
      for (const ref of rawRefs) {
        if (this.capsules.has(ref.parentId)) {
          if (!seenParentEdge.has(ref.parentId)) {
            seenParentEdge.add(ref.parentId);
            edges.push({ from: ref.parentId, to: id, kind: ref.kind });
          }
        } else {
          orphan_references.push({
            capsule_id: id,
            from_capsule_id: id,
            missing_target_id: ref.parentId,
            target_id: ref.parentId,
            kind: ref.kind,
          });
          orphanIdsSet.add(ref.parentId);
        }
      }
    }

    // Evaluate 3-phase intent <-> outcome pairing
    for (const id of this.insertionOrder) {
      const c = this.capsules.get(id)!;
      if (c.phase === 'outcome') {
        const targetIntentId = c.intent_capsule_id;
        if (!targetIntentId) {
          unpaired_outcomes.push(id);
        } else {
          const targetCapsule = this.capsules.get(targetIntentId);
          if (!targetCapsule || (targetCapsule.phase !== undefined && targetCapsule.phase !== 'intent')) {
            unpaired_outcomes.push(id);
          } else {
            closedIntents.add(targetIntentId);
          }
        }
      }
    }

    const unclosed_intents = [...intentIds].filter((id) => !closedIntents.has(id));
    const { order: topological_order, has_cycles, cycle_nodes } = this.topologicalSort();
    const critical_path = this.criticalPath();

    const roots = this.insertionOrder.filter((id) => this.getParents(id).length === 0);
    const leaves = this.insertionOrder.filter((id) => this.getChildren(id).length === 0);

    return {
      node_count: this.capsules.size,
      edge_count: edges.length,
      has_cycles,
      cycle_nodes,
      roots,
      leaves,
      topological_order,
      topological_sort: topological_order,
      critical_path,
      critical_path_length: critical_path.length,
      orphan_references,
      orphan_refs: orphan_references,
      orphan_capsule_ids: [...orphanIdsSet],
      unclosed_intents,
      unpaired_outcomes,
      confirmations,
      cross_org_edges,
      cross_org_boundary_edges: cross_org_edges,
      edges,
    };
  }
}

export function analyzeTraceDag(capsules: Capsule[]): TraceDagAnalysis {
  return new TraceDag(capsules).analyze();
}
