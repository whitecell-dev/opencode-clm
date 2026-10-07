/**
 * Phase 3 SUSPECT propagation (fork-local): reconcile the `[SUSPECT]` marker on claim
 * citations against the current fold.
 *
 * Mechanism is re-fold, not diff-driven rewriting: the store is already re-folded on
 * every transform (Phase 1), so marking is a pure function of (mirror text, current
 * rows) applied at render. No retained mirror text, no new fold cadence. The per-session
 * last-fold map in clm.ts exists only for transition logging and the panel — marking
 * correctness never depends on it.
 *
 * Rules per `OBSERVED: <id>@<version>` line (same parser as the gate, so the two
 * agree on what counts as a citation):
 * - fold state SUSPECT, no marker → append ` [SUSPECT]`.
 * - fold state ACTIVE, marker present → strip the marker (re-authorized).
 * - anything else (ACTIVE unmarked, unknown claim, terminal states, file citations,
 *   ASSUMED:, prose) → untouched. Unknown claims are left for the Phase 2 gate,
 *   which rejects them with a resolution failure.
 *
 * The claims body is never passed through here: it is regenerated from the fold on
 * every render (Phase 1) and its rows carry no `OBSERVED:` prefix.
 */

import type { ConvergenceClaim } from "./loader.ts";
import { parseCitationLine, SUSPECT_MARKER } from "./citations.ts";

export interface MarkerReconciliation {
	body: string;
	/** Claim keys (`id@version`) that gained the marker. */
	marked: string[];
	/** Claim keys whose marker was removed after re-authorization. */
	unmarked: string[];
}

/** Reconcile markers line-wise; returns the body unchanged when nothing applies. */
export function reconcileSuspectMarkers(body: string, rows: readonly ConvergenceClaim[]): MarkerReconciliation {
	const byClaim = new Map(rows.map((row) => [`${row.id}@${row.version}`, row]));
	const marked: string[] = [];
	const unmarked: string[] = [];
	let changed = false;
	const lines = body.split("\n").map((line) => {
		const citation = parseCitationLine(line);
		if (!citation || citation.kind !== "claim") return line;
		const key = `${citation.id}@${citation.version}`;
		const row = byClaim.get(key);
		if (!row) return line;
		if (row.state === "SUSPECT" && !citation.marked) {
			marked.push(key);
			changed = true;
			return `${line.trimEnd()}${SUSPECT_MARKER}`;
		}
		if (row.state === "ACTIVE" && citation.marked) {
			unmarked.push(key);
			changed = true;
			return line.replace(/[ \t]+\[SUSPECT\](?=[ \t]*$)/, "");
		}
		return line;
	});
	return { body: changed ? lines.join("\n") : body, marked, unmarked };
}

/** One state change between two folds, keyed by `id@version`. */
export interface ClaimTransition {
	key: string;
	from: string;
	to: string;
}

/** A transition with Phase 4's trust label (fork-local, heuristic — see below). */
export interface FlaggedTransition extends ClaimTransition {
	untrusted?: boolean;
}

/**
 * Window in which a model store-touch before the store bytes changed marks the
 * resulting transitions untrusted (Phase 4, fork-local).
 */
export const UNTRUSTED_TOUCH_WINDOW_MS = 5 * 60 * 1000;

/**
 * Phase 4 reconciliation (fork-local): label transitions whose store bytes changed
 * shortly after a model tool call touched the store. Timestamped correlation is the
 * weakest of Step 4's options and is labeled as such — a marker file is forgeable
 * by the same uid and a separate store location is unenforceable for the same
 * reason. The hook block (guard.ts) is the enforcement; this label is the tripwire.
 * Propagation never stops on an untrusted label: maintainer workflows must not
 * break on false positives (e.g. agent and maintainer touching the tree together).
 * `storeMtimeMax` undefined (loader could not fold) means no labels.
 */
export function markUntrustedTransitions(
	transitions: readonly ClaimTransition[],
	storeMtimeMax: number | undefined,
	touches: readonly number[],
): FlaggedTransition[] {
	if (storeMtimeMax === undefined) return transitions.map((transition) => ({ ...transition }));
	return transitions.map((transition) => {
		const untrusted = touches.some(
			(touch) => touch <= storeMtimeMax && storeMtimeMax - touch <= UNTRUSTED_TOUCH_WINDOW_MS,
		);
		return untrusted ? { ...transition, untrusted: true } : { ...transition };
	});
}

/**
 * Pure diff of two folds for transition logging and the panel. Only states are
 * compared; the marker pass above handles the mirror. New keys (no previous state)
 * and vanished keys (store error) are not transitions.
 */
export function diffClaimStates(
	previous: ReadonlyMap<string, string>,
	current: ReadonlyMap<string, string>,
): ClaimTransition[] {
	const transitions: ClaimTransition[] = [];
	for (const [key, to] of current) {
		const from = previous.get(key);
		if (from !== undefined && from !== to) transitions.push({ key, from, to });
	}
	return transitions.sort((left, right) => (left.key < right.key ? -1 : 1));
}
