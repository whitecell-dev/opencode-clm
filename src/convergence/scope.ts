/**
 * Fork-local scope policy, Phase 1.
 *
 * SCOPE_POLICY: inject every ACTIVE claim; each claim's scope is rendered verbatim for
 * the model to read. The plugin does no scope filtering in Phase 1. Scope matching
 * becomes enforced at citation verification (Phase 2), where a claim citation must
 * resolve to a claim whose scope covers the citing work.
 *
 * This is deliberately fork-local, not protocol: the protocol owns the claim shape and
 * the lifecycle states; which scopes a consumer admits is the consumer's policy. A
 * paths-prefix or exact-subset matcher can replace `selectActiveClaims` without touching
 * the loader or the mirror format.
 */

import { statSync } from "node:fs";
import { normalize, relative, sep } from "node:path";

import type { ConvergenceClaim } from "./loader.ts";

export const SCOPE_POLICY =
	"Phase-1 fork-local policy: inject every ACTIVE claim regardless of scope; scope is advisory text for the model. Enforcement moves to citation verification in Phase 2.";

/**
 * Fork-local scope-match rule, Phase 2 (enforced at citation verification).
 *
 * SCOPE_MATCH_RULE: a claim is in scope for a project rooted at `projectRoot` iff
 * every entry of its `scope.paths` list names a location inside that project that
 * exists on disk (file or directory). An empty scope `{}` always matches. Other
 * scope keys are ignored. A missing `projectRoot` matches only the empty scope.
 *
 * Rationale: the scope declares the world the claim speaks about; a citation is
 * valid only when that world is wholly this project. One rule, implemented here,
 * used only by the citation gate — injection still admits every ACTIVE claim.
 */
export const SCOPE_MATCH_RULE =
	"Phase-2 fork-local rule: scope {} matches; otherwise every scope.paths entry must be a project-relative path that stays inside the project root and exists on disk.";

function isInsideRoot(root: string, entry: string): boolean {
	if (typeof entry !== "string" || entry.length === 0 || entry.startsWith("/")) return false;
	const normalized = normalize(entry);
	if (normalized === ".." || normalized.startsWith(`..${sep}`)) return false;
	const rel = relative(root, `${root}${sep}${normalized}`);
	return rel !== ".." && !rel.startsWith(`..${sep}`) && !rel.startsWith(sep) && rel !== "";
}

/** Deterministic scope match used only by the Phase 2 citation gate. */
export function isClaimInScope(scope: ConvergenceClaim["scope"], projectRoot?: string): boolean {
	const keys = Object.keys(scope);
	if (keys.length === 0) return true;
	const paths = (scope as { paths?: unknown }).paths;
	if (!Array.isArray(paths) || paths.length === 0) return true;
	if (!projectRoot) return false;
	return paths.every((entry) => {
		if (!isInsideRoot(projectRoot, entry)) return false;
		try {
			statSync(`${projectRoot}${sep}${normalize(entry as string)}`);
			return true;
		} catch {
			return false;
		}
	});
}

/** Every ACTIVE claim, ordered by id then version. */
export function selectActiveClaims(claims: readonly ConvergenceClaim[]): ConvergenceClaim[] {
	return claims
		.filter((claim) => claim.state === "ACTIVE")
		.sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : left.version - right.version));
}
