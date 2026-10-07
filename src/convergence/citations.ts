/**
 * Phase 2 citation verification (fork-local).
 *
 * The model cites evidence with whole-line markers:
 *   OBSERVED: <claim-id>@<version>   (strong form: the claim IS the fact)
 *   OBSERVED: <file>:<line>           (weak form: the pointer resolves)
 *   ASSUMED: <free text>              (always permitted, never examined)
 *
 * Only a whole line matching one of the regexes below counts as a citation, so at
 * most one citation parses per line and prose mentions ("see OBSERVED: x") are
 * inert. Claim citations check resolution, ACTIVE state, and scope against the
 * render-time fold. File citations check the pointer ONLY — existence and line
 * range. A correct pointer to a real line can still support a false conclusion;
 * Phase 2 does not catch that, which is why claim citations are the strong form
 * and file citations must never be oversold.
 */

import { readFileSync, statSync } from "node:fs";
import { isAbsolute, normalize, relative, resolve, sep } from "node:path";

import type { ConvergenceClaim } from "./loader.ts";
import { isClaimInScope } from "./scope.ts";

/** OBSERVED: <id>@<version>, with an optional Phase 3 ` [SUSPECT]` marker suffix. */
export const CLAIM_CITATION_RE =
	/^[ \t]*OBSERVED:[ \t]*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)@([1-9][0-9]*)([ \t]+\[SUSPECT\])?[ \t]*$/;

/**
 * OBSERVED: <path>:<line>; greedy take yields the last-colon split, so the parse
 * is unique per line. Tried only after the claim form (the two are disjoint: a
 * claim citation contains no colon).
 */
export const FILE_CITATION_RE = /^[ \t]*OBSERVED:[ \t]*(.+):([1-9][0-9]*)[ \t]*$/;

/** The Phase 3 marker token: one space plus `[SUSPECT]`, appended to a claim citation. */
export const SUSPECT_MARKER = " [SUSPECT]";

export type ParsedCitation =
	| { kind: "claim"; raw: string; id: string; version: number; marked: boolean }
	| { kind: "file"; raw: string; path: string; line: number };

/** At most one citation per line; anything else (including ASSUMED:) is undefined. */
export function parseCitationLine(line: string): ParsedCitation | undefined {
	const claim = CLAIM_CITATION_RE.exec(line);
	if (claim) {
		return { kind: "claim", raw: line.trim(), id: claim[1]!, version: Number(claim[2]), marked: claim[3] !== undefined };
	}
	const file = FILE_CITATION_RE.exec(line);
	if (file) return { kind: "file", raw: line.trim(), path: file[1]!, line: Number(file[2]) };
	return undefined;
}

export type CitationCheckName = "resolution" | "state" | "scope";

export interface CitationFailure {
	raw: string;
	check: CitationCheckName;
	reason: string;
}

export interface CitationStore {
	/** Render-time fold: the gate checks what the model saw, not a re-fold. */
	rows: readonly ConvergenceClaim[];
	/** Directory scope.paths entries and relative file citations resolve against. */
	projectRoot?: string;
}

/** First failures in document order, capped so the refusal stays readable. */
export const MAX_CITATION_FAILURES = 5;

function containedPath(projectRoot: string, target: string): string | undefined {
	const resolved = resolve(projectRoot, target);
	const rel = relative(projectRoot, resolved);
	if (rel === "" || rel === ".." || rel.startsWith(`..${sep}`)) return undefined;
	return resolved;
}

function checkFileCitation(path: string, line: number, projectRoot?: string): string | undefined {
	let resolved: string | undefined;
	if (isAbsolute(path)) {
		if (!projectRoot) return "no project directory to resolve the citation against";
		resolved = normalize(path);
		const rel = relative(projectRoot, resolved);
		if (rel === "" || rel === ".." || rel.startsWith(`..${sep}`)) {
			return `absolute path escapes the project (${projectRoot})`;
		}
	} else {
		if (!projectRoot) return "no project directory to resolve the citation against";
		resolved = containedPath(projectRoot, path);
		if (!resolved) return `relative path escapes the project (${projectRoot})`;
	}
	let stat: ReturnType<typeof statSync>;
	try {
		stat = statSync(resolved);
	} catch {
		return `no such file: ${path}`;
	}
	if (!stat.isFile()) return `not a file: ${path}`;
	let text: string;
	try {
		text = readFileSync(resolved, "utf8");
	} catch {
		return `unreadable file: ${path}`;
	}
	const count = text.split("\n").length;
	if (line > count) return `line ${line} is beyond the file's ${count} lines: ${path}`;
	return undefined;
}

/**
 * Provenance of the citing text, from the commit-path body comparison (kept means the
 * line is byte-identical to the rendered source). Past vs new: a `[SUSPECT]`-marked
 * citation of a SUSPECT claim is acknowledged past reasoning when kept, but relying
 * on the claim in new work when edited or added. The marker is informational in both
 * cases — the fold stays authoritative, so hand-adding or hand-stripping it changes
 * which refusal the gate gives, never an accept for a SUSPECT claim in new text.
 */
export type CitationProvenance = "kept" | "new";

export function checkCitations(lines: readonly string[], store: CitationStore, provenance: CitationProvenance = "new"): CitationFailure[] {
	const byClaim = new Map(store.rows.map((row) => [`${row.id}@${row.version}`, row]));
	const failures: CitationFailure[] = [];
	for (const line of lines) {
		if (failures.length >= MAX_CITATION_FAILURES) break;
		const citation = parseCitationLine(line);
		if (!citation) continue;
		if (citation.kind === "claim") {
			const row = byClaim.get(`${citation.id}@${citation.version}`);
			if (!row) {
				failures.push({ raw: citation.raw, check: "resolution", reason: `no claim ${citation.id}@${citation.version} in the loaded store` });
			} else if (row.state === "SUSPECT" && citation.marked && provenance === "kept") {
				continue;
			} else if (row.state !== "ACTIVE") {
				failures.push({
					raw: citation.raw,
					check: "state",
					reason: `claim ${citation.id}@${citation.version} is ${row.state}, not ACTIVE` +
						(provenance === "new" && citation.marked ? "; a [SUSPECT] marker is not authorization — do not rely on it for new work" : ""),
				});
			} else if (!isClaimInScope(row.scope, store.projectRoot)) {
				failures.push({ raw: citation.raw, check: "scope", reason: `claim ${citation.id}@${citation.version} is out of scope for this project` });
			}
			continue;
		}
		const pointer = checkFileCitation(citation.path, citation.line, store.projectRoot);
		if (pointer) failures.push({ raw: citation.raw, check: "resolution", reason: pointer });
	}
	return failures;
}

/** Project root for scope/file resolution: the tree the convergence root belongs to. */
export function projectRootFor(convergenceRoot: string): string {
	return resolve(convergenceRoot, "..");
}
