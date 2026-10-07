/**
 * Phase 1: read-only loader for a `.convergence/` claim store.
 *
 * Ports Convergence `convergence/claims.py` (`_load_claims` + `_fold`) to TypeScript:
 * claim files under `rules/` (`rules/<id>.json` shorthand or `rules/<id>/v<version>.json`)
 * plus the ordered `transitions.jsonl` fold into a per-claim state.
 *
 * The plugin only reads. Nothing here writes to the store.
 */

import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative } from "node:path";

export type ClaimState =
	| "CANDIDATE"
	| "AUTHORIZED"
	| "ACTIVE"
	| "SUSPECT"
	| "SUPERSEDED"
	| "RETIRED"
	| "WITHDRAWN";

export interface ConvergenceClaim {
	id: string;
	version: number;
	scope: Record<string, unknown>;
	claim: string;
	evidence_refs: string[];
	state: ClaimState;
	approval_ref?: string;
}

export interface ConvergenceLoad {
	root: string;
	claims: ConvergenceClaim[];
	/** sha256 over the sorted rule bytes plus the transitions bytes; for per-request change audit. */
	digest: string;
	/** Set when the store exists but is unusable; claims is then empty. */
	error?: string;
	/**
	 * Phase 3: latest valid CHALLENGE `counterevidence_ref` per `id@version` — the
	 * cause shown when a claim goes SUSPECT. Last valid challenge wins.
	 */
	causes: Record<string, string>;
	/**
	 * Phase 4: newest mtime (ms) over transitions.jsonl and the rule files read,
	 * for correlating store changes with model tool calls. Absent when the store
	 * is unusable.
	 */
	mtimeMax?: number;
}

const CLAIM_FIELDS = ["id", "version", "scope", "claim", "evidence_refs"] as const;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const TRANSITIONS = ["CANDIDATE", "AUTHORIZED", "ACTIVE", "CHALLENGE", "SUPERSEDED", "RETIRED", "WITHDRAWN"] as const;

type Raw = Record<string, unknown>;

function isRecord(value: unknown): value is Raw {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function ruleError(rule: unknown): string | undefined {
	if (!isRecord(rule) || Object.keys(rule).length !== CLAIM_FIELDS.length || !CLAIM_FIELDS.every((field) => field in rule)) {
		return "claim needs exactly id, version, scope, claim, evidence_refs";
	}
	if (typeof rule.id !== "string" || !ID_RE.test(rule.id)) return "invalid claim id";
	if (typeof rule.version !== "number" || !Number.isInteger(rule.version) || rule.version < 1) {
		return "version must be a positive integer";
	}
	if (!isRecord(rule.scope)) return "scope must be an object";
	if (typeof rule.claim !== "string" || !rule.claim.trim()) return "claim must be nonblank text";
	if (!Array.isArray(rule.evidence_refs) || !rule.evidence_refs.every((ref) => typeof ref === "string" && ref.trim())) {
		return "evidence_refs must be a list of nonblank strings";
	}
	return undefined;
}

async function ruleFiles(rulesDir: string): Promise<string[]> {
	const found: string[] = [];
	const walk = async (dir: string): Promise<void> => {
		for (const entry of await readdir(dir, { withFileTypes: true })) {
			const path = join(dir, entry.name);
			if (entry.isDirectory()) await walk(path);
			else if (entry.isFile() && entry.name.endsWith(".json")) found.push(path);
		}
	};
	await walk(rulesDir);
	return found.sort();
}

function expectedPath(root: string, id: string, version: number, flat: boolean): string {
	return flat ? join(root, "rules", `${id}.json`) : join(root, "rules", id, `v${version}.json`);
}

function fold(
	claims: Map<string, Raw>,
	transitions: Raw[],
	errors: string[],
): { states: Map<string, ClaimState>; approvals: Map<string, string>; causes: Map<string, string> } {
	const states = new Map<string, ClaimState>();
	const approvals = new Map<string, string>();
	const causes = new Map<string, string>();
	const pending = new Map<string, Set<string>>();
	const versions = new Map<string, number>();
	for (const key of [...claims.keys()].sort()) {
		const version = Number(key.split("@")[1]);
		if (version !== (versions.get(key.split("@")[0]!) ?? 0) + 1) {
			errors.push(`${key}: versions must start at 1 and advance by one`);
		}
		versions.set(key.split("@")[0]!, version);
	}
	transitions.forEach((event, index) => {
		const label = `transitions.jsonl:${index + 1}`;
		if (!isRecord(event) || typeof event.event !== "string" || !(TRANSITIONS as readonly string[]).includes(event.event)) {
			errors.push(`${label}: unknown transition event`);
			return;
		}
		const kind = event.event as string;
		const id = event.id;
		const version = event.version;
		if (typeof id !== "string" || typeof version !== "number" || !Number.isInteger(version)) {
			errors.push(`${label}: invalid transition fields`);
			return;
		}
		const key = `${id}@${version}`;
		if (!claims.has(key)) {
			errors.push(`${label}: unknown claim version`);
			return;
		}
		const previous = states.get(key) ?? "CANDIDATE";
		let valid = false;
		let state: ClaimState = "CANDIDATE";
		if (kind === "CANDIDATE") {
			valid = !states.has(key);
			state = "CANDIDATE";
		} else if (kind === "AUTHORIZED") {
			const ref = event.approval_ref;
			valid = (previous === "CANDIDATE" || previous === "SUSPECT") && typeof ref === "string" && !!ref.trim();
			if (previous === "SUSPECT") {
				const resolves = event.resolves;
				const open = pending.get(key) ?? new Set();
				valid =
					valid &&
					Array.isArray(resolves) &&
					resolves.every((entry) => typeof entry === "string") &&
					resolves.length === open.size &&
					resolves.every((entry) => open.has(entry as string));
			} else {
				valid = valid && !("resolves" in event);
			}
			state = "AUTHORIZED";
			if (valid) {
				approvals.set(key, (event.approval_ref as string).trim());
				pending.set(key, new Set());
			}
		} else if (kind === "ACTIVE") {
			valid = previous === "AUTHORIZED";
			state = "ACTIVE";
		} else if (kind === "CHALLENGE") {
			const ref = event.counterevidence_ref;
			const open = pending.get(key) ?? new Set();
			valid =
				(previous === "ACTIVE" || previous === "SUSPECT") && typeof ref === "string" && !!ref.trim() && !open.has(ref);
			state = "SUSPECT";
			if (valid) {
				open.add(ref as string);
				pending.set(key, open);
				causes.set(key, (ref as string).trim());
			}
		} else if (kind === "SUPERSEDED") {
			const next = event.superseded_by;
			valid =
				(previous === "AUTHORIZED" || previous === "ACTIVE" || previous === "SUSPECT") &&
				typeof next === "number" &&
				next === version + 1 &&
				claims.has(`${id}@${next}`);
			state = "SUPERSEDED";
		} else if (kind === "RETIRED") {
			valid = previous === "AUTHORIZED" || previous === "ACTIVE" || previous === "SUSPECT";
			state = "RETIRED";
		} else {
			valid = previous === "CANDIDATE";
			state = "WITHDRAWN";
		}
		let blocker: string | undefined;
		if (valid && (state === "AUTHORIZED" || state === "ACTIVE" || state === "SUSPECT")) {
			blocker = [...states.entries()].find(
				([other, otherState]) =>
					other.split("@")[0] === id &&
					other !== key &&
					(otherState === "AUTHORIZED" || otherState === "ACTIVE" || otherState === "SUSPECT"),
			)?.[0];
			valid = blocker === undefined;
		}
		if (valid) states.set(key, state);
		else errors.push(`${label}: incoherent lifecycle transition ${kind} ${key} from ${previous}${blocker ? `; ${blocker} still holds authority` : ""}`);
	});
	return { states, approvals, causes };
}

/**
 * Load and fold the store at `dir`. Undefined when disabled (`dir` unset) or when no
 * store exists there (backwards compatible: no claims section). A store that exists but
 * is unusable returns an empty claim list with `error` set, so the mirror can show the
 * failure instead of silently dropping authority.
 */
export async function loadConvergenceStore(dir: string | undefined): Promise<ConvergenceLoad | undefined> {
	if (!dir) return undefined;
	const rulesDir = join(dir, "rules");
	const transitionsPath = join(dir, "transitions.jsonl");
	const rulesMissing = await stat(rulesDir)
		.then((info) => !info.isDirectory())
		.catch(() => true);
	const transitionsMissing = await stat(transitionsPath)
		.then((info) => !info.isFile())
		.catch(() => true);
	if (rulesMissing && transitionsMissing) return undefined;
	const errors: string[] = [];
	if (rulesMissing) errors.push("missing protocol path: rules");
	if (transitionsMissing) errors.push("missing protocol path: transitions.jsonl");
	let mtimeMax: number | undefined;
	const noteMtime = (ms: number | undefined) => {
		if (typeof ms === "number" && (mtimeMax === undefined || ms > mtimeMax)) mtimeMax = ms;
	};
	const claims = new Map<string, Raw>();
	const hash = createHash("sha256");
	if (!rulesMissing) {
		let files: string[] = [];
		try {
			files = await ruleFiles(rulesDir);
		} catch (error) {
			errors.push(`rules: ${error instanceof Error ? error.message : String(error)}`);
		}
		for (const path of files) {
			try {
				noteMtime((await stat(path)).mtimeMs);
				const raw = JSON.parse(await readFile(path, "utf8")) as unknown;
				const problem = ruleError(raw);
				if (problem) throw new Error(problem);
				const rule = raw as Raw;
				const flat = join(dir, "rules") === join(path, "..");
				if (path !== expectedPath(dir, rule.id as string, rule.version as number, flat)) {
					throw new Error("claim id/version differs from path");
				}
				const key = `${rule.id}@${rule.version}`;
				if (claims.has(key)) throw new Error("duplicate claim version");
				claims.set(key, rule);
				hash.update(`${relative(dir, path)}\0${await readFile(path)}\0`);
			} catch (error) {
				errors.push(`${relative(dir, path)}: ${error instanceof Error ? error.message : String(error)}`);
			}
		}
	}
	let transitions: Raw[] = [];
	if (!transitionsMissing) {
		try {
			noteMtime((await stat(transitionsPath)).mtimeMs);
			const bytes = await readFile(transitionsPath);
			hash.update(`transitions.jsonl\0${bytes}\0`);
			transitions = bytes
				.toString("utf8")
				.split("\n")
				.filter((line) => line.trim() !== "")
				.map((line, index) => {
					try {
						return JSON.parse(line) as Raw;
					} catch {
						throw new Error(`transitions.jsonl:${index + 1}: invalid JSON`);
					}
				});
		} catch (error) {
			errors.push(error instanceof Error ? error.message : String(error));
		}
	}
	const { states, approvals, causes } = fold(claims, transitions, errors);
	const digest = hash.digest("hex");
	if (errors.length > 0) return { root: dir, claims: [], digest, error: errors.join("; "), causes: {} };
	const rows: ConvergenceClaim[] = [...claims.entries()]
		.sort(([left], [right]) => (left < right ? -1 : 1))
		.map(([key, rule]) => ({
			id: rule.id as string,
			version: rule.version as number,
			scope: rule.scope as Record<string, unknown>,
			claim: rule.claim as string,
			evidence_refs: rule.evidence_refs as string[],
			state: states.get(key) ?? "CANDIDATE",
			...(approvals.has(key) ? { approval_ref: approvals.get(key)! } : {}),
		}));
	return { root: dir, claims: rows, digest, causes: Object.fromEntries(causes), ...(mtimeMax !== undefined ? { mtimeMax } : {}) };
}
