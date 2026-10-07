/**
 * Phase 4 write policy on `.convergence/` (fork-local).
 *
 * The authorized claim store is read-only to the agent. Reads are permitted (the
 * loader needs them; inspection is harmless). Any write through a visible tool call
 * is rejected at `tool.execute.before`, which OpenCode turns into the call's error
 * result. Unknown tools fail closed when they name the store (Option A, store-scoped;
 * see below) — the file-writing custom-tool bypass is closed for plain string paths,
 * not solved in general.
 *
 * Boundary rule (the whole enforcement): a raw tool path is resolved against the
 * call's working directory, `..`/`.` collapsed lexically, then symlinks in the
 * deepest existing ancestor prefix are resolved via realpath and the remainder
 * re-appended. A target is inside the store iff it equals the canonical store root
 * or lies beneath it (plus a case-folded comparison on darwin, whose filesystems
 * are usually case-insensitive). Paths resolving outside the project root are
 * evaluated by the same rule — they block only if they land inside the store.
 *
 * Bash commands are heuristic: write indicators plus target extraction (redirects,
 * `tee` operands, operands of destructive commands, `cd`-chain base tracking).
 * Lexical matching cannot see through env indirection (`$C/rules/x`) or token
 * obfuscation (`e''cho`); those are stated limits, backstopped by Phase 3's
 * mtime correlation, not by this file.
 */

import { realpathSync } from "node:fs";
import { dirname, join, normalize, resolve, sep } from "node:path";

/** Canonical store root: realpath when it exists, lexical resolution otherwise. */
export function canonicalStoreRoot(storeRoot: string): string {
	try {
		return realpathSync(storeRoot);
	} catch {
		return resolve(storeRoot);
	}
}

/**
 * Resolve a raw tool path against `cwd`, resolving symlinks in the deepest
 * existing ancestor prefix. Falls back to the lexical resolution when nothing
 * on the path exists yet (e.g. a fresh file in a fresh directory).
 */
export function resolveToolPath(cwd: string, raw: string): string {
	const abs = resolve(cwd, raw);
	const tail: string[] = [];
	let current = abs;
	for (;;) {
		try {
			const real = realpathSync(current);
			return normalize(tail.length > 0 ? join(real, ...tail) : real);
		} catch {
			const parent = dirname(current);
			if (parent === current) return abs;
			tail.unshift(current.slice(parent.length + 1));
			current = parent;
		}
	}
}

/** True when the raw path resolves into the store (or is the store root). */
export function resolvesIntoStore(cwd: string, raw: string, storeRoot: string): boolean {
	const root = canonicalStoreRoot(storeRoot);
	const target = resolveToolPath(cwd, raw);
	if (target === root || target.startsWith(root + sep)) return true;
	if (process.platform === "darwin") {
		const folded = target.toLowerCase();
		const foldedRoot = root.toLowerCase();
		if (folded === foldedRoot || folded.startsWith(foldedRoot + sep)) return true;
	}
	return false;
}

/** Write indicators for bash commands; same family as the mirror guard's list. */
const BASH_WRITE = new RegExp(
	[
		String.raw`>>?\|?`,
		String.raw`&>>?`,
		String.raw`\btee\b`,
		String.raw`\bsed\s+(?:-\S+\s+)*-i\b`,
		String.raw`\bperl\s+(?:-\S+\s+)*-i\b`,
		String.raw`\btruncate\b`,
		String.raw`\brm\b`,
		String.raw`\bmv\b`,
		String.raw`\bcp\b`,
		String.raw`\bdd\b`,
		String.raw`\binstall\b`,
		String.raw`\bln\b`,
		String.raw`\brsync\b`,
		String.raw`\bex\b`,
		String.raw`writeFile(?:Sync)?\s*\(`,
		String.raw`\bopen\s*\([^()]*["'][wax+]`,
		String.raw`\.open\(\s*["'][wax]`,
		String.raw`\bmode\s*=\s*["'][wax]`,
	].join("|"),
);

/** Redirects that never touch a store path: fd duplication and /dev/null. */
const HARMLESS_IO = /\d*>&\d+|[12&]?>>?\|?\s*\/dev\/null/g;

/** Split a command into segments on unquoted `;`, `|`, `&` and newlines. */
function splitCommands(command: string): string[] {
	const segments: string[] = [];
	let current = "";
	let quote: string | undefined;
	for (let index = 0; index < command.length; index++) {
		const char = command[index]!;
		if (quote) {
			current += char;
			if (char === quote) quote = undefined;
		} else if (char === '"' || char === "'") {
			quote = char;
			current += char;
		} else if (char === ";" || char === "|" || char === "&" || char === "\n") {
			segments.push(current);
			current = "";
		} else {
			current += char;
		}
	}
	segments.push(current);
	return segments.map((segment) => segment.trim()).filter((segment) => segment !== "");
}

/** Quote-aware whitespace split; quotes are kept on the token for later stripping. */
function splitArgs(segment: string): string[] {
	const args: string[] = [];
	let current = "";
	let quote: string | undefined;
	for (const char of segment) {
		if (quote) {
			current += char;
			if (char === quote) quote = undefined;
		} else if (char === '"' || char === "'") {
			quote = char;
			current += char;
		} else if (char === " " || char === "\t") {
			if (current !== "") args.push(current);
			current = "";
		} else {
			current += char;
		}
	}
	if (current !== "") args.push(current);
	return args;
}

function stripQuotes(token: string): string {
	if (token.length >= 2) {
		const first = token[0]!;
		const last = token[token.length - 1]!;
		if ((first === '"' && last === '"') || (first === "'" && last === "'")) return token.slice(1, -1);
	}
	return token;
}

/**
 * Candidate write targets of a bash command: redirect targets, `tee` operands,
 * `of=` for `dd`, and non-flag operands of destructive commands. Over-approximate
 * by design — every candidate is resolved against the boundary rule, and only a
 * target landing inside the store blocks.
 */
export function extractBashWriteTargets(command: string): string[] {
	const scrubbed = command.replace(HARMLESS_IO, " ");
	const targets: string[] = [];
	for (const redirect of scrubbed.matchAll(/(?:^|[\s;&|])(?:\d+)?(?:>>?\|?|&>>?)\s*(["']?)([^\s;'"|&<>]+)\1/g)) {
		if (redirect[2]) targets.push(stripQuotes(redirect[2]));
	}
	for (const segment of splitCommands(scrubbed)) {
		const args = splitArgs(segment);
		const head = stripQuotes(args[0] ?? "").split("/").pop() ?? "";
		if (head === "tee") {
			for (const operand of args.slice(1)) {
				const clean = stripQuotes(operand);
				if (clean !== "" && !clean.startsWith("-") && clean !== "-") targets.push(clean);
			}
			continue;
		}
		if (head === "dd") {
			for (const operand of args.slice(1)) {
				const clean = stripQuotes(operand);
				if (clean.startsWith("of=") && clean.length > 3) targets.push(clean.slice(3));
			}
			continue;
		}
		if (
			(head === "rm" || head === "mv" || head === "cp" || head === "mkdir" || head === "touch" ||
				head === "truncate" || head === "shred" || head === "install" || head === "ln" || head === "rsync" ||
				head === "ex" || ((head === "sed" || head === "perl") && args.some((arg) => /^-.*i/.test(stripQuotes(arg)))))
		) {
			for (const operand of args.slice(1)) {
				const clean = stripQuotes(operand);
				if (clean !== "" && !clean.startsWith("-")) targets.push(clean);
			}
		}
	}
	return targets;
}

/**
 * Working directories a command's relative targets may resolve against: the call
 * directory plus every `cd` destination in the command (last `cd` is not special —
 * all are tried, because segment order is approximate). A `cd` into the store
 * followed by a relative write is the case this exists for.
 */
export function commandBases(command: string, cwd: string): string[] {
	const bases = [cwd];
	for (const segment of splitCommands(command)) {
		const match = /^cd\s+(["']?)([^\s;'"|&]+)\1\s*$/.exec(segment.trim());
		if (match?.[2] && match[2] !== "-") bases.push(resolve(cwd, stripQuotes(match[2])));
	}
	return bases;
}

/** Lexical store mention: the absolute root or the `.convergence` directory name. */
export function mentionsStore(command: string, storeRoot: string): boolean {
	return command.includes(resolve(storeRoot)) || command.includes(".convergence");
}

function pathArg(input: Record<string, unknown>): string {
	const given = typeof input.filePath === "string" ? input.filePath : typeof input.path === "string" ? input.path : "";
	return given.replace(/^@/, "");
}

/**
 * Tools the guard classifies by schema. Anything else is unknown: a custom tool or
 * a future built-in whose argument shape the plugin cannot know.
 */
const CLASSIFIED_TOOLS = new Set(["edit", "write", "apply_patch", "bash", "read"]);

/**
 * Unknown tools known to never write (Option A known-safe set): OpenCode's
 * built-in readers. They pass even when an argument names the store. Extend this
 * set — never the deny below — when a legitimate read-only tool trips it.
 */
export const KNOWN_SAFE_READONLY = new Set(["glob", "grep"]);

/** Every string anywhere in a tool's args, nested included (custom schemas use unknown keys). */
function stringArgs(input: Record<string, unknown>): string[] {
	const out: string[] = [];
	const walk = (value: unknown): void => {
		if (typeof value === "string") {
			if (value !== "") out.push(value);
		} else if (Array.isArray(value)) {
			for (const item of value) walk(item);
		} else if (value && typeof value === "object") {
			for (const item of Object.values(value)) walk(item);
		}
	};
	walk(input);
	return out;
}

/**
 * Path-like candidates: single tokens with no whitespace. A prose sentence never
 * resolves into the store (resolve() of it lands nowhere near the root), so only
 * exact store paths fail closed. Residual: a store path containing whitespace
 * would not match — accepted, store paths have none in practice.
 */
function pathLike(candidate: string): boolean {
	return !/\s/.test(candidate);
}

/** File headers of OpenCode's `apply_patch` format. */
const PATCH_PATH = /^\s*\*\*\* (?:Add File|Update File|Delete File|Move to):\s*(.+?)\s*$/gm;

export interface ConvergenceWriteVerdict {
	tool: string;
	/** The offending target as written in the call. */
	path: string;
	/** The message the model sees (names the tool, the path, the why, the alternative). */
	message: string;
}

function verdict(tool: string, path: string, storeRoot: string): ConvergenceWriteVerdict {
	return {
		tool,
		path,
		message:
			`CLM blocked ${tool} targeting ${path}: the authorized claim store (${resolve(storeRoot)}) is read-only to the agent. ` +
			`To propose a claim, write it to a file outside .convergence/ and ask the maintainer; to challenge a claim, report it out-of-band — do not write to the store. ` +
			`If this blocked a read, split the command (absolute paths, one purpose per call) and run the reads separately.`,
	};
}

/**
 * The Phase 4 deny check: a verdict when the call writes into the store, undefined
 * otherwise. Reads (including the `read` tool and read-only bash) always pass.
 *
 * Unknown-tool policy (Option A, store-scoped): a tool outside CLASSIFIED_TOOLS
 * whose path-like string arguments resolve into the store is denied — fail closed
 * on unclassifiable-but-store-referencing calls. Tools in KNOWN_SAFE_READONLY
 * pass. An unknown tool with no store path passes through (and is touch-tracked
 * below, so the mtime tripwire still correlates it).
 *
 * Tradeoff, stated plainly: full deny-by-default (block every unknown tool) would
 * break legitimate write-capable built-ins the plugin cannot inspect (task /
 * subagents above all) and is refuted by the existing suite, which runs unknown
 * tools through `tool.execute.before` and expects them to pass. So the deny is
 * scoped to store references. What remains open: a custom tool that writes to the
 * store without naming it as a plain string (encoded path, path with whitespace,
 * spawned subprocess) bypasses the block; the tripwire is the backstop, and full
 * variable indirection blinds even that (documented in test/convergence-guard.test.ts).
 */
export function classifyConvergenceWrite(
	tool: string,
	input: Record<string, unknown>,
	cwd: string,
	storeRoot: string,
): ConvergenceWriteVerdict | undefined {
	switch (tool) {
		case "edit":
		case "write": {
			const target = pathArg(input);
			if (target !== "" && resolvesIntoStore(cwd, target, storeRoot)) return verdict(tool, target, storeRoot);
			return undefined;
		}
		case "apply_patch": {
			const patch = typeof input.patchText === "string" ? input.patchText : "";
			for (const match of patch.matchAll(PATCH_PATH)) {
				const target = (match[1] ?? "").trim();
				if (target !== "" && resolvesIntoStore(cwd, target, storeRoot)) return verdict(tool, target, storeRoot);
			}
			return undefined;
		}
		case "bash": {
			const command = typeof input.command === "string" ? input.command : "";
			if (command === "" || !BASH_WRITE.test(command)) return undefined;
			const targets = extractBashWriteTargets(command);
			const bases = commandBases(command, cwd);
			for (const target of targets) {
				for (const base of bases) {
					if (resolvesIntoStore(base, target, storeRoot)) return verdict(tool, target, storeRoot);
				}
			}
			return undefined;
		}
		case "read":
			// Reads are always permitted (the loader needs them; inspection is
			// harmless). An explicit case, so the unknown-tool deny below — which
			// also matches `read` by name when it falls through — never fires.
			return undefined;
		default: {
			for (const candidate of stringArgs(input)) {
				if (!pathLike(candidate)) continue;
				if (resolvesIntoStore(cwd, candidate, storeRoot)) {
					if (KNOWN_SAFE_READONLY.has(tool)) return undefined;
					return verdict(tool, candidate, storeRoot);
				}
			}
			return undefined;
		}
	}
}

/**
 * Any reference to the store — a resolving path on any tool, or a lexical mention
 * in bash — for Phase 3's mtime correlation. Reads count: a "read" call can hide
 * an obfuscated write the lexical check cannot see.
 */
export function touchesConvergenceStore(
	tool: string,
	input: Record<string, unknown>,
	cwd: string,
	storeRoot: string,
): boolean {
	switch (tool) {
		case "edit":
		case "write":
		case "read": {
			const target = pathArg(input);
			return target !== "" && resolvesIntoStore(cwd, target, storeRoot);
		}
		case "apply_patch": {
			const patch = typeof input.patchText === "string" ? input.patchText : "";
			for (const match of patch.matchAll(PATCH_PATH)) {
				const target = (match[1] ?? "").trim();
				if (target !== "" && resolvesIntoStore(cwd, target, storeRoot)) return true;
			}
			return false;
		}
		case "bash": {
			const command = typeof input.command === "string" ? input.command : "";
			if (command === "") return false;
			if (mentionsStore(command, storeRoot)) return true;
			const targets = extractBashWriteTargets(command);
			const bases = commandBases(command, cwd);
			return targets.some((target) => bases.some((base) => resolvesIntoStore(base, target, storeRoot)));
		}
		default: {
			// Over-approximate by design: any lexical mention counts (no pathLike
			// filter here), so an obfuscated write is still correlated by the
			// tripwire. Touches stay in memory; only blocks are logged as events.
			const strings = stringArgs(input);
			if (strings.some((text) => text.includes(".convergence") || text.includes(resolve(storeRoot)))) return true;
			return strings.some((text) => pathLike(text) && resolvesIntoStore(cwd, text, storeRoot));
		}
	}
}
