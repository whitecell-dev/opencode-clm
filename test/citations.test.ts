// Phase 2 citation verification (fork-local): OBSERVED:/ASSUMED: gate.
import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { applyContextDocument, renderContextDocument } from "../src/context-document.ts";
import { parseCitationLine } from "../src/convergence/citations.ts";
import { loadConvergenceStore } from "../src/convergence/loader.ts";
import { renderClaimsBody } from "../src/convergence/render.ts";
import { selectActiveClaims } from "../src/convergence/scope.ts";
import type { ApplyDocumentOptions, ContextDocumentSnapshot, LiveContextMessage } from "../src/types.ts";

function messages(): LiveContextMessage[] {
	return [
		{ role: "user", content: "Do the thing.", timestamp: 1 },
		{ role: "assistant", content: [{ type: "text", text: "Doing it." }], stopReason: "stop", timestamp: 2 },
	];
}

function rule(id: string, version: number, scope: Record<string, unknown> = {}) {
	return { id, version, scope, claim: `Claim ${id}.`, evidence_refs: ["evidence/notes.md"] };
}

interface Fixture {
	snapshot: ContextDocumentSnapshot;
	options: ApplyDocumentOptions;
}

async function fixture(): Promise<Fixture> {
	const proj = mkdtempSync(join(tmpdir(), "clm-cite-"));
	mkdirSync(join(proj, ".convergence", "rules"), { recursive: true });
	mkdirSync(join(proj, "sub"), { recursive: true });
	writeFileSync(join(proj, "notes.txt"), "alpha\nbeta\ngamma\n");
	const rules: Array<[string, unknown]> = [
		["good.json", rule("good", 1)],
		["scoped.json", rule("scoped", 1, { paths: ["sub/"] })],
		["outer.json", rule("outer", 1, { paths: ["elsewhere/"] })],
		["suspect.json", rule("suspect", 1)],
	];
	for (const [name, body] of rules) {
		writeFileSync(join(proj, ".convergence", "rules", name), JSON.stringify(body));
	}
	const lines: Array<Record<string, unknown>> = [];
	for (const id of ["good", "scoped", "outer", "suspect"]) {
		lines.push({ event: "CANDIDATE", id, version: 1 });
		lines.push({ event: "AUTHORIZED", id, version: 1, approval_ref: "human:br" });
		lines.push({ event: "ACTIVE", id, version: 1 });
	}
	lines.push({ event: "CHALLENGE", id: "suspect", version: 1, counterevidence_ref: "evidence/bug.md" });
	writeFileSync(join(proj, ".convergence", "transitions.jsonl"), lines.map((line) => JSON.stringify(line)).join("\n") + "\n");

	const root = join(proj, ".convergence");
	const store = await loadConvergenceStore(root);
	expect(store?.error).toBeUndefined();
	const rows = store?.claims ?? [];
	const snapshot = renderContextDocument(messages(), {
		revision: 0,
		documentSeed: "cite-seed",
		claimsBody: renderClaimsBody(selectActiveClaims(rows)),
		claimsMeta: { rows, root },
	});
	return { snapshot, options: { editingMode: "clm", projectDir: proj } };
}

/** Appending text extends the last block's body; headers are untouched. */
function cite(fixture: Fixture, line: string): string {
	return `${fixture.snapshot.text}\n${line}\n`;
}

describe("citation line parsing", () => {
	test("whole-line forms parse; prose mentions and ASSUMED: do not", () => {
		expect(parseCitationLine("OBSERVED: good@1")).toMatchObject({ kind: "claim", id: "good", version: 1 });
		expect(parseCitationLine("  OBSERVED: notes.txt:12  ")).toMatchObject({ kind: "file", path: "notes.txt", line: 12 });
		expect(parseCitationLine("(see OBSERVED: good@1)")).toBeUndefined();
		expect(parseCitationLine("OBSERVED: good@1 and OBSERVED: scoped@1")).toBeUndefined();
		expect(parseCitationLine("ASSUMED: the cache helps")).toBeUndefined();
		expect(parseCitationLine("Doing it.")).toBeUndefined();
	});
});

describe("claim citations", () => {
	test("valid citation (resolves, ACTIVE, in scope) is accepted", async () => {
		const fix = await fixture();
		for (const line of ["OBSERVED: good@1", "OBSERVED: scoped@1"]) {
			const result = applyContextDocument(cite(fix, line), fix.snapshot, fix.options);
			expect(result.accepted).toBe(true);
		}
	});

	test("nonexistent claim is rejected with a resolution failure", async () => {
		const fix = await fixture();
		const result = applyContextDocument(cite(fix, "OBSERVED: missing@1"), fix.snapshot, fix.options);
		expect(result.accepted).toBe(false);
		expect(result.reason).toMatch(/resolution/);
		expect(result.reason).toMatch(/missing@1/);
		expect(result.reason).toMatch(/ASSUMED/);
	});

	test("SUSPECT claim is rejected with a state failure", async () => {
		const fix = await fixture();
		const result = applyContextDocument(cite(fix, "OBSERVED: suspect@1"), fix.snapshot, fix.options);
		expect(result.accepted).toBe(false);
		expect(result.reason).toMatch(/state/);
		expect(result.reason).toMatch(/SUSPECT/);
	});

	test("ACTIVE claim out of scope is rejected with a scope failure", async () => {
		const fix = await fixture();
		const result = applyContextDocument(cite(fix, "OBSERVED: outer@1"), fix.snapshot, fix.options);
		expect(result.accepted).toBe(false);
		expect(result.reason).toMatch(/scope/);
	});

	test("claim citation with no store loaded fails resolution", async () => {
		const snapshot = renderContextDocument(messages(), { revision: 0, documentSeed: "cite-nostore" });
		const options: ApplyDocumentOptions = { editingMode: "clm", projectDir: tmpdir() };
		const result = applyContextDocument(`${snapshot.text}\nOBSERVED: good@1\n`, snapshot, options);
		expect(result.accepted).toBe(false);
		expect(result.reason).toMatch(/resolution/);
	});
});

describe("file citations", () => {
	test("resolving pointer is accepted", async () => {
		const fix = await fixture();
		const result = applyContextDocument(cite(fix, "OBSERVED: notes.txt:2"), fix.snapshot, fix.options);
		expect(result.accepted).toBe(true);
	});

	test("missing file is rejected", async () => {
		const fix = await fixture();
		const result = applyContextDocument(cite(fix, "OBSERVED: absent.txt:1"), fix.snapshot, fix.options);
		expect(result.accepted).toBe(false);
		expect(result.reason).toMatch(/resolution/);
		expect(result.reason).toMatch(/no such file/);
	});

	test("line beyond the file length is rejected", async () => {
		const fix = await fixture();
		const result = applyContextDocument(cite(fix, "OBSERVED: notes.txt:99"), fix.snapshot, fix.options);
		expect(result.accepted).toBe(false);
		expect(result.reason).toMatch(/resolution/);
		expect(result.reason).toMatch(/beyond/);
	});

	test("directory target is rejected", async () => {
		const fix = await fixture();
		const result = applyContextDocument(cite(fix, "OBSERVED: sub:1"), fix.snapshot, fix.options);
		expect(result.accepted).toBe(false);
		expect(result.reason).toMatch(/not a file/);
	});
});

describe("gate behavior", () => {
	test("ASSUMED: lines are always accepted", async () => {
		const fix = await fixture();
		const result = applyContextDocument(cite(fix, "ASSUMED: the cache probably helps here"), fix.snapshot, fix.options);
		expect(result.accepted).toBe(true);
	});

	test("one failure rejects a mix of valid and invalid citations", async () => {
		const fix = await fixture();
		const text = `${fix.snapshot.text}\nOBSERVED: good@1\nOBSERVED: missing@2\n`;
		const result = applyContextDocument(text, fix.snapshot, fix.options);
		expect(result.accepted).toBe(false);
		expect(result.reason).toMatch(/missing@2/);
	});

	test("prose mentions of citations are inert", async () => {
		const fix = await fixture();
		const result = applyContextDocument(cite(fix, "As shown (see OBSERVED: missing@1), we proceed."), fix.snapshot, fix.options);
		expect(result.accepted).toBe(true);
	});

	test("self-validation: identical edit accepted without, rejected with, a bogus citation", async () => {
		const fix = await fixture();
		const base = `${fix.snapshot.text}\nOBSERVED: good@1\n`;
		const good = applyContextDocument(base, fix.snapshot, fix.options);
		expect(good.accepted).toBe(true);
		const bad = applyContextDocument(`${base}OBSERVED: missing@9\n`, fix.snapshot, fix.options);
		expect(bad.accepted).toBe(false);
		expect(good.accepted).not.toBe(bad.accepted);
	});
});
