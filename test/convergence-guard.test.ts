// Phase 4 verification (fork-local): the `.convergence/` write guard, the mtime
// tripwire, the loader-path closures, the lexical bypasses, and the unknown-tool
// policy. Pure classifier tests use a real temp project (symlink and `..` cases
// need the filesystem); the hook and tripwire tests drive the plugin and session.
import { describe, expect, test } from "bun:test";
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { PluginInput } from "@opencode-ai/plugin";

import { server } from "../index.ts";
import { ClmSession } from "../src/clm.ts";
import {
	classifyConvergenceWrite,
	KNOWN_SAFE_READONLY,
	resolvesIntoStore,
	touchesConvergenceStore,
} from "../src/convergence/guard.ts";
import { loadConvergenceStore } from "../src/convergence/loader.ts";
import { markUntrustedTransitions, UNTRUSTED_TOUCH_WINDOW_MS } from "../src/convergence/suspect.ts";
import { changeSetting } from "../src/overrides.ts";
import { sanitizeOverrides, SETTING_NAMES, settingDescriptor } from "../src/settings-table.ts";
import { assistant, conversation, SESSION, settings, tempDir, user } from "./fixtures.ts";

let linkCounter = 0;

/** A real project with a real store: `<root>/.convergence/rules/a.json`. */
function project(): { root: string; store: string } {
	const root = mkdtempSync(join(tmpdir(), "clm-conv-guard-"));
	const store = join(root, ".convergence");
	mkdirSync(join(store, "rules"), { recursive: true });
	writeFileSync(join(store, "rules", "a.json"), "{}");
	return { root, store };
}

const deny = (tool: string, input: Record<string, unknown>, cwd: string, store: string) =>
	classifyConvergenceWrite(tool, input, cwd, store);

describe("boundary rule", () => {
	test("a `..` path that resolves into the store is blocked", () => {
		const { root, store } = project();
		const sub = join(root, "sub");
		mkdirSync(sub, { recursive: true });
		const verdict = deny("edit", { filePath: "../.convergence/rules/a.json" }, sub, store);
		expect(verdict).toBeDefined();
		expect(verdict?.path).toBe("../.convergence/rules/a.json");
	});

	test("a `..` path that resolves outside the project is not a store write", () => {
		const { root, store } = project();
		expect(deny("edit", { filePath: "../outside.txt" }, root, store)).toBeUndefined();
		expect(resolvesIntoStore(root, "../outside.txt", store)).toBe(false);
	});

	test("a symlink through /tmp pointing into the store is blocked", () => {
		const { root, store } = project();
		linkCounter += 1;
		const link = join(tmpdir(), `clm-conv-link-${process.pid}-${linkCounter}`);
		symlinkSync(store, link);
		const verdict = deny("edit", { filePath: join(link, "rules/a.json") }, root, store);
		expect(verdict).toBeDefined();
	});

	test("an absolute path outside the project that misses the store is allowed", () => {
		const { root, store } = project();
		expect(deny("edit", { filePath: join(tmpdir(), "elsewhere.txt") }, root, store)).toBeUndefined();
	});

	test("a path landing exactly on the store root is blocked", () => {
		const { root, store } = project();
		expect(deny("edit", { filePath: store }, root, store)).toBeDefined();
		expect(deny("edit", { filePath: ".convergence" }, root, store)).toBeDefined();
	});

	test("a nested path inside the store is blocked", () => {
		const { root, store } = project();
		expect(deny("write", { path: ".convergence/rules/nested/deep.json" }, root, store)).toBeDefined();
	});

	test("the verdict names the tool, the path, and the alternative", () => {
		const { root, store } = project();
		const verdict = deny("edit", { filePath: ".convergence/rules/a.json" }, root, store)!;
		expect(verdict.tool).toBe("edit");
		expect(verdict.message).toContain(".convergence/rules/a.json");
		expect(verdict.message).toMatch(/read-only/);
	});
});

describe("bash target extraction", () => {
	const cases: Array<[string, boolean]> = [
		["echo x > .convergence/rules/a.json", true],
		["echo x >> .convergence/rules/a.json", true],
		["cat f | tee .convergence/rules/a.json", true],
		["dd of=.convergence/transitions.jsonl", true],
		["rm .convergence/rules/a.json", true],
		["mv foo .convergence/", true],
		["sed -i 's/x/y/' .convergence/rules/a.json", true],
		["cd .convergence && rm rules/a.json", true],
		["cat .convergence/rules/a.json", false],
		["grep -r claim src/ > /tmp/out.txt", false],
		["echo hello", false],
	];

	for (const [command, blocked] of cases) {
		test(`${blocked ? "blocked" : "allowed"}: ${command}`, () => {
			const { root, store } = project();
			const verdict = deny("bash", { command }, root, store);
			expect(verdict !== undefined).toBe(blocked);
		});
	}

	test("a non-string or missing command never blocks", () => {
		const { root, store } = project();
		expect(deny("bash", {}, root, store)).toBeUndefined();
		expect(deny("bash", { command: 42 }, root, store)).toBeUndefined();
	});
});

describe("non-bash tools", () => {
	test("edit and write into the store are blocked", () => {
		const { root, store } = project();
		expect(deny("edit", { filePath: ".convergence/rules/a.json" }, root, store)).toBeDefined();
		expect(deny("write", { path: ".convergence/transitions.jsonl" }, root, store)).toBeDefined();
		expect(deny("edit", { filePath: "src/main.ts" }, root, store)).toBeUndefined();
	});

	test("apply_patch naming a store file is blocked", () => {
		const { root, store } = project();
		const patch = ["*** Begin Patch", `*** Update File: ${store}/rules/a.json`, "@@", "-old", "+new", "*** End Patch"].join("\n");
		expect(deny("apply_patch", { patchText: patch }, root, store)).toBeDefined();
		const other = ["*** Begin Patch", "*** Update File: src/a.ts", "@@", "-old", "+new", "*** End Patch"].join("\n");
		expect(deny("apply_patch", { patchText: other }, root, store)).toBeUndefined();
	});

	test("read of a store file, and of anything else, is allowed", () => {
		const { root, store } = project();
		expect(deny("read", { filePath: ".convergence/rules/a.json" }, root, store)).toBeUndefined();
		expect(deny("read", { filePath: "README.md" }, root, store)).toBeUndefined();
		// Reads still count for the tripwire.
		expect(touchesConvergenceStore("read", { filePath: ".convergence/rules/a.json" }, root, store)).toBe(true);
		expect(touchesConvergenceStore("read", { filePath: "README.md" }, root, store)).toBe(false);
	});
});

describe("Phase 3 reconciliation (mtime tripwire)", () => {
	const transition = { key: "flip@1", from: "ACTIVE", to: "SUSPECT" };

	test("the window is five minutes", () => {
		expect(UNTRUSTED_TOUCH_WINDOW_MS).toBe(5 * 60 * 1000);
	});

	test("a transition whose mtime is within 5 min after a touch is untrusted", () => {
		const mtime = 1_700_000_000_000;
		const flagged = markUntrustedTransitions([transition], mtime, [mtime - 60_000]);
		expect(flagged).toEqual([{ ...transition, untrusted: true }]);
	});

	test("a transition with no recent touch is not labeled", () => {
		const mtime = 1_700_000_000_000;
		expect(markUntrustedTransitions([transition], mtime, [mtime - 10 * 60_000])).toEqual([transition]);
		expect(markUntrustedTransitions([transition], mtime, [])).toEqual([transition]);
		// A touch after the mtime (clock skew, or an unrelated later call) does not label.
		expect(markUntrustedTransitions([transition], mtime, [mtime + 1_000])).toEqual([transition]);
	});

	test("a transition with no mtime is left unlabeled (loader could not fold)", () => {
		expect(markUntrustedTransitions([transition], undefined, [Date.now()])).toEqual([transition]);
	});

	test("end to end: a touch before a store change labels the transition on the next transform", async () => {
		const proj = mkdtempSync(join(tmpdir(), "clm-guard-e2e-"));
		const conv = join(proj, ".convergence");
		mkdirSync(join(conv, "rules"), { recursive: true });
		writeFileSync(join(conv, "rules", "flip.json"), JSON.stringify({ id: "flip", version: 1, scope: {}, claim: "Flip.", evidence_refs: [] }));
		const lifecycle = (extra: Array<Record<string, unknown>> = []) =>
			[
				{ event: "CANDIDATE", id: "flip", version: 1 },
				{ event: "AUTHORIZED", id: "flip", version: 1, approval_ref: "human:br" },
				{ event: "ACTIVE", id: "flip", version: 1 },
				...extra,
			].map((line) => JSON.stringify(line)).join("\n") + "\n";
		writeFileSync(join(conv, "transitions.jsonl"), lifecycle());

		const clm = await ClmSession.open(SESSION, settings({ convergenceDir: conv }));
		const raw = [
			{ ...user("msg_u1", "Inspect the repository and report.") },
			assistant("msg_a1", "Looking."),
			user("msg_u2", "Note.\nOBSERVED: flip@1"),
		];
		await clm.transform(structuredClone(raw));

		// The model touches the store, then the bytes change: the next transform
		// must label the resulting transition untrusted. The touch predates the
		// write by two seconds on purpose: filesystem mtimes and Date.now() can
		// disagree by milliseconds (observed ~6ms on overlayfs), so a zero-gap
		// touch-then-write is inherently racy for any timestamp correlation.
		clm.noteStoreTouch(Date.now() - 2_000);
		appendFileSync(join(conv, "transitions.jsonl"), JSON.stringify({ event: "CHALLENGE", id: "flip", version: 1, counterevidence_ref: "evidence/bug.md" }) + "\n");
		await clm.transform([...structuredClone(raw), user("msg_u3", "Continue.")]);

		const events = readFileSync(join(clm.store.directory, "events.jsonl"), "utf8")
			.trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
		expect(events).toContainEqual(expect.objectContaining({ event: "convergence-transition", key: "flip@1", untrusted: true }));
	});
});

describe("loader path closure", () => {
	test("convergenceDir has no settings-table descriptor under any name", () => {
		for (const name of ["convergenceDir", "convergence", "convergence-dir", "convergencedir"]) {
			expect(settingDescriptor(name)).toBeUndefined();
		}
		expect(SETTING_NAMES).not.toContain("convergenceDir");
	});

	test("a saved convergenceDir override is dropped, loudly", () => {
		const { overrides, ignored } = sanitizeOverrides({ convergenceDir: "/tmp/evil", budget: 1000 });
		expect(overrides).not.toHaveProperty("convergenceDir");
		expect(ignored).toContain("convergenceDir");
		expect(overrides).toMatchObject({ budget: 1000 });
	});

	test("/clm config convergenceDir is an unknown setting", async () => {
		const directory = tempDir("clm-guard-settings-");
		await expect(
			changeSetting(
				{ sessionDirectory: directory, base: settings(), baseEditing: true, projectDirectory: directory },
				"convergenceDir",
				"/tmp/evil",
			),
		).rejects.toThrow(/Unknown setting/);
	});
});

describe("mirror-into-store closure", () => {
	test("mirrorDir has no settings-table descriptor under any name", () => {
		for (const name of ["mirrorDir", "mirror", "mirror-dir", "mirrordir"]) {
			expect(settingDescriptor(name)).toBeUndefined();
		}
		expect(SETTING_NAMES).not.toContain("mirrorDir");
	});

	test("a saved mirrorDir override is dropped, loudly", () => {
		const { overrides, ignored } = sanitizeOverrides({ mirrorDir: ".convergence/evil" });
		expect(overrides).not.toHaveProperty("mirrorDir");
		expect(ignored).toContain("mirrorDir");
	});

	test("/clm config mirrorDir is an unknown setting", async () => {
		const directory = tempDir("clm-guard-settings-");
		await expect(
			changeSetting(
				{ sessionDirectory: directory, base: settings(), baseEditing: true, projectDirectory: directory },
				"mirrorDir",
				".convergence/evil",
			),
		).rejects.toThrow(/Unknown setting/);
	});
});

describe("self-validation", () => {
	test("the check fires: a synthetic store write is blocked, a plain command is not", () => {
		const { root, store } = project();
		const blocked = deny("bash", { command: "echo x >> .convergence/rules/a.json" }, root, store);
		expect(blocked).toBeDefined();
		expect(blocked?.message).toMatch(/read-only/);
		expect(deny("bash", { command: "echo hello" }, root, store)).toBeUndefined();
		// And across the whole matrix above, at least one case blocks and one allows,
		// so a regression to allow-everything (or deny-everything) fails loudly.
		const matrix: Array<[string, Record<string, unknown>]> = [
			["edit", { filePath: ".convergence/rules/a.json" }],
			["bash", { command: "rm .convergence/rules/a.json" }],
			["read", { filePath: ".convergence/rules/a.json" }],
			["bash", { command: "echo hello" }],
		];
		const results = matrix.map(([tool, input]) => deny(tool, input, root, store) !== undefined);
		expect(results).toContain(true);
		expect(results).toContain(false);
	});
});

describe("lexical bypasses (expected outcomes documented)", () => {
	test("env indirection passes the block but the touch feeds the tripwire", () => {
		const { root, store } = project();
		const command = "C=.convergence; echo x >> $C/rules/a.json";
		// The guard cannot resolve `$C`: the write passes through.
		expect(deny("bash", { command }, root, store)).toBeUndefined();
		// But the literal `.convergence` mention records a touch ...
		expect(touchesConvergenceStore("bash", { command }, root, store)).toBe(true);
		// ... and a touch just before the mtime labels the transition untrusted.
		const mtime = 1_700_000_000_000;
		expect(markUntrustedTransitions(
			[{ key: "a@1", from: "ACTIVE", to: "SUSPECT" }],
			mtime,
			[mtime - 1_000],
		)).toEqual([{ key: "a@1", from: "ACTIVE", to: "SUSPECT", untrusted: true }]);
	});

	test("token obfuscation of the command name is still blocked (stronger than claimed)", () => {
		// The redirect target is extracted as text regardless of what runs it, so
		// quoting games on the command name do not hide the destination.
		const { root, store } = project();
		expect(deny("bash", { command: "e''cho x >> .convergence/rules/a.json" }, root, store)).toBeDefined();
	});

	test("full indirection blinds the block AND the touch (open hole, documented)", () => {
		// No literal `.convergence` anywhere: neither the deny nor the touch fires.
		// Only the digest log (`convergence-changed`, no attribution) remains.
		const { root, store } = project();
		const command = "D=.converg;E=ence; echo x >> $D$E/rules/a.json";
		expect(command).not.toContain(".convergence");
		expect(deny("bash", { command }, root, store)).toBeUndefined();
		expect(touchesConvergenceStore("bash", { command }, root, store)).toBe(false);
	});

	test("a store change still shows up as a digest change (the unattributed backstop)", async () => {
		const proj = mkdtempSync(join(tmpdir(), "clm-guard-digest-"));
		const conv = join(proj, ".convergence");
		mkdirSync(join(conv, "rules"), { recursive: true });
		writeFileSync(join(conv, "rules", "a.json"), JSON.stringify({ id: "a", version: 1, scope: {}, claim: "A.", evidence_refs: [] }));
		const lifecycle = (extra: Array<Record<string, unknown>> = []) =>
			[
				{ event: "CANDIDATE", id: "a", version: 1 },
				{ event: "AUTHORIZED", id: "a", version: 1, approval_ref: "human:x" },
				{ event: "ACTIVE", id: "a", version: 1 },
				...extra,
			].map((line) => JSON.stringify(line)).join("\n") + "\n";
		writeFileSync(join(conv, "transitions.jsonl"), lifecycle());
		const before = await loadConvergenceStore(conv);
		appendFileSync(join(conv, "transitions.jsonl"), JSON.stringify({ event: "CHALLENGE", id: "a", version: 1, counterevidence_ref: "e.md" }) + "\n");
		const after = await loadConvergenceStore(conv);
		expect(before?.digest).toBeDefined();
		expect(after?.digest).toBeDefined();
		expect(after?.digest).not.toBe(before?.digest);
	});
});

describe("unknown-tool policy (Option A, store-scoped)", () => {
	test("an unknown tool naming a store path is blocked", () => {
		const { root, store } = project();
		const verdict = deny("mywrite", { filePath: ".convergence/rules/a.json" }, root, store);
		expect(verdict).toBeDefined();
		expect(verdict?.tool).toBe("mywrite");
		// Nested string args are found too (custom schemas use unknown keys).
		expect(deny("mytool", { nested: { output: `${store}/rules/a.json` } }, root, store)).toBeDefined();
	});

	test("an unknown tool with no store path passes through", () => {
		const { root, store } = project();
		expect(deny("mywrite", { filePath: "notes.md" }, root, store)).toBeUndefined();
		expect(deny("mywrite", {}, root, store)).toBeUndefined();
	});

	test("a known-safe read-only tool passes even when it names the store", () => {
		const { root, store } = project();
		expect(KNOWN_SAFE_READONLY.has("glob")).toBe(true);
		expect(KNOWN_SAFE_READONLY.has("grep")).toBe(true);
		expect(deny("glob", { pattern: `${store}/rules/*.json` }, root, store)).toBeUndefined();
		expect(deny("grep", { pattern: "claim", path: ".convergence/rules/a.json" }, root, store)).toBeUndefined();
	});

	test("prose mentioning the store does not fail closed", () => {
		const { root, store } = project();
		expect(deny("mytask", { description: "rewrite the rules in .convergence please" }, root, store)).toBeUndefined();
	});

	test("unknown-tool touches feed the tripwire", () => {
		const { root, store } = project();
		expect(touchesConvergenceStore("mywrite", { filePath: ".convergence/rules/a.json" }, root, store)).toBe(true);
		expect(touchesConvergenceStore("mywrite", { filePath: "notes.md" }, root, store)).toBe(false);
	});
});

describe("hook wiring (tool.execute.before)", () => {
	async function harness() {
		const directory = tempDir("clm-guard-hook-");
		const input = { directory, worktree: directory, client: {} } as unknown as PluginInput;
		const hooks = await server(input, { mirrorDir: join(directory, "mirrors") });
		const output = { messages: conversation() } as never;
		await hooks["experimental.chat.messages.transform"]!({}, output);
		return { hooks, directory };
	}

	const before = (
		hooks: Awaited<ReturnType<typeof server>>,
		tool: string,
		args: Record<string, unknown>,
	) => hooks["tool.execute.before"]!({ tool, sessionID: SESSION, callID: "c_guard" }, { args });

	test("an edit of the store through the hook is rejected", async () => {
		const { hooks, directory } = await harness();
		await expect(before(hooks, "edit", { filePath: join(directory, ".convergence", "rules", "a.json") }))
			.rejects.toThrow(/read-only/);
		const events = readFileSync(join(directory, "mirrors", `clm-${SESSION}`, "events.jsonl"), "utf8");
		expect(events).toContain('"event":"convergence-write-blocked"');
	});

	test("a read of the store and an unrelated write pass the hook", async () => {
		const { hooks, directory } = await harness();
		await before(hooks, "read", { filePath: join(directory, ".convergence", "rules", "a.json") });
		await before(hooks, "edit", { filePath: join(directory, "notes.md") });
	});

	test("an unknown custom tool naming the store is rejected at the hook", async () => {
		const { hooks, directory } = await harness();
		await expect(before(hooks, "mywrite", { filePath: join(directory, ".convergence", "rules", "a.json") }))
			.rejects.toThrow(/read-only/);
		await before(hooks, "glob", { pattern: join(directory, ".convergence", "rules", "*.json") });
	});
});
