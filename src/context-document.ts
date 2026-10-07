// Adapted from pi-clm src/context-document.ts (MIT, Copyright 2026 Emanuel Casco).
import { createHash } from "node:crypto";
import { dirname } from "node:path";

import { gateEdit } from "./policy.ts";
import { checkCitations, MAX_CITATION_FAILURES } from "./convergence/citations.ts";
import type { ConvergenceClaim } from "./convergence/loader.ts";
import { reconcileSuspectMarkers } from "./convergence/suspect.ts";
import type {
	ApplyDocumentOptions,
	ApplyDocumentResult,
	ContextDocumentSnapshot,
	ContextEditSourceKind,
	ContextEditTrace,
	DocumentBlock,
	LiveContextMessage,
} from "./types.ts";

const DOCUMENT_VERSION = 1;
const EDIT_HINT = "# Edit bodies or delete editable CTX_TURN blocks. Keep metadata/header lines intact.";
/** customType of messages the plugin authors: model-inserted blocks and edited bodies that changed role. */
export const NOTE_TYPE = "clm-note";
// Metadata is valid only as the first line. An example copied into a message body must
// never be mistaken for the active document envelope.
const META_RE =
	/^\[\[LIVE_CONTEXT version=(\d+) revision=(\d+) document=([a-f0-9]{64}) baseline=([a-f0-9]{64})\]\](?:\r?\n|$)/;

interface ParsedBlock {
	index: number;
	id: string;
	role: string;
	protected: boolean;
	body: string;
}

interface ParsedDocument {
	version?: number;
	revision?: number;
	documentId?: string;
	baselineDigest?: string;
	blocks: ParsedBlock[];
	preamble: string;
	duplicateIds: string[];
	malformedCurrentHeaders: string[];
}

function normalizeJson(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(normalizeJson);
	if (value && typeof value === "object") {
		return Object.fromEntries(
			Object.entries(value as Record<string, unknown>)
				.filter(([, item]) => item !== undefined)
				.sort(([left], [right]) => left.localeCompare(right))
				.map(([key, item]) => [key, normalizeJson(item)]),
		);
	}
	return value;
}

export function canonicalMessage(message: LiveContextMessage): string {
	return JSON.stringify(normalizeJson(message));
}

export function digestMessages(messages: LiveContextMessage[]): string {
	const hash = createHash("sha256");
	for (const message of messages) {
		hash.update(canonicalMessage(message));
		hash.update("\n");
	}
	return hash.digest("hex");
}

function textFromContent(content: unknown): string {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";

	return content
		.map((part) => {
			if (typeof part === "string") return part;
			if (!part || typeof part !== "object") return String(part ?? "");
			const block = part as Record<string, unknown>;
			if (block.type === "text" && typeof block.text === "string") return block.text;
			if (block.type === "thinking" && typeof block.thinking === "string") {
				return `[thinking]\n${block.thinking}`;
			}
			if (block.type === "toolCall") {
				const name = typeof block.name === "string" ? block.name : "tool";
				return `[tool call: ${name}]\n${JSON.stringify(normalizeJson(block.arguments ?? {}))}`;
			}
			if (block.type === "image") {
				const mimeType =
					typeof block.mimeType === "string"
						? block.mimeType
						: typeof (block.source as Record<string, unknown> | undefined)?.mediaType === "string"
							? String((block.source as Record<string, unknown>).mediaType)
							: "unknown";
				return `[image: ${mimeType}; data omitted]`;
			}
			return JSON.stringify(normalizeJson(block));
		})
		.filter(Boolean)
		.join("\n");
}

export function renderMessage(message: LiveContextMessage): string {
	const parts: string[] = [];
	let content = textFromContent(message.content);
	const contextRole = (message.details as { contextRole?: unknown } | undefined)?.contextRole;
	if (message.role === "custom" && message.customType === NOTE_TYPE && typeof contextRole === "string") {
		const prefix = `[context role=${contextRole}]\n`;
		if (content.startsWith(prefix)) content = content.slice(prefix.length);
	}
	if (content) parts.push(content);

	if (message.role === "bashExecution") {
		if (typeof message.command === "string") parts.push(`[command]\n${message.command}`);
		if (typeof message.output === "string" && message.output) parts.push(`[output]\n${message.output}`);
	}
	if (message.role === "branchSummary" || message.role === "compactionSummary") {
		if (typeof message.summary === "string") parts.push(message.summary);
	}

	// Legacy/OpenAI-shaped messages are accepted by the pure core as well.
	const toolCalls = Array.isArray(message.tool_calls) ? message.tool_calls : [];
	for (const toolCall of toolCalls) {
		if (!toolCall || typeof toolCall !== "object") continue;
		const fn = (toolCall as Record<string, unknown>).function as Record<string, unknown> | undefined;
		if (!fn) continue;
		parts.push(`[tool call: ${String(fn.name ?? "tool")}]\n${String(fn.arguments ?? "")}`);
	}

	return parts.join("\n\n").trim();
}

export function estimateContextCharacters(messages: LiveContextMessage[]): number {
	return messages.reduce((total, message) => total + renderMessage(message).length, 0);
}

/** The mirror block id of `message` at position `index` of the rendered messages. */
export function blockId(message: LiveContextMessage, index: number): string {
	const digest = createHash("sha256").update(canonicalMessage(message)).digest("hex").slice(0, 12);
	return `${index + 1}-${digest}`;
}

function documentId(baselineDigest: string, revision: number): string {
	return createHash("sha256")
		.update(`opencode-clm:${DOCUMENT_VERSION}:${revision}:${baselineDigest}`)
		.digest("hex");
}

/**
 * Structural lines inside a body are escaped when the document nonce is stable across
 * renders (CLM mode). With a per-render nonce this was unnecessary: a header the model
 * printed on one call could never match the nonce of the next render. With a per-revision
 * nonce, a `head -5 LIVE_CONTEXT.md` tool result would contain live headers, so they are
 * neutralised with a leading backslash at render time and restored when a body is edited.
 */
const STRUCTURAL_LINE_RE = /^(\\*)(\[\[(?:CTX_TURN|LIVE_CONTEXT) )/gm;

export function escapeStructuralLines(body: string): string {
	return body.replace(STRUCTURAL_LINE_RE, (_match, slashes: string, start: string) => `\\${slashes}${start}`);
}

export function unescapeStructuralLines(body: string): string {
	return body.replace(STRUCTURAL_LINE_RE, (_match, slashes: string, start: string) =>
		slashes.length > 0 ? `${slashes.slice(1)}${start}` : `${slashes}${start}`,
	);
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export interface RenderContextDocumentOptions {
	revision?: number;
	protectedIndexes?: Set<number>;
	/**
	 * Read-only Convergence claims body (Phase 1, fork-local). When set, a reserved
	 * `role=claims` block is emitted ahead of the message blocks and recorded on
	 * the snapshot; `applyContextDocument` rejects any edit that touches it.
	 */
	claimsBody?: string;
	/**
	 * Render-time claim fold for Phase 2 citation checks (fork-local). Carried on
	 * the snapshot so the gate verifies citations against what the model saw.
	 */
	claimsMeta?: { rows: readonly ConvergenceClaim[]; root: string };
	/**
	 * When set, the document nonce is derived from this seed and the revision instead of
	 * the rendered baseline, so it stays constant between accepted edits even as new
	 * messages arrive. Header ids a model reads on one call remain valid on the next.
	 * Bodies are then escaped so live headers quoted inside tool output stay inert.
	 */
	documentSeed?: string;
}

/**
 * Reserved claims-section framing (Phase 1 convergence, fork-local). The claims
 * block is not a message: it carries project-authorized claims into the mirror as
 * read-only context. Fixed id outside the `<index>-<12-hex>` namespace so the
 * model is never expected to preserve it — the render pass re-emits it
 * deterministically and the commit path rejects any edit that touches it.
 */
export const CLAIMS_ROLE = "claims";
export const CLAIMS_ID = "claims";

export function renderContextDocument(
	messages: LiveContextMessage[],
	options: RenderContextDocumentOptions = {},
): ContextDocumentSnapshot {
	const revision = options.revision ?? 0;
	const protectedIndexes = options.protectedIndexes ?? new Set<number>();
	const baselineDigest = digestMessages(messages);
	const stable = options.documentSeed !== undefined;
	const currentDocumentId = documentId(stable ? `seed:${options.documentSeed}` : baselineDigest, revision);
	const blocks: DocumentBlock[] = messages.map((source, index) => {
		const id = blockId(source, index);
		const authoredRole = (source.details as { contextRole?: unknown } | undefined)?.contextRole;
		const role = source.role === "custom" && source.customType === NOTE_TYPE &&
			typeof authoredRole === "string" && /^[A-Za-z][A-Za-z0-9_-]*$/.test(authoredRole)
			? authoredRole : source.role;
		const protectedBlock = protectedIndexes.has(index);
		// Phase 3 SUSPECT propagation (fork-local): reconcile the [SUSPECT] marker on
		// claim citations against the render-time fold. Same parser as the gate, so
		// the two agree on what counts as a citation. The claims body is regenerated,
		// never reconciled; blocks and text stay consistent, so marking alone never
		// reads as an edit at commit time.
		const rawBody = stable ? escapeStructuralLines(renderMessage(source)) : renderMessage(source);
		const markedBody = options.claimsMeta
			? reconcileSuspectMarkers(rawBody, options.claimsMeta.rows).body
			: rawBody;
		return {
			index,
			id,
			role,
			protected: protectedBlock,
			header: `[[CTX_TURN document=${currentDocumentId} index=${index + 1} role=${role} id=${id} protected=${protectedBlock}]]`,
			body: markedBody,
			source,
		};
	});
	const renderedBlocks = blocks.map((block) => `${block.header}\n${block.body}`);
	// Claims first: a reserved role=claims block with a fixed synthetic id. Message
	// block indexes are unchanged (claims takes header index 0, messages start at 1).
	const claims = options.claimsBody !== undefined
		? {
			id: CLAIMS_ID,
			body: (stable ? escapeStructuralLines(options.claimsBody) : options.claimsBody).trim(),
			rows: [...(options.claimsMeta?.rows ?? [])],
			root: options.claimsMeta?.root ?? "",
		}
		: undefined;
	const claimsHeader = `[[CTX_TURN document=${currentDocumentId} index=0 role=${CLAIMS_ROLE} id=${CLAIMS_ID} protected=true]]`;
	const text = [
		`[[LIVE_CONTEXT version=${DOCUMENT_VERSION} revision=${revision} document=${currentDocumentId} baseline=${baselineDigest}]]`,
		EDIT_HINT,
		...(claims ? [`${claimsHeader}\n${claims.body}`] : []),
		...renderedBlocks,
	].join("\n\n");

	return {
		version: DOCUMENT_VERSION,
		revision,
		baselineDigest,
		documentId: currentDocumentId,
		stableDocument: stable,
		text,
		messages: [...messages],
		blocks,
		...(claims ? { claims } : {}),
	};
}

function parseDocument(text: string, snapshot: ContextDocumentSnapshot): ParsedDocument {
	const metadata = META_RE.exec(text);
	const blockRe = new RegExp(
		`^\\[\\[CTX_TURN document=${escapeRegExp(snapshot.documentId)} index=(\\d+) role=([A-Za-z][A-Za-z0-9_-]*) id=([a-zA-Z0-9-]+) protected=(true|false)\\]\\]\\s*$`,
		"gm",
	);
	const matches = [...text.matchAll(blockRe)];
	const blocks: ParsedBlock[] = [];
	const seen = new Set<string>();
	const duplicateIds: string[] = [];

	for (let index = 0; index < matches.length; index++) {
		const match = matches[index];
		const start = (match.index ?? 0) + match[0].length;
		const end = index + 1 < matches.length ? (matches[index + 1].index ?? text.length) : text.length;
		const id = match[3];
		if (seen.has(id)) duplicateIds.push(id);
		seen.add(id);
		blocks.push({
			index: Number(match[1]) - 1,
			role: match[2],
			id,
			protected: match[4] === "true",
			body: text.slice(start, end).trim(),
		});
	}

	const validHeaderLines = new Set(matches.map((match) => match[0].trim()));
	const currentPrefix = `[[CTX_TURN document=${snapshot.documentId} `;
	const malformedCurrentHeaders = text
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter((line) => line.startsWith(currentPrefix) && !validHeaderLines.has(line));

	const metadataEnd = metadata ? metadata[0].length : 0;
	const firstBlockStart = matches[0]?.index ?? text.length;
	const preamble = text
		.slice(metadataEnd, firstBlockStart)
		.split("\n")
		.filter((line) => !line.trim().startsWith(EDIT_HINT))
		.join("\n")
		.trim();

	return {
		version: metadata ? Number(metadata[1]) : undefined,
		revision: metadata ? Number(metadata[2]) : undefined,
		documentId: metadata?.[3],
		baselineDigest: metadata?.[4],
		blocks,
		preamble,
		duplicateIds,
		malformedCurrentHeaders,
	};
}

/**
 * True when a line starts with a `[[CTX_TURN ` or `[[LIVE_CONTEXT ` frame of any nonce,
 * other than a metadata line for the current revision and document.
 */
function hasForeignFraming(text: string, snapshot: ContextDocumentSnapshot): boolean {
	return text.split(/\r?\n/).some((raw) => {
		const line = raw.trimStart();
		if (line.startsWith("[[CTX_TURN ")) return true;
		if (!line.startsWith("[[LIVE_CONTEXT ")) return false;
		const meta = META_RE.exec(line);
		return !meta ||
			Number(meta[1]) !== snapshot.version ||
			Number(meta[2]) !== snapshot.revision ||
			meta[3] !== snapshot.documentId;
	});
}

function contentToolCalls(message: LiveContextMessage): Array<{ id?: string; name?: string; arguments?: unknown }> {
	if (!Array.isArray(message.content)) return [];
	return message.content
		.filter(
			(part): part is Record<string, unknown> =>
				Boolean(part && typeof part === "object" && (part as Record<string, unknown>).type === "toolCall"),
		)
		.map((part) => ({
			id: typeof part.id === "string" ? part.id : undefined,
			name: typeof part.name === "string" ? part.name : undefined,
			arguments: part.arguments,
		}));
}

function toolCallIds(message: LiveContextMessage): Set<string> {
	const ids = new Set<string>();
	for (const call of contentToolCalls(message)) if (call.id) ids.add(call.id);
	for (const call of Array.isArray(message.tool_calls) ? message.tool_calls : []) {
		if (call && typeof call === "object" && typeof (call as Record<string, unknown>).id === "string") {
			ids.add(String((call as Record<string, unknown>).id));
		}
	}
	return ids;
}

/** Edited body text as it should enter a message: escaped structural lines restored. */
function bodyText(body: string, snapshot: ContextDocumentSnapshot): string {
	return snapshot.stableDocument ? unescapeStructuralLines(body) : body;
}

function contextNote(body: string, source?: LiveContextMessage, requestedRole?: string): LiveContextMessage {
	return {
		role: "custom",
		customType: NOTE_TYPE,
		content: requestedRole ? `[context role=${requestedRole}]\n${body}` : body,
		...(requestedRole ? { details: { contextRole: requestedRole } } : {}),
		display: false,
		timestamp: typeof source?.timestamp === "number" ? source.timestamp : Date.now(),
	};
}

function changedMessage(source: LiveContextMessage, body: string, requestedRole: string, labelRole = false): LiveContextMessage {
	if (source.role === "assistant" && requestedRole === "assistant") {
		const changed: LiveContextMessage = {
			...source,
			content: [{ type: "text", text: body }],
			stopReason: "stop",
			edited: true,
		};
		delete changed.errorMessage;
		delete changed.tool_calls;
		return changed;
	}
	if (source.role === "user" && requestedRole === "user") {
		return {
			...source,
			content: Array.isArray(source.content) ? [{ type: "text", text: body }] : body,
			edited: true,
		};
	}
	// OpenCode stores a tool call and its result in one part, so an edited result body can
	// stay a structured tool result: the call keeps its pairing and only the output changes.
	if (source.role === "toolResult" && requestedRole === "toolResult") {
		return { ...source, content: [{ type: "text", text: body }], edited: true };
	}
	return contextNote(body, source, labelRole ? requestedRole : undefined);
}

function repairToolGroups(messages: LiveContextMessage[]): LiveContextMessage[] {
	const repaired = [...messages];

	for (let index = 0; index < repaired.length; index++) {
		const message = repaired[index];
		if (message.role !== "assistant") continue;
		const ids = toolCallIds(message);
		if (ids.size === 0) continue;

		const resultIds = new Set<string>();
		let cursor = index + 1;
		while (cursor < repaired.length && repaired[cursor].role === "toolResult") {
			const resultId = repaired[cursor].toolCallId;
			if (typeof resultId === "string" && ids.has(resultId)) resultIds.add(resultId);
			cursor++;
		}
		const complete = [...ids].every((id) => resultIds.has(id));
		if (!complete) repaired[index] = contextNote(renderMessage(message), message);
	}

	for (let index = 0; index < repaired.length; index++) {
		const message = repaired[index];
		if (message.role !== "toolResult") continue;
		let assistantIndex = index - 1;
		while (assistantIndex >= 0 && repaired[assistantIndex].role === "toolResult") assistantIndex--;
		const assistant = assistantIndex >= 0 ? repaired[assistantIndex] : undefined;
		const ids = assistant?.role === "assistant" ? toolCallIds(assistant) : new Set<string>();
		if (typeof message.toolCallId !== "string" || !ids.has(message.toolCallId)) {
			repaired[index] = contextNote(renderMessage(message), message);
		}
	}

	return repaired;
}

export function hasOrphanToolMessages(messages: LiveContextMessage[]): boolean {
	for (let index = 0; index < messages.length; index++) {
		const message = messages[index];
		if (message.role === "assistant") {
			const ids = toolCallIds(message);
			if (ids.size === 0) continue;
			const found = new Set<string>();
			let cursor = index + 1;
			while (cursor < messages.length && messages[cursor].role === "toolResult") {
				const resultId = messages[cursor].toolCallId;
				if (typeof resultId === "string" && ids.has(resultId)) found.add(resultId);
				cursor++;
			}
			if ([...ids].some((id) => !found.has(id))) return true;
		}
		if (message.role === "toolResult") {
			let cursor = index - 1;
			while (cursor >= 0 && messages[cursor].role === "toolResult") cursor--;
			const assistant = cursor >= 0 ? messages[cursor] : undefined;
			if (
				!assistant ||
				assistant.role !== "assistant" ||
				typeof message.toolCallId !== "string" ||
				!toolCallIds(assistant).has(message.toolCallId)
			) {
				return true;
			}
		}
	}
	return false;
}

function rejected(
	snapshot: ContextDocumentSnapshot,
	beforeEstimate: number,
	reason: string,
	diagnostics: string[] = [],
): ApplyDocumentResult {
	return {
		accepted: false,
		changed: true,
		messages: [...snapshot.messages],
		beforeEstimate,
		afterEstimate: beforeEstimate,
		savingsEstimate: 0,
		diagnostics,
		reason,
	};
}

export function applyContextDocument(
	editedText: string,
	snapshot: ContextDocumentSnapshot,
	options: ApplyDocumentOptions = {},
): ApplyDocumentResult {
	const estimate = options.estimate ?? estimateContextCharacters;
	const estimateUnit = options.estimateUnit ?? "characters";
	const beforeEstimate = estimate(snapshot.messages);
	if (editedText.trim() === snapshot.text.trim()) {
		return {
			accepted: true,
			changed: false,
			messages: [...snapshot.messages],
			beforeEstimate,
			afterEstimate: beforeEstimate,
			savingsEstimate: 0,
			diagnostics: [],
		};
	}

	const finalize = (
		candidate: LiveContextMessage[],
		candidateOrigins: Array<{ sourceIndex?: number; kind: ContextEditSourceKind | "added" }>,
		removedSourceIndexes: Set<number>,
		diagnostics: string[],
	): ApplyDocumentResult => {
		const messages = repairToolGroups(candidate);
		if (hasOrphanToolMessages(messages)) {
			return rejected(snapshot, beforeEstimate, "Context edit could not be normalized to legal tool-call structure.");
		}
		const afterEstimate = estimate(messages);
		const gate = gateEdit({
			gate: options.gate ?? (options.editingMode === "clm" ? "fit" : "shrink"),
			before: beforeEstimate,
			after: afterEstimate,
			limit: options.limit,
			unit: estimateUnit,
		});
		if (!gate.accepted) return rejected(snapshot, beforeEstimate, gate.reason ?? "Context edit rejected by the edit gate.", diagnostics);

		const tracedSources: ContextEditTrace["sources"] = candidateOrigins.flatMap((origin, outputIndex) => {
			if (origin.sourceIndex === undefined) return [];
			const wasNormalized = canonicalMessage(candidate[outputIndex]) !== canonicalMessage(messages[outputIndex]);
			const kind: ContextEditSourceKind = wasNormalized
				? "normalized"
				: origin.kind === "added" ? "edited" : origin.kind;
			return [{ sourceIndex: origin.sourceIndex, outputIndex, kind }];
		});
		for (const sourceIndex of removedSourceIndexes) {
			tracedSources.push({ sourceIndex, kind: "removed" });
		}
		tracedSources.sort((left, right) => left.sourceIndex - right.sourceIndex);
		const editTrace: ContextEditTrace = {
			version: 1,
			sourceRevision: snapshot.revision,
			sourceMessageCount: snapshot.messages.length,
			outputMessageCount: messages.length,
			sources: tracedSources,
			additions: candidateOrigins.flatMap((origin, outputIndex) =>
				origin.sourceIndex === undefined ? [{ outputIndex, kind: "added" as const }] : [],
			),
		};

		return {
			accepted: true,
			changed: true,
			messages,
			beforeEstimate,
			afterEstimate,
			savingsEstimate: beforeEstimate - afterEstimate,
			diagnostics,
			editTrace,
		};
	};

	const parsed = parseDocument(editedText, snapshot);
	const metadataLine = snapshot.text.split("\n")[0] ?? "";
	// States the current revision, what is wrong with the file, and the exact line to
	// write, so the model can fix the file in one step.
	const staleMetadata = () => {
		const current = `The mirror is at revision ${snapshot.revision}.`;
		let found: string;
		let cause: string;
		if (parsed.revision === undefined) {
			found = "your file has no [[LIVE_CONTEXT ...]] line 1";
			cause = parsed.blocks.length === 0 && /^\s*\[\[CTX_TURN /m.test(editedText)
				? `${current} Its block headers come from an older copy of the mirror: read the file again and apply your change to its current text.`
				: `${current} Put the line below back as line 1 and keep the rest of your edit.`;
		} else if (parsed.revision !== snapshot.revision) {
			found = `your file says revision ${parsed.revision}`;
			cause = `${current} It was rewritten after the copy you edited was taken: read the file again and apply your change to its current text, leaving line 1 as it is.`;
		} else {
			const fields = [
				...(parsed.version !== snapshot.version ? ["version"] : []),
				...(parsed.documentId !== snapshot.documentId ? ["document id"] : []),
				...(!snapshot.stableDocument && parsed.baselineDigest !== snapshot.baselineDigest ? ["baseline digest"] : []),
			];
			found = fields.length > 0
				? `your file says revision ${parsed.revision}, but its ${fields.join(" and ")} differ${fields.length === 1 ? "s" : ""}`
				: `your file's line 1 is current, but its block headers belong to another copy of the mirror`;
			cause = fields.length > 0
				? `${current} Line 1 was changed or copied from another mirror: restore it exactly and keep the rest of your edit.`
				: `${current} Read the file again and apply your change to its current text.`;
		}
		return rejected(
			snapshot,
			beforeEstimate,
			`Mirror metadata does not match the current context revision (expected revision ${snapshot.revision}, document ${snapshot.documentId.slice(0, 12)}…; ${found}). ` +
				`${cause} The first line must be exactly: ${metadataLine}`,
		);
	};
	// Phase 1 convergence (fork-local): the reserved role=claims block is read-only.
	// It is not part of snapshot.blocks, so after validation it is extracted here
	// and excluded from the conversation processing below. Any touch — deletion,
	// body/role/flag change, duplication, or a forged role=claims block — rejects
	// the whole edit. This runs inside applyContextDocument, so the dry-run receipt
	// (validateMirror) and the binding commit agree.
	const claimsRefusal = (detail: string) =>
		rejected(
			snapshot,
			beforeEstimate,
			`Mirror claims section (id "${CLAIMS_ID}", role "${CLAIMS_ROLE}") is read-only: ${detail}. ` +
				`Restore its header and body exactly and keep the rest of your edit. Cite claims by id; do not rewrite them.`,
		);
	// A file with no current block headers but with framing lines from another document
	// (or a stale revision) is an old mirror copied back, not a summary: reject it.
	if (parsed.blocks.length === 0 && hasForeignFraming(editedText, snapshot)) return staleMetadata();
	// With a claims section, a headerless file necessarily dropped the read-only
	// claims block: refuse it here so the whole-rewrite path below stays closed.
	if (snapshot.claims && !parsed.blocks.some((block) => block.id === snapshot.claims!.id)) {
		return claimsRefusal("it is missing");
	}
	// CLM: a file with no block headers at all is the model replacing its whole context
	// with free text (the paper's "collapse to a summary" move). Accept it as one notes
	// block, keeping the first user turn so the task statement survives.
	// With a claims section this path is closed: dropping every header also drops the
	// read-only claims block, which the guard above already refused. What remains here
	// is "only the claims header kept", which falls through to normal processing.
	if (options.editingMode === "clm" && parsed.blocks.length === 0 && !snapshot.claims && editedText.trim().length > 0) {
		const body = unescapeStructuralLines(
			editedText
				.split(/\r?\n/)
				.filter((line) => !META_RE.test(`${line}\n`) && !line.trim().startsWith(EDIT_HINT))
				.join("\n")
				.trim(),
		);
		if (body.length === 0) return rejected(snapshot, beforeEstimate, "Mirror is empty after removing metadata; nothing to apply.");
		const candidate: LiveContextMessage[] = [];
		const candidateOrigins: Array<{ sourceIndex?: number; kind: ContextEditSourceKind | "added" }> = [];
		const removedSourceIndexes = new Set<number>();
		const firstUserIndex = options.taskPinned ? -1 : snapshot.messages.findIndex((message) => message.role === "user");
		for (const [index, message] of snapshot.messages.entries()) {
			if (index === firstUserIndex) {
				candidate.push(message);
				candidateOrigins.push({ sourceIndex: index, kind: "kept" });
			} else {
				removedSourceIndexes.add(index);
			}
		}
		candidate.push(contextNote(body, undefined, "notes"));
		candidateOrigins.push({ kind: "added" });
		return finalize(candidate, candidateOrigins, removedSourceIndexes, [
			"Accepted a headerless rewrite: every block was replaced by one notes block" +
				(firstUserIndex >= 0 ? " after the first user turn" : "") +
				". To edit blocks individually, keep the [[CTX_TURN ...]] headers.",
		]);
	}
	// With a stable document the baseline digest still changes every render (new raw
	// messages), so only the revision and nonce identify the document the model edited.
	const baselineMatches = snapshot.stableDocument || parsed.baselineDigest === snapshot.baselineDigest;
	if (
		parsed.version !== snapshot.version ||
		parsed.revision !== snapshot.revision ||
		parsed.documentId !== snapshot.documentId ||
		!baselineMatches
	) {
		return staleMetadata();
	}
	// Claims validation, after staleness so an old copy still gets the stale-copy
	// message. The intact claims block is then extracted: it never enters the
	// conversation processing below.
	if (snapshot.claims) {
		const found = parsed.blocks.filter((block) => block.id === snapshot.claims!.id);
		if (found.length !== 1) {
			return claimsRefusal("it appears more than once");
		}
		const claimsBlock = found[0]!;
		if (claimsBlock.role !== CLAIMS_ROLE || !claimsBlock.protected || claimsBlock.body !== snapshot.claims.body) {
			const detail = claimsBlock.role !== CLAIMS_ROLE
				? `its role changed to ${claimsBlock.role}`
				: !claimsBlock.protected
				? "its protected flag was changed"
				: "its body was edited";
			return claimsRefusal(detail);
		}
		if (parsed.blocks.some((block) => block !== claimsBlock && block.role === CLAIMS_ROLE)) {
			return claimsRefusal(`role "${CLAIMS_ROLE}" is reserved`);
		}
		parsed.blocks = parsed.blocks.filter((block) => block !== claimsBlock);
	} else if (parsed.blocks.some((block) => block.id === CLAIMS_ID || block.role === CLAIMS_ROLE)) {
		return claimsRefusal(`role "${CLAIMS_ROLE}" is reserved`);
	}
	// Phase 2 citation verification (fork-local), in the same function as the
	// Phase 1 claims guard so the dry-run receipt and the binding commit agree.
	// Every OBSERVED: line in the edited conversation text is checked: claim
	// citations against the render-time fold (resolution, ACTIVE state, scope),
	// file citations for pointer resolution only. ASSUMED: lines are never
	// examined. One failure rejects the whole edit.
	// Phase 3 past-vs-new: a [SUSPECT]-marked citation of a SUSPECT claim is
	// acknowledged past reasoning when the line is byte-identical to the source
	// (kept), but relying on the claim in edited or added text (new) is rejected.
	const sourceBodyById = new Map(snapshot.blocks.map((block) => [block.id, block.body]));
	const splitBody = (body: string): string[] => bodyText(body, snapshot).split(/\r?\n/);
	const keptCitationLines: string[] = [];
	const newCitationLines: string[] = [];
	if (parsed.preamble) newCitationLines.push(...splitBody(parsed.preamble));
	for (const block of parsed.blocks) {
		// Body comparison mirrors the kept check below: marker reconciliation at
		// render keeps source and text consistent, so only the model's own edits
		// land in the new set.
		const kept = sourceBodyById.get(block.id) === block.body;
		(kept ? keptCitationLines : newCitationLines).push(...splitBody(block.body));
	}
	const citationStore = {
		rows: snapshot.claims?.rows ?? [],
		projectRoot: options.projectDir ?? (snapshot.claims?.root ? dirname(snapshot.claims.root) : undefined),
	};
	const citationFailures = [
		...checkCitations(keptCitationLines, citationStore, "kept"),
		...checkCitations(newCitationLines, citationStore, "new"),
	].slice(0, MAX_CITATION_FAILURES);
	if (citationFailures.length > 0) {
		const details = citationFailures.map(
			(failure) =>
				`- ${failure.raw} — ${failure.check} check failed: ${failure.reason}. ` +
				"Reclassify it as ASSUMED: <your inference> or remove the line.",
		);
		return rejected(
			snapshot,
			beforeEstimate,
			`Mirror citation check failed (${citationFailures.length} problem${citationFailures.length === 1 ? "" : "s"}):\n${details.join("\n")}`,
		);
	}
	if (parsed.duplicateIds.length > 0) {
		return rejected(snapshot, beforeEstimate, `Mirror contains duplicate block IDs: ${parsed.duplicateIds.join(", ")}.`);
	}
	if (parsed.malformedCurrentHeaders.length > 0) {
		return rejected(snapshot, beforeEstimate, "Mirror contains malformed headers for the current document.");
	}

	const sourceById = new Map(snapshot.blocks.map((block) => [block.id, block]));
	const parsedById = new Map<string, ParsedBlock>();
	const unknownIds: string[] = [];
	for (const block of parsed.blocks) {
		if (!sourceById.has(block.id) && !(options.editingMode === "clm" && /^new-[a-zA-Z0-9-]+$/.test(block.id))) unknownIds.push(block.id);
		else parsedById.set(block.id, block);
	}
	if (unknownIds.length > 0) {
		return rejected(
			snapshot,
			beforeEstimate,
			`Mirror contains unknown block IDs: ${unknownIds.join(", ")}. ` +
				(options.editingMode === "clm"
					? "Use ids from the current mirror headers, or prefix a new block's id with new-."
					: "Use ids from the current mirror headers."),
		);
	}

	const diagnostics: string[] = [];
	const candidate: LiveContextMessage[] = [];
	const candidateOrigins: Array<{ sourceIndex?: number; kind: ContextEditSourceKind | "added" }> = [];
	const removedSourceIndexes = new Set<number>();
	// Stray text above the first block keeps its written position as a leading note.
	if (parsed.preamble) {
		candidate.push(contextNote(bodyText(parsed.preamble, snapshot)));
		candidateOrigins.push({ kind: "added" });
	}
	// Conservative mode retains source order. CLM follows the edited order;
	// removed originals are still visited for complete provenance/protected restoration.
	const orderedIds = options.editingMode === "clm"
		? [...parsed.blocks.map((block) => block.id), ...snapshot.blocks.filter((block) => !parsedById.has(block.id)).map((block) => block.id)]
		: snapshot.blocks.map((block) => block.id);
	for (const id of orderedIds) {
		const sourceBlock = sourceById.get(id);
		const parsedBlock = parsedById.get(id);
		if (!sourceBlock) {
			if (parsedBlock?.body) {
				candidate.push(contextNote(bodyText(parsedBlock.body, snapshot), undefined, parsedBlock.role));
				candidateOrigins.push({ kind: "added" });
			}
			continue;
		}
		if (sourceBlock.protected) {
			const restored =
				!parsedBlock ||
				parsedBlock.body !== sourceBlock.body ||
				parsedBlock.role !== sourceBlock.role ||
				!parsedBlock.protected;
			candidate.push(sourceBlock.source);
			candidateOrigins.push({ sourceIndex: sourceBlock.index, kind: restored ? "restored" : "kept" });
			if (restored) diagnostics.push(`Restored protected turn ${sourceBlock.index + 1}.`);
			continue;
		}
		if (!parsedBlock || !parsedBlock.body) {
			removedSourceIndexes.add(sourceBlock.index);
			continue;
		}
		if (
			parsedBlock.body === sourceBlock.body &&
			parsedBlock.role === sourceBlock.role &&
			parsedBlock.protected === sourceBlock.protected
		) {
			candidate.push(sourceBlock.source);
			candidateOrigins.push({ sourceIndex: sourceBlock.index, kind: "kept" });
		} else {
			candidate.push(changedMessage(sourceBlock.source, bodyText(parsedBlock.body, snapshot), parsedBlock.role, options.editingMode === "clm"));
			candidateOrigins.push({ sourceIndex: sourceBlock.index, kind: "edited" });
		}
	}

	return finalize(candidate, candidateOrigins, removedSourceIndexes, diagnostics);
}
