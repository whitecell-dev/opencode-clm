/**
 * Phase 1: mirror body for the read-only claims section.
 *
 * One line per claim carries everything Phase 2 citation verification needs: id,
 * version, state, scope, claim text, evidence refs and the approval ref. The body never
 * emits `[[CTX_TURN` / `[[LIVE_CONTEXT` framing lines; structural escaping at render
 * time stays a second line of defence.
 */

import type { ConvergenceClaim } from "./loader.ts";

function oneLine(value: string): string {
	return value.replace(/\s+/g, " ").trim();
}

export function renderClaimRow(claim: ConvergenceClaim): string {
	const scope = JSON.stringify(claim.scope);
	const evidence = claim.evidence_refs.length > 0 ? claim.evidence_refs.join(", ") : "none recorded";
	const approval = claim.approval_ref ?? "none recorded";
	return `- ${claim.id}@${claim.version} [${claim.state}] scope=${scope} :: ${oneLine(claim.claim)} (evidence: ${evidence}; approval: ${approval})`;
}

/** Mirror body for the claims block: header, rows, and the read-only rule. */
export function renderClaimsBody(claims: readonly ConvergenceClaim[], error?: string): string {
	const head =
		"## CLAIMS (read-only): project-authorized claims. Cite a claim with a whole line `OBSERVED: <id>@<version>`; " +
		"cite a file with `OBSERVED: <file>:<line>`; mark your own inference `ASSUMED: <text>`. " +
		"Do not rewrite this section; any edit touching it is refused.";
	if (error) return `${head}\n- claims store error: ${oneLine(error)}`;
	if (claims.length === 0) return `${head}\n- No ACTIVE claims.`;
	return `${head}\n${claims.map(renderClaimRow).join("\n")}`;
}
