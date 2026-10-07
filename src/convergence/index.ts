/** Phase 1 read-only Convergence integration: loader, scope policy, mirror render. */
export { loadConvergenceStore, type ClaimState, type ConvergenceClaim, type ConvergenceLoad } from "./loader.ts";
export { SCOPE_POLICY, selectActiveClaims } from "./scope.ts";
export { SCOPE_MATCH_RULE, isClaimInScope } from "./scope.ts";
export {
	CLAIM_CITATION_RE,
	FILE_CITATION_RE,
	MAX_CITATION_FAILURES,
	SUSPECT_MARKER,
	checkCitations,
	parseCitationLine,
	projectRootFor,
	type CitationFailure,
	type CitationProvenance,
	type CitationStore,
	type ParsedCitation,
} from "./citations.ts";
export { diffClaimStates, markUntrustedTransitions, reconcileSuspectMarkers, UNTRUSTED_TOUCH_WINDOW_MS, type ClaimTransition, type FlaggedTransition, type MarkerReconciliation } from "./suspect.ts";
export {
	canonicalStoreRoot,
	classifyConvergenceWrite,
	commandBases,
	extractBashWriteTargets,
	mentionsStore,
	resolveToolPath,
	resolvesIntoStore,
	touchesConvergenceStore,
	type ConvergenceWriteVerdict,
} from "./guard.ts";
export { renderClaimRow, renderClaimsBody } from "./render.ts";
