// SPDX-License-Identifier: Apache-2.0
/**
 * EUDI declared-attribute policy — construction-time guard.
 *
 * Generalises upact-oidc's scope-policy: where OIDC has fixed
 * FORBIDDEN/ALLOWED scope sets, this module takes the relying party's
 * registered attribute list (the same list filed with the registrar per
 * CIR (EU) 2025/848 Art. 5(1)) as configuration, validates it against the
 * upact privacy minima (SPEC §7), and freezes it. The DCQL builder may only
 * read the frozen policy, so the registrable declaration and the runtime
 * request are one artifact: it is impossible to request an attribute the
 * configuration does not declare.
 *
 * Privacy-load-bearing: PID attributes that identify the holder (name,
 * birthdate, address, ...) can never surface on an Upactor (SPEC §7.1), so
 * declaring them would only put PII in the adapter's hands with no port to
 * deliver it through. They are rejected at construction, before any network
 * activity. What remains declarable are boolean predicates
 * (`age_equal_or_over/<threshold>`) and possession-only declarations.
 */

import type { AttributeDeclaration, ClaimPath, EudiConfig } from './types.js';

/**
 * Credential types this adapter knows how to request and verify.
 * v0.1: the German PID (SD-JWT VC) per the BMI developer guide. The
 * registry extends when concrete consumers surface, mirroring upact's
 * capability-vocabulary discipline (SPEC §5.1).
 */
export const KNOWN_CREDENTIAL_TYPES: ReadonlySet<string> = new Set([
	'urn:eudi:pid:de:1',
]);

/**
 * German PID claims that carry upact SPEC §7.1 / §7.3 fields: legal names,
 * date-of-birth fields, contact identifiers, correlation handles. Declaring
 * them throws with the SPEC clause. Keyed by the first path segment, so
 * nested paths (e.g. `address/locality`) are caught at the root.
 */
const FORBIDDEN_CLAIMS: ReadonlyMap<string, string> = new Map([
	['given_name', 'legal-name field (SPEC §7.1)'],
	['family_name', 'legal-name field (SPEC §7.1)'],
	['given_name_birth', 'legal-name field (SPEC §7.1)'],
	['family_name_birth', 'legal-name field (SPEC §7.1)'],
	['birth_family_name', 'legal-name field (SPEC §7.1)'],
	['birthdate', 'date-of-birth field (SPEC §7.1)'],
	['age_birth_year', 'date-of-birth field (SPEC §7.1)'],
	['place_of_birth', 'birth-record field (SPEC §7.1)'],
	['address', 'address field (SPEC §7.1)'],
	['nationalities', 'identifying attribute (SPEC §7.1)'],
	['email', 'contact identifier (SPEC §7.1)'],
	['phone_number', 'contact identifier (SPEC §7.1)'],
	['personal_administrative_number', 'correlation handle (SPEC §7.3)'],
	['portrait', 'biometric identifier (SPEC §7.1)'],
]);

/**
 * Claim paths a relying party may declare, beyond possession-only.
 * Boolean predicates only: they surface as capability-style booleans, never
 * as PII (plan decision 4; upact SPEC §7). Thresholds follow the EU PID
 * rulebook's `age_equal_or_over` sub-claims.
 */
export const ALLOWED_CLAIM_PATHS: readonly ClaimPath[] = Object.freeze(
	['12', '14', '16', '18', '21', '65'].map((threshold) =>
		Object.freeze(['age_equal_or_over', threshold]),
	),
);

/**
 * The validated, deep-frozen attribute policy. Everything downstream (the
 * DCQL builder in U2, the claims mapper in U3) reads this and only this.
 */
export interface AttributePolicy {
	/** The verifier identity presentations are addressed to. */
	readonly audience: string;
	/** The declared credentials, deep-frozen copies of the config input. */
	readonly declarations: readonly Readonly<AttributeDeclaration>[];
}

function formatPath(path: ClaimPath): string {
	return path.join('/');
}

function canonical(path: ClaimPath): string {
	return JSON.stringify(path);
}

const ALLOWED_CANONICAL: ReadonlySet<string> = new Set(
	ALLOWED_CLAIM_PATHS.map(canonical),
);

function validateClaimPath(path: ClaimPath, vct: string): void {
	if (!Array.isArray(path) || path.length === 0 || path.some((segment) => typeof segment !== 'string' || segment.length === 0)) {
		throw new Error(
			`upact attribute policy: malformed claim path ${JSON.stringify(path)} ` +
				`declared for '${vct}'. A claim path is a non-empty array of non-empty strings, ` +
				`e.g. ['age_equal_or_over', '18'].`,
		);
	}
	const forbidden = FORBIDDEN_CLAIMS.get(path[0]);
	if (forbidden !== undefined) {
		throw new Error(
			`upact attribute policy violation (SPEC §7): claim path '${formatPath(path)}' ` +
				`declared for '${vct}' is forbidden: ${forbidden}. ` +
				`Such fields MUST NOT surface at the port, so declaring them only puts PII ` +
				`in the adapter's hands with no port to deliver it through. ` +
				`Declarable claim paths: ${ALLOWED_CLAIM_PATHS.map(formatPath).join(', ')}, or none (possession-only).`,
		);
	}
	if (!ALLOWED_CANONICAL.has(canonical(path))) {
		throw new Error(
			`upact attribute policy: claim path '${formatPath(path)}' declared for '${vct}' ` +
				`is not in the allow-list. The declared attribute list mirrors the registrar ` +
				`filing (CIR (EU) 2025/848 Art. 5(1)) and only boolean predicates are declarable. ` +
				`Declarable claim paths: ${ALLOWED_CLAIM_PATHS.map(formatPath).join(', ')}, or none (possession-only).`,
		);
	}
}

function validateDeclaration(declaration: AttributeDeclaration): void {
	if (declaration.format !== 'dc+sd-jwt') {
		throw new Error(
			`upact attribute policy: unsupported credential format '${String(declaration.format)}'. ` +
				`v0.1 supports 'dc+sd-jwt' (SD-JWT VC) only; mdoc is deferred.`,
		);
	}
	if (typeof declaration.vct !== 'string' || declaration.vct.length === 0) {
		throw new Error(`upact attribute policy: declaration is missing a credential type (vct).`);
	}
	if (!KNOWN_CREDENTIAL_TYPES.has(declaration.vct)) {
		throw new Error(
			`upact attribute policy: unknown credential type '${declaration.vct}'. ` +
				`Known types: ${[...KNOWN_CREDENTIAL_TYPES].join(', ')}.`,
		);
	}
	if (!Array.isArray(declaration.claims)) {
		throw new Error(
			`upact attribute policy: declaration for '${declaration.vct}' has no claims array. ` +
				`Use an empty array for a possession-only declaration.`,
		);
	}
	for (const path of declaration.claims) {
		validateClaimPath(path, declaration.vct);
	}
}

/**
 * Validates the declared attribute surface and returns a deep-frozen policy.
 *
 * Called at adapter construction time, before any network request. Throws a
 * descriptive error naming the offending path and the SPEC clause on any
 * undeclarable input. The returned policy is a frozen copy: later mutation
 * of the caller's config object cannot reach it.
 */
export function freezeAttributePolicy(
	config: Pick<EudiConfig, 'declaredAttributes' | 'audience'>,
): AttributePolicy {
	if (typeof config.audience !== 'string' || config.audience.length === 0) {
		throw new Error(
			`upact attribute policy: 'audience' must be a non-empty string (the verifier ` +
				`identity presentations are addressed to, e.g. the relying party's origin).`,
		);
	}
	if (!Array.isArray(config.declaredAttributes) || config.declaredAttributes.length === 0) {
		throw new Error(
			`upact attribute policy: 'declaredAttributes' declares no credentials. ` +
				`A relying party without a declared attribute list has nothing it may request ` +
				`(CIR (EU) 2025/848 Art. 5(1)); declare at least one credential type, ` +
				`possession-only if no claims are needed.`,
		);
	}
	const declared: readonly AttributeDeclaration[] = config.declaredAttributes;
	for (const declaration of declared) {
		validateDeclaration(declaration);
	}
	// Deep-frozen copy — the caller's config stays untouched, and no later
	// mutation of it can reach the policy the DCQL builder reads.
	const declarations = Object.freeze(
		declared.map((declaration) =>
			Object.freeze({
				format: declaration.format,
				vct: declaration.vct,
				claims: Object.freeze(
					declaration.claims.map((path) => Object.freeze([...path])),
				),
			}),
		),
	);
	return Object.freeze({ audience: config.audience, declarations });
}

/**
 * True when the policy declares `path` for credential type `vct`.
 * The U3 claims mapper uses this to drop over-disclosed claims: anything a
 * wallet shares beyond the declaration is discarded before mapping.
 */
export function isDeclaredClaim(
	policy: AttributePolicy,
	vct: string,
	path: ClaimPath,
): boolean {
	const wanted = canonical(path);
	return policy.declarations.some(
		(declaration) =>
			declaration.vct === vct &&
			declaration.claims.some((declared) => canonical(declared) === wanted),
	);
}
