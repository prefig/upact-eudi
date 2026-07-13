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
/**
 * Builds a genuinely immutable Set: the mutating methods throw, so the
 * `ReadonlySet` type annotation is enforced at runtime and not merely at
 * compile time. Any in-process `.add()`/`.delete()`/`.clear()` on the
 * exported registry throws rather than silently widening the credential-type
 * guard.
 */
function freezeReadonlySet<T>(values: readonly T[]): ReadonlySet<T> {
	const set = new Set(values);
	const block = (): never => {
		throw new TypeError(
			'upact-eudi: KNOWN_CREDENTIAL_TYPES is an immutable registry and cannot be mutated at runtime',
		);
	};
	Object.defineProperties(set, {
		add: { value: block, writable: false, configurable: false },
		delete: { value: block, writable: false, configurable: false },
		clear: { value: block, writable: false, configurable: false },
	});
	return Object.freeze(set) as ReadonlySet<T>;
}

export const KNOWN_CREDENTIAL_TYPES: ReadonlySet<string> = freezeReadonlySet([
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
 * as PII (plan decision 4; upact SPEC §7). Two spellings of the same
 * predicate family are declarable: the EU PID rulebook's nested
 * `age_equal_or_over/<threshold>` sub-claims, and the flat
 * `age_over_<threshold>` form the BMI Erica simulator's PID template
 * discloses (the vocabulary the U5 end-to-end harness meets in practice).
 */
const AGE_THRESHOLDS: readonly string[] = ['12', '14', '16', '18', '21', '65'];

export const ALLOWED_CLAIM_PATHS: readonly ClaimPath[] = Object.freeze([
	...AGE_THRESHOLDS.map((threshold) => Object.freeze(['age_equal_or_over', threshold])),
	...AGE_THRESHOLDS.map((threshold) => Object.freeze([`age_over_${threshold}`])),
]);

/**
 * The validated, deep-frozen attribute policy. Everything downstream (the
 * DCQL builder in U2, the claims mapper in U3) reads this and only this.
 */
export interface AttributePolicy {
	/**
	 * The relying party's configured verifier identity, validated non-empty at
	 * construction (part of the registrable declaration). Note: the audience a
	 * wallet actually addresses a presentation to is the OpenID4VP `client_id`
	 * (`x509_hash:...`, derived from the access certificate), and the KB-JWT
	 * `aud` is checked against that client_id, not against this string. This
	 * field is retained for declaration/registration parity; it is not itself
	 * the enforced presentation audience.
	 */
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

/**
 * Validates one declaration and returns its deep-frozen copy in a single
 * pass. Every config property is read exactly once into a local, and both
 * validation and the frozen artifact are built from that captured value, so a
 * getter- or Proxy-backed config cannot vary a value between the validation
 * read and the freeze-copy read (a TOCTOU that would otherwise let a benign
 * value pass validation while a forbidden value lands in the frozen policy).
 */
function freezeDeclaration(input: AttributeDeclaration): Readonly<AttributeDeclaration> {
	// Capture each property once; never re-read `input` after this point.
	const format = input.format;
	const vct = input.vct;
	const claimsInput = input.claims;

	if (format !== 'dc+sd-jwt') {
		throw new Error(
			`upact attribute policy: unsupported credential format '${String(format)}'. ` +
				`v0.1 supports 'dc+sd-jwt' (SD-JWT VC) only; mdoc is deferred.`,
		);
	}
	if (typeof vct !== 'string' || vct.length === 0) {
		throw new Error(`upact attribute policy: declaration is missing a credential type (vct).`);
	}
	if (!KNOWN_CREDENTIAL_TYPES.has(vct)) {
		throw new Error(
			`upact attribute policy: unknown credential type '${vct}'. ` +
				`Known types: ${[...KNOWN_CREDENTIAL_TYPES].join(', ')}.`,
		);
	}
	if (!Array.isArray(claimsInput)) {
		throw new Error(
			`upact attribute policy: declaration for '${vct}' has no claims array. ` +
				`Use an empty array for a possession-only declaration.`,
		);
	}

	// Dense own-property snapshot: read each claim path once, validate the
	// captured snapshot, and freeze the same snapshot. Skipping non-own
	// indices also means prototype-pollution of a sparse hole cannot inject an
	// undeclared path.
	const claims: ClaimPath[] = [];
	for (let i = 0; i < claimsInput.length; i++) {
		if (!Object.prototype.hasOwnProperty.call(claimsInput, i)) continue;
		const rawPath = claimsInput[i];
		const path: ClaimPath = Array.isArray(rawPath)
			? rawPath.map((segment) => segment)
			: (rawPath as ClaimPath);
		validateClaimPath(path, vct);
		claims.push(Object.freeze(path));
	}
	return Object.freeze({ format, vct, claims: Object.freeze(claims) });
}

/**
 * Validates the declared attribute surface and returns a deep-frozen policy.
 *
 * Called at adapter construction time, before any network request. Throws a
 * descriptive error naming the offending path and the SPEC clause on any
 * undeclarable input. The returned policy is a frozen copy built from a
 * single read of each config property (see `freezeDeclaration`): later
 * mutation, accessor tricks, or prototype pollution of the caller's config
 * object cannot reach it.
 */
export function freezeAttributePolicy(
	config: Pick<EudiConfig, 'declaredAttributes' | 'audience'>,
): AttributePolicy {
	const audience = config.audience;
	if (typeof audience !== 'string' || audience.length === 0) {
		throw new Error(
			`upact attribute policy: 'audience' must be a non-empty string (the verifier ` +
				`identity presentations are addressed to, e.g. the relying party's origin).`,
		);
	}
	const declaredInput = config.declaredAttributes;
	if (!Array.isArray(declaredInput) || declaredInput.length === 0) {
		throw new Error(
			`upact attribute policy: 'declaredAttributes' declares no credentials. ` +
				`A relying party without a declared attribute list has nothing it may request ` +
				`(CIR (EU) 2025/848 Art. 5(1)); declare at least one credential type, ` +
				`possession-only if no claims are needed.`,
		);
	}
	// Dense own-property snapshot, validated and frozen in one pass — no
	// second read of the caller's array, so accessors and prototype-pollution
	// of sparse holes cannot inject a declaration the validator never saw.
	const declarations: Readonly<AttributeDeclaration>[] = [];
	for (let index = 0; index < declaredInput.length; index++) {
		if (!Object.prototype.hasOwnProperty.call(declaredInput, index)) continue;
		declarations.push(freezeDeclaration(declaredInput[index]));
	}
	if (declarations.length === 0) {
		throw new Error(
			`upact attribute policy: 'declaredAttributes' declares no credentials. ` +
				`A relying party without a declared attribute list has nothing it may request ` +
				`(CIR (EU) 2025/848 Art. 5(1)); declare at least one credential type, ` +
				`possession-only if no claims are needed.`,
		);
	}
	return Object.freeze({ audience, declarations: Object.freeze(declarations) });
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
