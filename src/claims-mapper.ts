// SPDX-License-Identifier: Apache-2.0
/**
 * Claims mapper — pure function, allow-list-based (pattern:
 * upact-oidc/src/claims-mapper.ts).
 *
 * Reads only: vct, issuer, expiry, nonce, presentation tag, and the declared
 * boolean predicates of each verified presentation. Privacy-stripping is
 * enforced by construction (allow-list), not by deletion (SPEC §7): the
 * response side already dropped everything outside the declared set, and
 * this mapper places no claim value of any kind on the Upactor.
 *
 * Identity stability (U4 decision, docs/identity-stability.md): `Upactor.id`
 * is per-authentication. It is derived from the single-use transaction nonce
 * plus each presentation's issuer and KB-JWT sd_hash, so it is opaque,
 * non-reversible (SPEC §7.3), and never repeats across authenticate() calls,
 * even when a wallet re-presents the identical stored credential. Equal ids
 * mean the same successful authentication, nothing more; cross-session
 * recognition is deliberately not offered. Applications that need a
 * returning identity pair at the application level (EUDI proves eligibility
 * once, the app issues its own credential).
 *
 * Declared predicates (plan decision 4, resolved here): a declared predicate
 * is a requirement. Every declared predicate must have been disclosed as
 * `true`; a `false` predicate throws PredicateNotSatisfiedError, which
 * authenticate() normalises to `credential_rejected`. A successful
 * authenticate() therefore attests every declared predicate, and no boolean
 * ever rides on the Upactor (SPEC §7.2 forbids fields beyond the spec, and
 * the v0.1 capability vocabulary carries no predicate entries).
 */

import { createHash } from 'node:crypto';
import type { Upactor } from '@prefig/upact';
import { PredicateNotSatisfiedError } from './response.js';
import type { VerifiedPresentation } from './response.js';

/**
 * Maps the verified presentations of one wallet response to an Upactor.
 *
 * - `id`: sha256 over substrate, transaction nonce, issuers, and
 *   presentation tags — opaque, derived, per-authentication (see the module
 *   note on stability).
 * - `capabilities`: empty. An EUDI presentation carries neither an email
 *   channel nor an account-recovery path in the v0.1 vocabulary.
 * - `lifecycle`: expires with the earliest credential expiry;
 *   `renewable: 'reauth'` — EUDI renewal is re-presentation.
 * - `provenance`: `{ substrate: 'eudi', instance: <issuer> }` (SPEC §4.4).
 * - No display_hint: everything human-readable in a PID is PII.
 *
 * Throws PredicateNotSatisfiedError when any declared predicate was
 * disclosed as `false` (→ `credential_rejected` at the port).
 */
export function mapPresentationsToUpactor(
	presentations: readonly VerifiedPresentation[],
): Upactor {
	if (presentations.length === 0) {
		throw new Error('upact-eudi: cannot map an empty set of verified presentations');
	}

	requirePredicatesSatisfied(presentations);

	const id = deriveId(presentations);
	const expiresAt = earliestExpiry(presentations);
	const instance = presentations[0].issuer;

	return {
		id,
		capabilities: new Set(),
		lifecycle: {
			...(expiresAt !== undefined ? { expires_at: expiresAt } : {}),
			renewable: 'reauth',
		},
		provenance: {
			substrate: 'eudi',
			...(instance !== undefined ? { instance } : {}),
		},
	};
}

/**
 * A declared predicate is a requirement: `false` means the presentation is
 * authentic but the holder does not meet the declared eligibility bar.
 * Branch-on-value predicates are not supported; they would land as a port
 * extension when a consumer needs them (docs/identity-stability.md).
 */
function requirePredicatesSatisfied(presentations: readonly VerifiedPresentation[]): void {
	for (const presentation of presentations) {
		for (const [path, value] of presentation.declaredClaims) {
			if (value !== true) {
				throw new PredicateNotSatisfiedError(
					`upact-eudi: declared predicate '${path}' for '${presentation.vct}' ` +
						`was disclosed as false; the presentation does not meet the declared eligibility bar`,
				);
			}
		}
	}
}

function deriveId(presentations: readonly VerifiedPresentation[]): string {
	const hash = createHash('sha256');
	hash.update('eudi');
	// The single-use transaction nonce: verifier-generated entropy that makes
	// the id per-authentication. Without it, a wallet re-presenting the same
	// stored credential would reproduce the sd_hash and hand the application
	// an unearned cross-visit correlation handle (SPEC §7.3).
	hash.update('\n');
	hash.update(presentations[0].nonce);
	for (const presentation of presentations) {
		hash.update('\n');
		hash.update(presentation.issuer ?? '');
		hash.update('#');
		hash.update(presentation.presentationTag);
	}
	return hash.digest('hex').slice(0, 32);
}

function earliestExpiry(presentations: readonly VerifiedPresentation[]): Date | undefined {
	let earliest: Date | undefined;
	for (const presentation of presentations) {
		if (presentation.expiresAt === undefined) continue;
		if (earliest === undefined || presentation.expiresAt < earliest) {
			earliest = presentation.expiresAt;
		}
	}
	return earliest;
}
