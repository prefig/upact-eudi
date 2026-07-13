// SPDX-License-Identifier: Apache-2.0
/**
 * Claims mapper — pure function, allow-list-based (pattern:
 * upact-oidc/src/claims-mapper.ts).
 *
 * Reads only: vct, issuer, expiry, and the presentation tag of each verified
 * presentation. Explicitly does NOT read PID attributes: the response side
 * already dropped everything outside the declared set, and this mapper does
 * not place even the declared boolean predicates on the Upactor — how
 * predicates surface (capability-style booleans or app-level pairing) is
 * U4's decision. Privacy-stripping is enforced by construction (allow-list),
 * not by deletion (SPEC §7).
 *
 * Identity stability (interim, pending U4): `Upactor.id` is derived from
 * the issuer and the presentation tag (the KB-JWT's sd_hash), so it is
 * opaque, non-reversible, and unique per presentation. German PIDs disclose
 * no stable identifier by default, so cross-session stability is NOT
 * promised in this build; equal ids mean the same presentation, nothing
 * more. U4 settles the stability semantics with real sandbox presentations
 * in hand and documents them in docs/identity-stability.md.
 */

import { createHash } from 'node:crypto';
import type { Upactor } from '@prefig/upact';
import type { VerifiedPresentation } from './response.js';

/**
 * Maps the verified presentations of one wallet response to an Upactor.
 *
 * - `id`: sha256 over substrate, issuers, and presentation tags — opaque,
 *   derived, per-presentation (see the module note on stability).
 * - `capabilities`: empty. An EUDI presentation carries neither an email
 *   channel nor an account-recovery path in the v0.1 vocabulary.
 * - `lifecycle`: expires with the earliest credential expiry;
 *   `renewable: 'reauth'` — EUDI renewal is re-presentation.
 * - `provenance`: `{ substrate: 'eudi', instance: <issuer> }` (SPEC §4.4).
 * - No display_hint: everything human-readable in a PID is PII.
 */
export function mapPresentationsToUpactor(
	presentations: readonly VerifiedPresentation[],
): Upactor {
	if (presentations.length === 0) {
		throw new Error('upact-eudi: cannot map an empty set of verified presentations');
	}

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

function deriveId(presentations: readonly VerifiedPresentation[]): string {
	const hash = createHash('sha256');
	hash.update('eudi');
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
