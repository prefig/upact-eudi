// SPDX-License-Identifier: Apache-2.0
/**
 * U3 — claims mapper: verified presentations → Upactor.
 *
 * The mapper is allow-list-based: it reads vct, issuer, expiry, and the
 * presentation tag, and nothing else. These tests pin the privacy minima
 * (SPEC §7): opaque derived id, no PII on any enumerable path, lifecycle
 * from credential validity with renewable 'reauth', provenance
 * { substrate: 'eudi', instance: issuer }, and — pending U4 — no claim
 * values of any kind on the Upactor, declared or not.
 *
 * Also covers filterToDeclaredClaims, the pre-mapper gate that drops
 * over-disclosure and rejects under-disclosure.
 */

import { describe, it, expect } from 'vitest';
import { mapPresentationsToUpactor } from '../src/claims-mapper.js';
import { filterToDeclaredClaims, ResponseInvalidError } from '../src/response.js';
import type { VerifiedPresentation } from '../src/response.js';

function presentation(overrides: Partial<VerifiedPresentation> = {}): VerifiedPresentation {
	return {
		vct: 'urn:eudi:pid:de:1',
		issuer: 'https://pid-issuer.test.example',
		expiresAt: new Date('2026-08-01T00:00:00Z'),
		presentationTag: 'tag-abc123',
		declaredClaims: new Map([['age_equal_or_over/18', true]]),
		...overrides,
	};
}

describe('mapPresentationsToUpactor', () => {
	it('derives an opaque 32-hex id that does not embed issuer or tag', () => {
		const upactor = mapPresentationsToUpactor([presentation()]);
		expect(upactor.id).toMatch(/^[0-9a-f]{32}$/);
		expect(upactor.id).not.toContain('pid-issuer');
		expect(upactor.id).not.toContain('tag-abc123');
	});

	it('is deterministic per presentation and differs across presentations', () => {
		const a = mapPresentationsToUpactor([presentation()]);
		const b = mapPresentationsToUpactor([presentation()]);
		const c = mapPresentationsToUpactor([presentation({ presentationTag: 'tag-other' })]);
		// Documented interim semantics: equal ids mean the same presentation.
		expect(a.id).toBe(b.id);
		expect(c.id).not.toBe(a.id);
	});

	it('ids differ across issuers even with equal tags', () => {
		const a = mapPresentationsToUpactor([presentation({ issuer: 'https://a.example' })]);
		const b = mapPresentationsToUpactor([presentation({ issuer: 'https://b.example' })]);
		expect(a.id).not.toBe(b.id);
	});

	it('lifecycle carries the credential expiry with renewable reauth', () => {
		const upactor = mapPresentationsToUpactor([presentation()]);
		expect(upactor.lifecycle).toEqual({
			expires_at: new Date('2026-08-01T00:00:00Z'),
			renewable: 'reauth',
		});
	});

	it('lifecycle without a credential expiry still declares reauth', () => {
		const noExpiry = presentation();
		const { expiresAt: _dropped, ...rest } = noExpiry;
		const upactor = mapPresentationsToUpactor([rest as VerifiedPresentation]);
		expect(upactor.lifecycle).toEqual({ renewable: 'reauth' });
	});

	it('multiple presentations map to one Upactor with the earliest expiry', () => {
		const upactor = mapPresentationsToUpactor([
			presentation({ expiresAt: new Date('2026-09-01T00:00:00Z') }),
			presentation({ presentationTag: 'tag-2', expiresAt: new Date('2026-07-20T00:00:00Z') }),
		]);
		expect(upactor.lifecycle?.expires_at).toEqual(new Date('2026-07-20T00:00:00Z'));
	});

	it('provenance names the substrate and the issuer instance (SPEC §4.4)', () => {
		const upactor = mapPresentationsToUpactor([presentation()]);
		expect(upactor.provenance).toEqual({
			substrate: 'eudi',
			instance: 'https://pid-issuer.test.example',
		});
	});

	it('provenance omits instance when the credential names no issuer', () => {
		const noIssuer = presentation();
		const { issuer: _dropped, ...rest } = noIssuer;
		const upactor = mapPresentationsToUpactor([rest as VerifiedPresentation]);
		expect(upactor.provenance).toEqual({ substrate: 'eudi' });
	});

	it('capabilities are empty: EUDI offers neither email nor recovery', () => {
		const upactor = mapPresentationsToUpactor([presentation()]);
		expect(upactor.capabilities.size).toBe(0);
	});

	it('sets no display_hint: everything human-readable in a PID is PII', () => {
		const upactor = mapPresentationsToUpactor([presentation()]);
		expect(upactor.display_hint).toBeUndefined();
	});

	it('places no claim values on the Upactor, declared or not (pending U4)', () => {
		const upactor = mapPresentationsToUpactor([
			presentation({
				declaredClaims: new Map([
					['age_equal_or_over/18', true],
					['age_equal_or_over/65', false],
				]),
			}),
		]);
		const serialized = JSON.stringify(upactor);
		expect(serialized).not.toContain('age_equal_or_over');
		expect(Object.keys(upactor).sort()).toEqual(['capabilities', 'id', 'lifecycle', 'provenance']);
	});

	it('throws on an empty presentation set', () => {
		expect(() => mapPresentationsToUpactor([])).toThrow(/empty/);
	});
});

describe('filterToDeclaredClaims — the pre-mapper gate', () => {
	const declaration = {
		format: 'dc+sd-jwt' as const,
		vct: 'urn:eudi:pid:de:1',
		claims: [['age_equal_or_over', '18']] as const,
	};

	it('keeps exactly the declared claims', () => {
		const declared = filterToDeclaredClaims(declaration, {
			age_equal_or_over: { '18': true, '21': true },
			given_name: 'ERIKA',
			birthdate: '1984-01-26',
		});
		expect([...declared.entries()]).toEqual([['age_equal_or_over/18', true]]);
	});

	it('over-disclosed claims are absent from the mapper input', () => {
		const declared = filterToDeclaredClaims(declaration, {
			age_equal_or_over: { '18': false },
			personal_administrative_number: 'DE-PII-SENTINEL-0001',
			address: { locality: 'BERLIN-SENTINEL' },
		});
		expect(declared.size).toBe(1);
		expect(declared.get('age_equal_or_over/18')).toBe(false);
		const serialized = JSON.stringify([...declared.entries()]);
		expect(serialized).not.toContain('SENTINEL');
		expect(serialized).not.toContain('address');
	});

	it('a missing declared claim throws (verify under-request)', () => {
		expect(() => filterToDeclaredClaims(declaration, { age_equal_or_over: {} })).toThrow(
			ResponseInvalidError,
		);
		expect(() => filterToDeclaredClaims(declaration, {})).toThrow(/did not disclose/);
	});

	it('a non-boolean value for a declared predicate throws', () => {
		expect(() =>
			filterToDeclaredClaims(declaration, { age_equal_or_over: { '18': 'yes' } }),
		).toThrow(/boolean/);
	});

	it('a possession-only declaration filters to an empty map', () => {
		const possessionOnly = { ...declaration, claims: [] as const };
		const declared = filterToDeclaredClaims(possessionOnly, {
			given_name: 'ERIKA',
			age_equal_or_over: { '18': true },
		});
		expect(declared.size).toBe(0);
	});
});
