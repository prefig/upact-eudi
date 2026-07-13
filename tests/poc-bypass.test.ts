// SPDX-License-Identifier: Apache-2.0
/**
 * Regression: getter/Proxy TOCTOU on the declared-attribute config.
 *
 * freezeAttributePolicy must read each config property exactly once and build
 * the frozen policy from that single captured value. An accessor-backed config
 * that returns a benign value during validation and a malicious value on a
 * later read must NOT be able to land undeclared/forbidden attributes in the
 * frozen policy (and thus in the DCQL request).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
	freezeAttributePolicy,
	buildDcqlQuery,
	isDeclaredClaim,
} from '../src/index.js';
import type { EudiConfig, AttributeDeclaration } from '../src/index.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const ACCESS_CERTIFICATE = readFileSync(join(FIXTURES, 'access-certificate.pem'), 'utf8');
const ACCESS_CERTIFICATE_KEY = readFileSync(join(FIXTURES, 'access-certificate.key.pem'), 'utf8');
const TRUST_ANCHOR_PEM = readFileSync(join(FIXTURES, 'pid-root-ca.pem'), 'utf8');

function baseConfig(declaredAttributes: readonly AttributeDeclaration[]): EudiConfig {
	return {
		declaredAttributes,
		audience: 'https://rp.example',
		accessCertificate: ACCESS_CERTIFICATE,
		accessCertificateKey: ACCESS_CERTIFICATE_KEY,
		registrationCertificate: 'SENTINEL',
		endpoints: { baseUrl: 'https://rp.example/oid4vp' },
		trustAnchors: [{ certificate: TRUST_ANCHOR_PEM, name: 'mock root' }],
	};
}

describe('regression: getter-based TOCTOU on declaration.claims', () => {
	it('a counting getter on claims cannot widen the frozen policy past validation', () => {
		// Benign on the first reads, forbidden PII on any later read.
		const benign: ReadonlyArray<readonly string[]> = [['age_over_18']];
		const malicious: ReadonlyArray<readonly string[]> = [
			['given_name'],
			['address', 'locality'],
			['birthdate'],
		];
		let reads = 0;
		const declaration = {
			format: 'dc+sd-jwt' as const,
			vct: 'urn:eudi:pid:de:1',
			get claims() {
				reads += 1;
				return reads >= 2 ? malicious : benign;
			},
		};

		const policy = freezeAttributePolicy(baseConfig([declaration]));

		// claims must be read exactly once; the benign value is what is frozen.
		expect(reads).toBe(1);
		expect(policy.declarations[0].claims.map((p) => p.join('/'))).toEqual(['age_over_18']);
		expect(isDeclaredClaim(policy, 'urn:eudi:pid:de:1', ['given_name'])).toBe(false);
		expect(isDeclaredClaim(policy, 'urn:eudi:pid:de:1', ['address', 'locality'])).toBe(false);

		const dcql = buildDcqlQuery(policy);
		const requestedPaths = dcql.credentials[0].claims?.map((c) => c.path.join('/')) ?? [];
		expect(requestedPaths).toEqual(['age_over_18']);
		expect(requestedPaths).not.toContain('given_name');
		expect(requestedPaths).not.toContain('address/locality');
	});

	it('a counting getter on vct cannot swap in an unknown credential type', () => {
		let vctReads = 0;
		const declaration = {
			format: 'dc+sd-jwt' as const,
			get vct() {
				vctReads += 1;
				return vctReads >= 2 ? 'urn:evil:unknown:1' : 'urn:eudi:pid:de:1';
			},
			claims: [['age_over_18']] as ReadonlyArray<readonly string[]>,
		};
		const policy = freezeAttributePolicy(baseConfig([declaration]));
		expect(vctReads).toBe(1);
		expect(policy.declarations[0].vct).toBe('urn:eudi:pid:de:1');
	});
});
