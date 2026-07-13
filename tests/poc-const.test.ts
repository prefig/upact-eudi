// SPDX-License-Identifier: Apache-2.0
/**
 * Regression: exported registries are immutable at runtime.
 *
 * KNOWN_CREDENTIAL_TYPES is typed ReadonlySet but is also enforced immutable
 * at runtime, so in-process code cannot widen the credential-type guard and
 * make freezeAttributePolicy accept a type it should reject.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
	KNOWN_CREDENTIAL_TYPES,
	ALLOWED_CLAIM_PATHS,
	freezeAttributePolicy,
} from '../src/index.js';
import type { EudiConfig } from '../src/index.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const ACCESS_CERTIFICATE = readFileSync(join(FIXTURES, 'access-certificate.pem'), 'utf8');
const ACCESS_CERTIFICATE_KEY = readFileSync(join(FIXTURES, 'access-certificate.key.pem'), 'utf8');
const TRUST_ANCHOR_PEM = readFileSync(join(FIXTURES, 'pid-root-ca.pem'), 'utf8');

function cfg(declaredAttributes: EudiConfig['declaredAttributes']): EudiConfig {
	return {
		declaredAttributes,
		audience: 'https://rp.example',
		accessCertificate: ACCESS_CERTIFICATE,
		accessCertificateKey: ACCESS_CERTIFICATE_KEY,
		registrationCertificate: 'S',
		endpoints: { baseUrl: 'https://rp.example/oid4vp' },
		trustAnchors: [{ certificate: TRUST_ANCHOR_PEM }],
	};
}

describe('regression: exported constants are immutable', () => {
	it('KNOWN_CREDENTIAL_TYPES cannot be widened via add/delete/clear', () => {
		expect(() => (KNOWN_CREDENTIAL_TYPES as Set<string>).add('urn:evil:x:1')).toThrow(TypeError);
		expect(() => (KNOWN_CREDENTIAL_TYPES as Set<string>).delete('urn:eudi:pid:de:1')).toThrow(
			TypeError,
		);
		expect(() => (KNOWN_CREDENTIAL_TYPES as Set<string>).clear()).toThrow(TypeError);
		// The registry still contains only its intended type, and rejects others.
		expect(KNOWN_CREDENTIAL_TYPES.has('urn:eudi:pid:de:1')).toBe(true);
		expect(KNOWN_CREDENTIAL_TYPES.has('urn:evil:x:1')).toBe(false);
		expect(() =>
			freezeAttributePolicy(cfg([{ format: 'dc+sd-jwt', vct: 'urn:evil:x:1', claims: [] }])),
		).toThrow(/unknown credential type/);
	});

	it('ALLOWED_CLAIM_PATHS is frozen (cannot push)', () => {
		expect(() => (ALLOWED_CLAIM_PATHS as unknown[]).push(['given_name'])).toThrow(TypeError);
	});
});
