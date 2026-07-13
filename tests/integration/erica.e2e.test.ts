// SPDX-License-Identifier: Apache-2.0
/**
 * U5 — Erica end-to-end: the whole same-device flow, locally, against the
 * BMI wallet simulator (gitlab.opencode.de/bmi/eudi-wallet/erica).
 *
 * What this suite establishes, per the plan:
 * - happy path e2e: deeplink → request dereference (real HTTPS) → Erica's
 *   simulated presentation (real direct_post.jwt POST) → authenticate() →
 *   Upactor, with Erica's HAIP validation of the signed request recorded as
 *   conformance evidence (tests/integration/evidence/);
 * - the suite IS the HAIP check: a request Erica's profile validation
 *   rejects fails the happy-path test (errorCount must be 0);
 * - Erica's incorrect-credential simulations land as port errors, never
 *   exceptions;
 * - Erica's edge templates (special characters) and modes (over-disclosure,
 *   missing claims) exercise the privacy-minima path end to end.
 *
 * Setup: docs/erica-setup.md. Run with `npm run test:integration`; the
 * default `npm test` excludes this suite (it needs a running Erica).
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AuthError, EudiConfig, Session, Upactor } from '../../src/index.js';
import {
	driveErica,
	fetchEricaTrustAnchor,
	insecureHttpsPost,
	isAuthError,
	probeErica,
	recordEvidence,
	startRpServer,
	ERICA_URL,
	type DriveResult,
	type RpServer,
} from './erica-harness.js';

// Failing checks the harness knowingly accepts, each with its reason.
// Anything else failing is a conformance regression and fails the suite.
const ACCEPTED_CHECK_FAILURES: Record<string, string> = {
	// The harness signs with the local test access certificate
	// (tests/fixtures/access-certificate.pem); only the sandbox registrar
	// can issue one that chains to Erica's registrar trust list, and its
	// signing key is (correctly) not published. Severity: WARNING.
	'url.request_jwt.x5c_trust_anchor': 'test access certificate is not registrar-issued',
};

// PID attribute values Erica's templates disclose. None may ever appear on
// any enumerable path of an Upactor (upact SPEC §7).
const TEMPLATE_PII = [
	// normal.json
	'maria',
	'müller',
	'1985-03-15',
	'hauptstraße',
	'10115',
	'münchen',
	// special-characters.json
	'müñez',
	'björgßöñ',
	'1988-07-22',
	'überumlaut',
	'köln',
	'düsseldorf',
	// OVER_DISCLOSURE extras (FakePIDData.addExtraClaims)
	't220001293',
	'123456789012',
	'bundesdruckerei',
	// claim names
	'given_name',
	'family_name',
	'birthdate',
	'address',
	'document_number',
	'administrative_number',
	'issuing_authority',
];

function enumerableStrings(value: unknown, out: string[] = []): string[] {
	if (typeof value === 'string') {
		out.push(value);
	} else if (Array.isArray(value) || value instanceof Set) {
		for (const entry of value) enumerableStrings(entry, out);
	} else if (value instanceof Map) {
		for (const [k, v] of value) {
			enumerableStrings(k, out);
			enumerableStrings(v, out);
		}
	} else if (value instanceof Date) {
		// Dates carry no strings.
	} else if (typeof value === 'object' && value !== null) {
		for (const key of Object.keys(value)) {
			out.push(key);
			enumerableStrings((value as Record<string, unknown>)[key], out);
		}
	}
	return out;
}

function expectNoPii(value: unknown): void {
	const strings = enumerableStrings(value).map((s) => s.toLowerCase());
	for (const sentinel of TEMPLATE_PII) {
		expect(
			strings.some((s) => s.includes(sentinel)),
			`PII sentinel '${sentinel}' leaked onto the port surface`,
		).toBe(false);
	}
}

function expectOutcomeError(result: DriveResult, code: AuthError['code']): AuthError {
	expect(result.postResult, 'Erica did not POST to the response_uri').not.toBeNull();
	expect(result.outcome, 'the RP server recorded no authenticate() outcome').not.toBeNull();
	if (!isAuthError(result.outcome)) {
		throw new Error(`expected AuthError '${code}', got a Session`);
	}
	// A port error, not an exception: typed code and message, and the wallet
	// received an OAuth-style error reply rather than a 5xx crash.
	expect(result.outcome.code).toBe(code);
	expect(typeof result.outcome.message).toBe('string');
	expect(result.walletReply?.status).toBe(400);
	expect(JSON.parse(result.walletReply?.body ?? '{}').error).toBe('invalid_request');
	return result.outcome;
}

async function expectOutcomeSession(result: DriveResult): Promise<Session> {
	expect(result.postResult?.success, `Erica's POST failed: ${result.postResult?.error}`).toBe(true);
	expect(result.outcome).not.toBeNull();
	if (isAuthError(result.outcome)) {
		throw new Error(
			`expected a Session, got AuthError ${result.outcome.code}: ${result.outcome.message}`,
		);
	}
	return result.outcome as Session;
}

let trustAnchors: EudiConfig['trustAnchors'];
let rp: RpServer;

beforeAll(async () => {
	const problem = await probeErica();
	if (problem !== null) {
		throw new Error(
			`${problem}\n\nThis suite drives the adapter against a locally running Erica ` +
				`(the BMI wallet simulator). Start it per docs/erica-setup.md, then re-run ` +
				`'npm run test:integration' (set ERICA_URL if it is not on ${ERICA_URL}).`,
		);
	}
	// Erica's PID-issuer root CA is the trust anchor: the same move a
	// sandbox RP makes with the published mock trust lists.
	trustAnchors = [{ certificate: await fetchEricaTrustAnchor(), name: 'Erica test PID issuer root' }];
	rp = await startRpServer({ trustAnchors });
});

afterAll(async () => {
	await rp?.close();
});

describe('happy path (Erica VALID, declared age_over_18)', () => {
	let result: DriveResult;
	let upactor: Upactor;

	it('completes deeplink → dereference → presentation → authenticate() → Upactor', async () => {
		result = await driveErica(rp, { simulationMode: 'VALID', pidTemplate: 'normal' });
		const session = await expectOutcomeSession(result);
		expect(session).toBeTruthy();

		// Session binding per the developer guide: the wallet's POST is
		// answered with a redirect_uri carrying a single-use response_code.
		expect(result.walletReply?.status).toBe(200);
		const reply = JSON.parse(result.walletReply?.body ?? '{}') as { redirect_uri?: string };
		expect(reply.redirect_uri).toContain('/oid4vp/finish?response_code=');

		const responseCode = new URL(reply.redirect_uri as string).searchParams.get('response_code');
		const redeemed = await rp.adapter.redeemResponseCode(responseCode as string);
		expect(redeemed).not.toBeNull();
		upactor = redeemed as Upactor;
		// Single-use: a second redemption finds nothing.
		expect(await rp.adapter.redeemResponseCode(responseCode as string)).toBeNull();
	});

	it('the request object passes Erica JWT-level checks (signature, x5c)', () => {
		expect(result.parseUrlChecks).not.toBeNull();
		const checks = result.parseUrlChecks ?? [];
		expect(checks.length).toBeGreaterThan(0);

		const signature = checks.find((c) => c.checkId === 'url.request_jwt.signature');
		expect(signature?.passed, 'request JWT signature must verify against the x5c certificate').toBe(true);

		const failed = checks.filter((c) => !c.passed);
		for (const check of failed) {
			expect(
				ACCEPTED_CHECK_FAILURES[check.checkId],
				`unaccepted Erica check failure: ${check.checkId} [${check.severity}] ${check.issue ?? ''}`,
			).toBeDefined();
			expect(check.severity).not.toBe('ERROR');
		}
	});

	it('the request passes Erica HAIP profile validation with zero errors (the suite IS the HAIP check)', () => {
		expect(result.requestValidation).not.toBeNull();
		const summary = result.requestValidation?.summary;
		expect(summary).toBeDefined();
		const errors = (result.requestValidation?.checks ?? []).filter(
			(c) => !c.passed && c.severity === 'ERROR',
		);
		expect(
			errors.map((c) => `${c.checkId}: ${c.issue ?? ''}`),
			'Erica HAIP validation rejected the request',
		).toEqual([]);
		expect(summary?.errorCount).toBe(0);
	});

	it('maps to an Upactor with an opaque id and no PII on any enumerable path', () => {
		expect(upactor.id).toMatch(/^[0-9a-f]{32}$/);
		expect(upactor.provenance?.substrate).toBe('eudi');
		expect(upactor.provenance?.instance).toBe('https://debugger.eudi-wallet-demo.example');
		expect(upactor.capabilities.size).toBe(0);
		expect(upactor.lifecycle?.renewable).toBe('reauth');
		expect(upactor.lifecycle?.expires_at).toBeInstanceOf(Date);
		expectNoPii(upactor);
		expectNoPii(JSON.parse(JSON.stringify(upactor)));
	});

	it('records the conformance evidence', () => {
		recordEvidence('happy-path', {
			recorded_at: new Date().toISOString(),
			erica_url: ERICA_URL,
			erica_commit: process.env.ERICA_COMMIT ?? null,
			accepted_check_failures: ACCEPTED_CHECK_FAILURES,
			parse_url_checks: result.parseUrlChecks,
			request_validation: result.requestValidation,
			response_validation: result.responseValidation,
			post_result: result.postResult,
			outcome: 'session',
		});
	});
});

describe('Erica edge-case simulations land as port errors, not exceptions', () => {
	// Where the rejection is the adapter's own check (not the wrapped
	// library's), the message is pinned so the test fails if the error
	// starts coming from the wrong layer.
	const modes: { mode: string; messageAbout?: RegExp }[] = [
		{ mode: 'EXPIRED' },
		{ mode: 'NOT_YET_VALID' },
		{ mode: 'MISSING_SIGNATURE' },
		{ mode: 'WRONG_NONCE' },
		{ mode: 'WRONG_AUDIENCE', messageAbout: /KB-JWT aud/ },
		{ mode: 'MISSING_HOLDER_BINDING' },
	];
	const edgeEvidence: { mode: string; template?: string; outcome: string; wallet_reply_status?: number }[] = [];

	for (const { mode, messageAbout } of modes) {
		it(`${mode} → credential_invalid`, async () => {
			const result = await driveErica(rp, { simulationMode: mode, validation: false });
			const error = expectOutcomeError(result, 'credential_invalid');
			if (messageAbout) expect(error.message).toMatch(messageAbout);
			edgeEvidence.push({
				mode,
				outcome: error.code,
				wallet_reply_status: result.walletReply?.status,
			});
		});
	}

	it('INVALID_SIGNATURE: Erica cannot currently simulate it (broken test key); unit-covered instead', async () => {
		// Erica's INVALID_SIGNATURE_KEY (src/simulator/TestKeys.ts) is not a
		// valid P-256 key pair (d does not belong to the x/y point), so
		// node's crypto rejects it and the simulation aborts before any POST
		// reaches the adapter. The tampered-issuer-signature path is covered
		// end to end by the unit wallet (tests/response.test.ts,
		// tamperIssuerSignature). If this test starts seeing a wallet POST,
		// Erica fixed its key: move the mode into the loop above.
		const result = await driveErica(rp, { simulationMode: 'INVALID_SIGNATURE', validation: false });
		expect(result.simulationError).toContain('Invalid JWK EC key');
		expect(result.postResult).toBeNull();
		expect(result.outcome).toBeNull();
		edgeEvidence.push({
			mode: 'INVALID_SIGNATURE',
			outcome: 'erica simulation failed (broken INVALID_SIGNATURE_KEY); adapter path unit-covered',
		});
	});

	it('MISSING_CLAIMS (under-disclosure of a declared claim) → credential_invalid', async () => {
		// Two declared predicates; Erica's MISSING_CLAIMS omits the last
		// requested one, so exactly one declared claim goes undisclosed.
		const twoClaims = await startRpServer({
			trustAnchors,
			declaredAttributes: [
				{ format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [['age_over_18'], ['age_over_21']] },
			],
		});
		try {
			const result = await driveErica(twoClaims, { simulationMode: 'MISSING_CLAIMS', validation: false });
			const error = expectOutcomeError(result, 'credential_invalid');
			edgeEvidence.push({ mode: 'MISSING_CLAIMS', outcome: error.code });
		} finally {
			await twoClaims.close();
		}
	});

	it('OVER_DISCLOSURE → Session, and nothing over-disclosed reaches the Upactor', async () => {
		const result = await driveErica(rp, { simulationMode: 'OVER_DISCLOSURE', validation: false });
		await expectOutcomeSession(result);
		const reply = JSON.parse(result.walletReply?.body ?? '{}') as { redirect_uri?: string };
		const code = new URL(reply.redirect_uri as string).searchParams.get('response_code');
		const upactor = await rp.adapter.redeemResponseCode(code as string);
		expect(upactor).not.toBeNull();
		expectNoPii(upactor);
		edgeEvidence.push({ mode: 'OVER_DISCLOSURE', outcome: 'session (over-disclosure dropped)' });
	});

	it('special-characters PID template → Session, umlauts and ß never surface', async () => {
		const result = await driveErica(rp, {
			simulationMode: 'VALID',
			pidTemplate: 'special-characters',
			validation: false,
		});
		await expectOutcomeSession(result);
		const reply = JSON.parse(result.walletReply?.body ?? '{}') as { redirect_uri?: string };
		const code = new URL(reply.redirect_uri as string).searchParams.get('response_code');
		const upactor = await rp.adapter.redeemResponseCode(code as string);
		expect(upactor).not.toBeNull();
		expectNoPii(upactor);
		expectNoPii(JSON.parse(JSON.stringify(upactor)));
		edgeEvidence.push({
			mode: 'VALID',
			template: 'special-characters',
			outcome: 'session (no PII surfaced)',
		});
	});

	it('a replayed direct_post.jwt → credential_invalid', async () => {
		const result = await driveErica(rp, { simulationMode: 'VALID', validation: false });
		await expectOutcomeSession(result);
		const post = rp.walletPosts[rp.walletPosts.length - 1];
		const replayed = await insecureHttpsPost(rp.responseUri, post.contentType, post.body);
		expect(replayed.status).toBe(400);
		const outcome = rp.outcomes[rp.outcomes.length - 1];
		expect(isAuthError(outcome) && outcome.code).toBe('credential_invalid');
		edgeEvidence.push({ mode: 'REPLAY', outcome: 'credential_invalid' });
	});

	it('records the edge-case evidence', () => {
		recordEvidence('edge-cases', {
			recorded_at: new Date().toISOString(),
			erica_url: ERICA_URL,
			erica_commit: process.env.ERICA_COMMIT ?? null,
			cases: edgeEvidence,
		});
	});
});

describe('known Erica limitation (documented, not worked around)', () => {
	it('possession-only: Erica emits an empty disclosure element, which the adapter rejects', async () => {
		// Erica's PresentationResponseAssembler builds `<JWT>~~<KB-JWT>` when
		// nothing is disclosed; RFC 9901 requires `<JWT>~<KB-JWT>`. The
		// malformed empty disclosure fails SD-JWT parsing, so possession-only
		// cannot complete against Erica today and lands as credential_invalid.
		// The spec-correct possession-only success path is covered by the
		// unit wallet in tests/response.test.ts. If this test starts failing
		// with a Session outcome, Erica fixed its assembler: flip the
		// assertion and retire the note in docs/erica-setup.md.
		const possessionOnly = await startRpServer({
			trustAnchors,
			declaredAttributes: [{ format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [] }],
		});
		try {
			const result = await driveErica(possessionOnly, { simulationMode: 'VALID', validation: false });
			expectOutcomeError(result, 'credential_invalid');
		} finally {
			await possessionOnly.close();
		}
	});
});
