// SPDX-License-Identifier: Apache-2.0
/**
 * Harness for the Erica end-to-end suite (U5).
 *
 * Erica (gitlab.opencode.de/bmi/eudi-wallet/erica) is the BMI's relying-
 * party integration tool: it validates OpenID4VP requests against the EUDI
 * HAIP profile and simulates wallet behaviour, POSTing a real encrypted
 * `direct_post.jwt` response back to the relying party. This harness drives
 * the adapter's full same-device flow against a locally running Erica:
 *
 *   deeplink → request_uri dereference (real HTTPS) → Erica HAIP validation
 *   → Erica wallet simulation → direct_post.jwt POST (Erica → local RP
 *   server, real HTTPS) → authenticate() → Upactor.
 *
 * Setup: docs/erica-setup.md. The suite needs Erica reachable at ERICA_URL
 * (default http://127.0.0.1:3001), started with
 * NODE_TLS_REJECT_UNAUTHORIZED=0 so it accepts the harness's self-signed
 * RP TLS certificate (tests/fixtures/rp-tls.pem).
 *
 * Two documented accommodations of Erica quirks live in driveErica():
 *
 * 1. KB-JWT audience derivation. Erica's WalletSimulator takes the KB-JWT
 *    audience from the request's `aud` (the JAR audience,
 *    `https://self-issued.me/v2`, i.e. the wallet) or a camelCase
 *    `clientId`, never from the snake_case `client_id` a decoded JAR
 *    payload actually carries. HAIP (and Erica's own JARM builder comment)
 *    require the KB-JWT aud to be the verifier's client_id. The simulation
 *    call therefore strips `aud` and mirrors `client_id` into `clientId`;
 *    the validation call sends the payload untouched, so the HAIP check
 *    runs against exactly what the adapter signed.
 *
 * 2. Zero-disclosure presentations. Erica assembles `<JWT>~~<KB-JWT>` (an
 *    empty disclosure element) when nothing is disclosed; RFC 9901 requires
 *    `<JWT>~<KB-JWT>`. The adapter correctly rejects the malformed form, so
 *    the possession-only e2e documents `credential_invalid` rather than
 *    success (see the test).
 */

import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import { request as httpsRequest } from 'node:https';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AuthError, EudiConfig, Session } from '../../src/index.js';
import { createEudiAdapter } from '../../src/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, '..', 'fixtures');
const EVIDENCE_DIR = join(HERE, 'evidence');

export const ERICA_URL: string = (process.env.ERICA_URL ?? 'http://127.0.0.1:3001').replace(/\/+$/, '');

export const ACCESS_CERTIFICATE: string = readFileSync(join(FIXTURES, 'access-certificate.pem'), 'utf8');
export const ACCESS_CERTIFICATE_KEY: string = readFileSync(join(FIXTURES, 'access-certificate.key.pem'), 'utf8');
const RP_TLS_CERT = readFileSync(join(FIXTURES, 'rp-tls.pem'), 'utf8');
const RP_TLS_KEY = readFileSync(join(FIXTURES, 'rp-tls.key.pem'), 'utf8');
export const REGISTRATION_JWT = 'eyJhbGciOiJFUzI1NiIsInR5cCI6InJjK2p3dCJ9.eyJzdWIiOiJ0ZXN0In0.c2ln';

export type EricaCheck = {
	checkId: string;
	checkName: string;
	passed: boolean;
	severity: string;
	category?: string;
	issue?: string;
	details?: string;
};

export interface EricaValidation {
	checks: EricaCheck[];
	summary?: {
		totalChecks: number;
		passedChecks: number;
		failedChecks: number;
		errorCount: number;
		warningCount: number;
		compliancePercentage?: number;
	};
}

/** Probes Erica; returns null when healthy, a description otherwise. */
export async function probeErica(): Promise<string | null> {
	try {
		const res = await fetch(`${ERICA_URL}/health`, { signal: AbortSignal.timeout(3000) });
		if (!res.ok) return `Erica answered ${res.status} at ${ERICA_URL}/health`;
		return null;
	} catch (err) {
		return `Erica is not reachable at ${ERICA_URL} (${err instanceof Error ? err.message : String(err)})`;
	}
}

/** Fetches Erica's PID-issuer root CA (the harness's trust anchor). */
export async function fetchEricaTrustAnchor(): Promise<string> {
	const res = await fetch(`${ERICA_URL}/api/trust-anchor`);
	if (!res.ok) throw new Error(`GET /api/trust-anchor answered ${res.status}`);
	const pem = await res.text();
	if (!pem.includes('BEGIN CERTIFICATE')) throw new Error('trust-anchor response is not a PEM certificate');
	return pem;
}

// ——— The local relying-party server ——————————————————————————————————————————

export interface RpServer {
	baseUrl: string;
	adapter: ReturnType<typeof createEudiAdapter>;
	/** authenticate() outcomes, in order of wallet POSTs received. */
	outcomes: (Session | AuthError)[];
	/** Raw wallet POST bodies (for replay tests). */
	walletPosts: { body: string; contentType: string }[];
	/** Bodies of the responses handed back to the wallet. */
	walletReplies: { status: number; body: string }[];
	responseUri: string;
	close(): Promise<void>;
}

/**
 * Starts an HTTPS relying-party server around a fresh adapter. TLS uses the
 * self-signed harness certificate; HAIP requires HTTPS endpoints, so the
 * adapter runs in its production posture (no allowInsecureRequests).
 */
export async function startRpServer(
	configOverrides: Partial<EudiConfig> & Pick<EudiConfig, 'trustAnchors'>,
): Promise<RpServer> {
	const outcomes: (Session | AuthError)[] = [];
	const walletPosts: { body: string; contentType: string }[] = [];
	const walletReplies: { status: number; body: string }[] = [];

	// Adapter needs the port for its endpoint URLs; listen first.
	let adapter: ReturnType<typeof createEudiAdapter> | null = null;
	const server: Server = createServer({ cert: RP_TLS_CERT, key: RP_TLS_KEY }, (req, res) => {
		void (async () => {
			const chunks: Buffer[] = [];
			for await (const chunk of req) chunks.push(chunk as Buffer);
			const body = Buffer.concat(chunks);
			const url = `https://127.0.0.1:${port}${req.url ?? '/'}`;
			const request = new Request(url, {
				method: req.method ?? 'GET',
				headers: { 'content-type': req.headers['content-type'] ?? '' },
				...(req.method === 'POST' ? { body } : {}),
			});
			let response: Response;
			if (!adapter) {
				response = new Response('adapter not ready', { status: 503 });
			} else if ((req.url ?? '').startsWith('/oid4vp/request')) {
				response = await adapter.handleRequestUri(request);
			} else if ((req.url ?? '').startsWith('/oid4vp/response')) {
				walletPosts.push({
					body: body.toString(),
					contentType: req.headers['content-type'] ?? '',
				});
				const outcome = await adapter.authenticate({ kind: 'eudi-response', request });
				outcomes.push(outcome);
				response = adapter.respondToWallet(outcome);
			} else {
				response = new Response('not found', { status: 404 });
			}
			const responseBody = Buffer.from(await response.arrayBuffer());
			if ((req.url ?? '').startsWith('/oid4vp/response')) {
				walletReplies.push({ status: response.status, body: responseBody.toString() });
			}
			res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
			res.end(responseBody);
		})().catch((err) => {
			res.writeHead(500);
			res.end(String(err));
		});
	});
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (address === null || typeof address === 'string') throw new Error('no bound address');
	const port = address.port;
	const baseUrl = `https://127.0.0.1:${port}/oid4vp`;

	adapter = createEudiAdapter({
		declaredAttributes: [
			{ format: 'dc+sd-jwt', vct: 'urn:eudi:pid:de:1', claims: [['age_over_18']] },
		],
		audience: `https://127.0.0.1:${port}`,
		accessCertificate: ACCESS_CERTIFICATE,
		accessCertificateKey: ACCESS_CERTIFICATE_KEY,
		registrationCertificate: REGISTRATION_JWT,
		endpoints: { baseUrl },
		// Erica's "DO NOT USE IN PRODUCTION" PID issuer omits CA:TRUE; the
		// harness runs real HTTPS but against these test certificates.
		allowTestIssuerCertificates: true,
		...configOverrides,
	});

	return {
		baseUrl,
		adapter,
		outcomes,
		walletPosts,
		walletReplies,
		responseUri: `${baseUrl}/response`,
		close: () => new Promise((resolve) => server.close(() => resolve())),
	};
}

/** GET against the harness RP server, trusting its self-signed certificate. */
export function insecureHttpsGet(
	url: string,
): Promise<{ status: number; contentType: string; body: string }> {
	return new Promise((resolve, reject) => {
		const req = httpsRequest(url, { method: 'GET', rejectUnauthorized: false }, (res) => {
			const chunks: Buffer[] = [];
			res.on('data', (chunk) => chunks.push(chunk as Buffer));
			res.on('end', () =>
				resolve({
					status: res.statusCode ?? 0,
					contentType: res.headers['content-type'] ?? '',
					body: Buffer.concat(chunks).toString(),
				}),
			);
		});
		req.on('error', reject);
		req.end();
	});
}

/** POST against the harness RP server, trusting its self-signed certificate. */
export function insecureHttpsPost(
	url: string,
	contentType: string,
	body: string,
): Promise<{ status: number; body: string }> {
	return new Promise((resolve, reject) => {
		const req = httpsRequest(
			url,
			{ method: 'POST', rejectUnauthorized: false, headers: { 'content-type': contentType } },
			(res) => {
				const chunks: Buffer[] = [];
				res.on('data', (chunk) => chunks.push(chunk as Buffer));
				res.on('end', () =>
					resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString() }),
				);
			},
		);
		req.on('error', reject);
		req.write(body);
		req.end();
	});
}

// ——— Driving Erica ———————————————————————————————————————————————————————————

export interface DriveOptions {
	simulationMode?: string;
	pidTemplate?: 'normal' | 'special-characters' | 'incomplete-birthdate';
	/** Skip the parse-url and validation-only calls (edge-case tests). */
	validation?: boolean;
}

export interface DriveResult {
	deeplink: URL;
	/** Decoded payload of the signed request object the wallet fetched. */
	requestPayload: Record<string, unknown>;
	/** Erica's JWT-level checks over the signed request object (by value). */
	parseUrlChecks: EricaCheck[] | null;
	/** Erica's HAIP profile validation of the untouched request payload. */
	requestValidation: EricaValidation | null;
	/** Erica's own RP-side validation of the response it simulated. */
	responseValidation: EricaValidation | null;
	/** Result of Erica's POST to the adapter's response_uri. */
	postResult: { success: boolean; statusCode?: number; error?: string } | null;
	/** Erica's wallet-simulation failure, when the simulator itself failed. */
	simulationError: string | null;
	/** The authenticate() outcome the RP server recorded for this flow. */
	outcome: Session | AuthError | null;
	/** The HTTP reply the wallet (Erica) received from respondToWallet. */
	walletReply: { status: number; body: string } | null;
}

async function ericaJson(path: string, body: unknown): Promise<Record<string, any>> {
	const res = await fetch(`${ERICA_URL}${path}`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify(body),
	});
	if (!res.ok) throw new Error(`POST ${path} answered ${res.status}: ${await res.text()}`);
	return (await res.json()) as Record<string, any>;
}

/**
 * One full same-device flow: deeplink → real HTTPS dereference → Erica
 * validation (untouched payload) → Erica wallet simulation (accommodated
 * payload, see header) → Erica POSTs direct_post.jwt to the RP server →
 * authenticate() outcome.
 */
export async function driveErica(rp: RpServer, options: DriveOptions = {}): Promise<DriveResult> {
	const outcomesBefore = rp.outcomes.length;
	const deeplink = await rp.adapter.buildPresentationDeeplink();
	const requestUri = deeplink.searchParams.get('request_uri');
	if (!requestUri) throw new Error('deeplink carries no request_uri');

	// Wallet-side dereference over real HTTPS.
	const deref = await insecureHttpsGet(requestUri);
	if (deref.status !== 200) throw new Error(`request_uri dereference answered ${deref.status}`);
	if (!deref.contentType.includes('application/oauth-authz-req+jwt')) {
		throw new Error(`request object served as '${deref.contentType}'`);
	}
	const requestJwt = deref.body.trim();
	const requestPayload = JSON.parse(
		Buffer.from(requestJwt.split('.')[1], 'base64url').toString(),
	) as Record<string, any>;

	let parseUrlChecks: EricaCheck[] | null = null;
	let requestValidation: EricaValidation | null = null;
	if (options.validation !== false) {
		// JWT-level checks (structure, x5c, signature, registrar trust) over
		// the signed request object, request-by-value so no fetch is involved
		// (Erica's SSRF guard rightly refuses loopback request_uri fetches).
		const byValue =
			`openid4vp://?client_id=${encodeURIComponent(String(requestPayload.client_id))}` +
			`&request=${requestJwt}`;
		const parsed = await ericaJson('/api/parse-url', { url: byValue });
		parseUrlChecks = (parsed.data?.checks ?? []) as EricaCheck[];

		// HAIP profile validation of the payload exactly as signed.
		const validated = await ericaJson('/api/debug', {
			request: requestPayload,
			validationProfile: 'pid-presentation',
			simulationMode: 'VALID',
			postResponseToUri: false,
		});
		requestValidation = (validated.data?.requestValidation ?? null) as EricaValidation | null;
	}

	// Wallet simulation + POST back. `aud` stripped / `clientId` mirrored per
	// the header's accommodation note, so the simulated KB-JWT is addressed
	// to the verifier's client_id as HAIP requires.
	const { aud: _aud, ...withoutAud } = requestPayload;
	const simulated = await ericaJson('/api/debug', {
		request: { ...withoutAud, clientId: requestPayload.client_id },
		validationProfile: 'pid-presentation',
		simulationMode: options.simulationMode ?? 'VALID',
		pidTemplate: options.pidTemplate ?? 'normal',
		postResponseToUri: true,
	});
	const session = simulated.data ?? {};
	const postResult = session.simulatedResponse?.postResult ?? null;

	const outcome = rp.outcomes.length > outcomesBefore ? rp.outcomes[rp.outcomes.length - 1] : null;
	const walletReply =
		rp.walletReplies.length > outcomesBefore ? rp.walletReplies[rp.walletReplies.length - 1] : null;

	return {
		deeplink,
		requestPayload,
		parseUrlChecks,
		requestValidation,
		responseValidation: (session.responseValidation ?? null) as EricaValidation | null,
		postResult,
		simulationError: (session.simulatedResponse?.error ?? null) as string | null,
		outcome,
		walletReply,
	};
}

// ——— Conformance evidence ————————————————————————————————————————————————————

/**
 * Records Erica output under tests/integration/evidence/ when
 * ERICA_RECORD_EVIDENCE=1. The committed files are the plan's conformance
 * evidence: Erica's HAIP validation of a request this adapter actually
 * signed, and the adapter's disposition of every Erica simulation mode.
 */
export function recordEvidence(name: string, data: unknown): void {
	if (process.env.ERICA_RECORD_EVIDENCE !== '1') return;
	mkdirSync(EVIDENCE_DIR, { recursive: true });
	writeFileSync(join(EVIDENCE_DIR, `${name}.json`), `${JSON.stringify(data, null, '\t')}\n`);
}

export function isAuthError(value: Session | AuthError | null): value is AuthError {
	return value !== null && typeof (value as AuthError).code === 'string';
}
