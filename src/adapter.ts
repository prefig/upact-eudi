// SPDX-License-Identifier: Apache-2.0
/**
 * createEudiAdapter — EUDI wallet relying-party adapter factory.
 *
 * Factory-only. Substrate state (the frozen attribute policy, the parsed
 * access certificate and its private key, the transaction store and its
 * HMAC key) is held in closure scope, never on the returned object
 * (SPEC §7.5). Out-of-port extensions are typed as EudiAdapterExtensions;
 * consumers that only depend on the port interface stay substrate-agnostic.
 *
 * Both protocol sides are live: the authorization request side (deeplink +
 * request_uri dereference handler, U2) and the response side (authenticate
 * over the wallet's direct_post.jwt, claims mapping, wallet-follow
 * redirect_uri with single-use response codes for session binding, U3).
 */

import { randomBytes } from 'node:crypto';
import type { AuthError, IdentityPort, Session, Upactor } from '@prefig/upact';
import { createSession } from '@prefig/upact';
import { _unwrapSession } from '@prefig/upact/internal';
import { freezeAttributePolicy } from './attribute-policy.js';
import { mapPresentationsToUpactor } from './claims-mapper.js';
import {
	buildDcqlQuery,
	buildRequestObjectJwt,
	createTransactionStore,
	loadAccessCertificate,
	REQUEST_OBJECT_CONTENT_TYPE,
	signTransactionRef,
	verifyTransactionRef,
} from './request.js';
import { normaliseEudiError, parseTrustAnchors, verifyDirectPostResponse } from './response.js';
import type { EudiConfig, EudiCredential } from './types.js';

/** Out-of-port methods specific to the EUDI adapter. */
export interface EudiAdapterExtensions {
	/**
	 * Begins a presentation transaction and returns the `openid4vp://`
	 * wallet deeplink (same-device flow; render it as a link or QR code).
	 * The deeplink carries `client_id`, `request_uri` (a signed, single-use,
	 * short-lived transaction reference under the configured request path),
	 * and `request_uri_method`. Pattern: upact-oidc's buildAuthRedirect.
	 */
	buildPresentationDeeplink(options?: { requestUriMethod?: 'get' | 'post' }): Promise<URL>;
	/**
	 * Handles the wallet's dereference of the `request_uri`: verifies the
	 * signed transaction reference, enforces single-use, and returns the
	 * ES256-signed request object (`application/oauth-authz-req+jwt`,
	 * `Cache-Control: no-store`). The application mounts this handler at
	 * `endpoints.baseUrl + endpoints.requestPath`; it accepts GET and POST
	 * (a POSTing wallet may supply `wallet_nonce`, which is echoed into the
	 * signed request per OpenID4VP 1.0).
	 */
	handleRequestUri(request: Request): Promise<Response>;
	/**
	 * Builds the HTTP response the application returns to the wallet's
	 * `direct_post.jwt` POST, from the outcome of `authenticate()`. On
	 * success it carries the wallet-follow `redirect_uri` (the configured
	 * finish path with a single-use `response_code`) per the developer
	 * guide's session-binding requirement; on failure, an OAuth-style error
	 * body with a status the outcome's port error code warrants.
	 */
	respondToWallet(outcome: Session | AuthError): Response;
	/**
	 * Redeems the single-use `response_code` the wallet-followed browser
	 * arrives with at the finish path, binding the browser session to the
	 * verified presentation. Returns the Upactor once; null for unknown,
	 * expired, replayed, or invalidated codes.
	 */
	redeemResponseCode(responseCode: string): Promise<Upactor | null>;
}

const DEFAULT_REQUEST_PATH = '/request';
const DEFAULT_RESPONSE_PATH = '/response';
const DEFAULT_FINISH_PATH = '/finish';

/** Lifetime of a wallet-follow response code (seconds). */
export const RESPONSE_CODE_TTL_SECONDS: number = 5 * 60;

/** What a Session opaquely holds (recovered only via _unwrapSession). */
interface EudiSessionData {
	upactor: Upactor;
	redirectUri: string;
	responseCode: string;
}

/**
 * Creates an upact IdentityPort backed by an EUDI wallet (OpenID4VP 1.0 /
 * HAIP relying-party flow).
 *
 * Throws at construction, before any network activity, when the declared
 * attribute surface violates the policy (undeclarable claim path, unknown
 * credential type, empty declaration) or when certificates, endpoints, or
 * trust anchors are missing or malformed.
 */
export function createEudiAdapter(config: EudiConfig): IdentityPort & EudiAdapterExtensions {
	// The centrepiece: validate and freeze the declared attribute surface
	// first. Everything downstream may only read the frozen policy.
	const policy = freezeAttributePolicy(config);

	requireNonEmpty(config.accessCertificate, 'accessCertificate', 'the sandbox-issued access certificate (PEM)');
	requireNonEmpty(config.accessCertificateKey, 'accessCertificateKey', 'the ES256 private key for the access certificate (PKCS#8 PEM)');
	requireNonEmpty(config.registrationCertificate, 'registrationCertificate', 'the registration certificate JWT (verifier_info)');
	if (!Array.isArray(config.trustAnchors) || config.trustAnchors.length === 0) {
		throw new Error(
			`upact-eudi config: 'trustAnchors' is empty. Issuer chains cannot be verified ` +
				`without at least one trust anchor; dev-mode uses the published mock trust lists.`,
		);
	}
	const baseUrl = parseBaseUrl(config);
	const cert = loadAccessCertificate(config.accessCertificate, config.accessCertificateKey);
	const registrationCertificate = config.registrationCertificate;
	const allowInsecure = config.allowInsecureRequests === true;
	// Parsed once at construction; an unparseable anchor throws here,
	// before any network activity.
	const trustAnchors = parseTrustAnchors(config.trustAnchors);

	// The DCQL query is derived once, from the frozen policy and nothing
	// else. No later caller input can widen it.
	const dcqlQuery = buildDcqlQuery(policy);

	const requestUriBase = joinPath(baseUrl, config.endpoints.requestPath ?? DEFAULT_REQUEST_PATH);
	const responseUri = joinPath(baseUrl, config.endpoints.responsePath ?? DEFAULT_RESPONSE_PATH);
	const finishUri = joinPath(baseUrl, config.endpoints.finishPath ?? DEFAULT_FINISH_PATH);

	// Per-transaction nonce/state, single-use, short-lived. The reference
	// key is instance-local: a transaction is bound to the adapter instance
	// that began it, as an OIDC state cookie is bound to its cookieKey.
	const transactionKey = randomBytes(32);
	const transactions = createTransactionStore();

	// Wallet-follow response codes: single-use, short-lived, holding only
	// the mapped Upactor (never substrate material). Swept on access.
	const responseCodes = new Map<string, { upactor: Upactor; expiresAt: number }>();

	function sweepResponseCodes(): void {
		const now = Math.floor(Date.now() / 1000);
		for (const [code, entry] of responseCodes) {
			if (entry.expiresAt <= now) responseCodes.delete(code);
		}
	}

	// ——— IdentityPort ————————————————————————————————————————————————————————

	async function authenticate(credential: unknown): Promise<Session | AuthError> {
		if (!isEudiCredential(credential)) {
			return { code: 'credential_invalid', message: 'unrecognised credential shape' };
		}
		try {
			const presentations = await verifyDirectPostResponse({
				request: credential.request,
				takeTransaction: (id) => transactions.takeForResponse(id),
				policy,
				cert,
				dcqlQuery,
				responseUri,
				registrationCertificate,
				trustAnchors,
				allowInsecureUrls: allowInsecure,
			});
			const upactor = mapPresentationsToUpactor(presentations);

			sweepResponseCodes();
			const responseCode = randomBytes(32).toString('base64url');
			responseCodes.set(responseCode, {
				upactor,
				expiresAt: Math.floor(Date.now() / 1000) + RESPONSE_CODE_TTL_SECONDS,
			});
			const redirectUri = `${finishUri}?response_code=${responseCode}`;

			const sessionData: EudiSessionData = { upactor, redirectUri, responseCode };
			return createSession(sessionData);
		} catch (err) {
			return normaliseEudiError(err);
		}
	}

	async function currentUpactor(_request: Request): Promise<Upactor | null> {
		// The adapter carries no browser-session machinery of its own: the
		// application binds its session at the finish path via
		// redeemResponseCode and manages it from there (EUDI has no
		// wallet-side session to consult).
		return null;
	}

	async function invalidate(session: Session): Promise<void> {
		const data = _unwrapSession<EudiSessionData>(session);
		if (data !== undefined) {
			responseCodes.delete(data.responseCode);
		}
	}

	async function issueRenewal(_identity: Upactor, _evidence: unknown): Promise<Upactor | null> {
		// EUDI has no represence semantics; renewal is re-presentation.
		// Permanently null per the plan's scope boundaries (SPEC §6.4 OPTIONAL).
		return null;
	}

	// ——— EudiAdapterExtensions ———————————————————————————————————————————————

	async function buildPresentationDeeplink(options?: { requestUriMethod?: 'get' | 'post' }): Promise<URL> {
		const transaction = transactions.begin();
		const ref = signTransactionRef(transaction.id, transactionKey);
		const requestUri = `${requestUriBase}?tx=${ref}`;

		const deeplink = new URL('openid4vp://');
		deeplink.searchParams.set('client_id', cert.clientId);
		deeplink.searchParams.set('request_uri', requestUri);
		deeplink.searchParams.set('request_uri_method', options?.requestUriMethod ?? 'post');
		return deeplink;
	}

	async function handleRequestUri(request: Request): Promise<Response> {
		if (request.method !== 'GET' && request.method !== 'POST') {
			return plainResponse(405, 'method not allowed', { Allow: 'GET, POST' });
		}

		let ref: string | null;
		try {
			ref = new URL(request.url).searchParams.get('tx');
		} catch {
			return plainResponse(404, 'not found');
		}
		if (!ref) return plainResponse(404, 'not found');

		const id = verifyTransactionRef(ref, transactionKey);
		if (id === null) return plainResponse(404, 'not found');

		// Single-use: unknown, expired, and already-dereferenced references
		// are deliberately indistinguishable.
		const transaction = transactions.takeForRequest(id);
		if (transaction === null) return plainResponse(404, 'not found');

		let walletNonce: string | undefined;
		if (request.method === 'POST') {
			walletNonce = await readWalletNonce(request);
		}

		const jwt = await buildRequestObjectJwt({
			cert,
			dcqlQuery,
			responseUri,
			requestUri: `${requestUriBase}?tx=${ref}`,
			registrationCertificate,
			transaction,
			...(walletNonce !== undefined ? { walletNonce } : {}),
			allowInsecureUrls: allowInsecure,
		});

		return new Response(jwt, {
			status: 200,
			headers: {
				'Content-Type': REQUEST_OBJECT_CONTENT_TYPE,
				'Cache-Control': 'no-store',
			},
		});
	}

	function respondToWallet(outcome: Session | AuthError): Response {
		if (isAuthError(outcome)) {
			// Wallet-facing OAuth error bodies; port detail stays in the
			// AuthError the application already holds.
			const unavailable = outcome.code === 'substrate_unavailable' || outcome.code === 'rate_limited';
			return jsonResponse(unavailable ? 503 : 400, {
				error: unavailable ? 'temporarily_unavailable' : 'invalid_request',
				error_description: outcome.message,
			});
		}
		const data = _unwrapSession<EudiSessionData>(outcome);
		if (data === undefined) {
			return jsonResponse(400, {
				error: 'invalid_request',
				error_description: 'session was not produced by this adapter',
			});
		}
		return jsonResponse(200, { redirect_uri: data.redirectUri });
	}

	async function redeemResponseCode(responseCode: string): Promise<Upactor | null> {
		sweepResponseCodes();
		if (typeof responseCode !== 'string' || responseCode.length === 0) return null;
		const entry = responseCodes.get(responseCode);
		if (!entry) return null;
		responseCodes.delete(responseCode); // single-use
		return entry.upactor;
	}

	return {
		authenticate,
		currentUpactor,
		invalidate,
		issueRenewal,
		buildPresentationDeeplink,
		handleRequestUri,
		respondToWallet,
		redeemResponseCode,
	};
}

// ——— Internal helpers ————————————————————————————————————————————————————————

function plainResponse(status: number, body: string, headers: Record<string, string> = {}): Response {
	return new Response(body, {
		status,
		headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store', ...headers },
	});
}

function jsonResponse(status: number, body: Record<string, unknown>): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
	});
}

function isAuthError(value: Session | AuthError): value is AuthError {
	const candidate = value as { code?: unknown; message?: unknown };
	return typeof candidate.code === 'string' && typeof candidate.message === 'string';
}

/** Reads `wallet_nonce` from a POSTing wallet's form body, if present. */
async function readWalletNonce(request: Request): Promise<string | undefined> {
	const contentType = request.headers.get('content-type') ?? '';
	if (!contentType.includes('application/x-www-form-urlencoded')) return undefined;
	try {
		const form = new URLSearchParams(await request.text());
		const nonce = form.get('wallet_nonce');
		return nonce === null || nonce.length === 0 ? undefined : nonce;
	} catch {
		return undefined;
	}
}

function joinPath(baseUrl: URL, path: string): string {
	const base = baseUrl.href.replace(/\/+$/, '');
	const suffix = path.startsWith('/') ? path : `/${path}`;
	return `${base}${suffix}`;
}

function requireNonEmpty(value: unknown, field: string, description: string): void {
	if (typeof value !== 'string' || value.length === 0) {
		throw new Error(`upact-eudi config: '${field}' must be a non-empty string: ${description}.`);
	}
}

function parseBaseUrl(config: EudiConfig): URL {
	const raw = config.endpoints?.baseUrl;
	if (typeof raw !== 'string' || raw.length === 0) {
		throw new Error(`upact-eudi config: 'endpoints.baseUrl' must be a non-empty URL.`);
	}
	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		throw new Error(`upact-eudi config: 'endpoints.baseUrl' is not a valid URL: '${raw}'.`);
	}
	if (url.protocol !== 'https:' && config.allowInsecureRequests !== true) {
		throw new Error(
			`upact-eudi config: 'endpoints.baseUrl' must be HTTPS ('${raw}' is not). ` +
				`Set allowInsecureRequests for local development only.`,
		);
	}
	return url;
}

function isEudiCredential(value: unknown): value is EudiCredential {
	if (typeof value !== 'object' || value === null) return false;
	const candidate = value as { kind?: unknown; request?: unknown };
	return candidate.kind === 'eudi-response' && candidate.request instanceof Request;
}
