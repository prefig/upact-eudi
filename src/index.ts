// SPDX-License-Identifier: Apache-2.0
/**
 * @prefig/upact-eudi — EUDI wallet relying-party adapter for upact.
 *
 * Presents the German EUDI wallet (and any HAIP-conforming wallet) to an
 * application as an upact IdentityPort. OpenID4VP 1.0 / HAIP verifier flow,
 * SD-JWT VC, with the declared attribute list (CIR (EU) 2025/848 Art. 5(1))
 * enforced at construction.
 *
 * Factory-only. Substrate state (certificates, keys, the frozen attribute
 * policy) is held in closure scope, never on the returned object
 * (SPEC §7.5). Out-of-port extensions are typed as EudiAdapterExtensions;
 * consumers that only depend on the port interface stay substrate-agnostic.
 *
 * Wraps @openid4vc/openid4vp + @sd-jwt/sd-jwt-vc (see docs/decisions.md D1
 * for why not Credo). The protocol wiring lands in U2/U3; this build
 * enforces the construction-time attribute policy and the port shape.
 */

import type { AuthError, IdentityPort, Session, Upactor } from '@prefig/upact';
import { freezeAttributePolicy } from './attribute-policy.js';
import type { EudiConfig, EudiCredential } from './types.js';

/** Out-of-port methods specific to the EUDI adapter. */
export interface EudiAdapterExtensions {
	/**
	 * Builds the `openid4vp://` wallet deeplink for a new presentation
	 * transaction (init phase). The consumer renders it as a link or QR code.
	 * Pattern: upact-oidc's buildAuthRedirect.
	 *
	 * Not yet implemented — the authorization request side lands in U2.
	 */
	buildPresentationDeeplink(): Promise<URL>;
}

/**
 * Creates an upact IdentityPort backed by an EUDI wallet (OpenID4VP 1.0 /
 * HAIP relying-party flow).
 *
 * Throws at construction, before any network activity, when the declared
 * attribute surface violates the policy (undeclarable claim path, unknown
 * credential type, empty declaration) or when certificates, endpoints, or
 * trust anchors are missing.
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

	// Closure state for U2/U3: policy, baseUrl, certificates and keys stay
	// here, out of public reflection (SPEC §7.5).
	void policy;
	void baseUrl;

	// ——— IdentityPort ————————————————————————————————————————————————————————

	async function authenticate(credential: unknown): Promise<Session | AuthError> {
		if (!isEudiCredential(credential)) {
			return { code: 'credential_invalid', message: 'unrecognised credential shape' };
		}
		return {
			code: 'auth_failed',
			message: 'EUDI presentation verification is not implemented in this build (response side pending)',
		};
	}

	async function currentUpactor(_request: Request): Promise<Upactor | null> {
		// No session machinery yet (lands with the response side).
		return null;
	}

	async function invalidate(_session: Session): Promise<void> {
		// No session machinery yet (lands with the response side).
	}

	async function issueRenewal(_identity: Upactor, _evidence: unknown): Promise<Upactor | null> {
		// EUDI has no represence semantics; renewal is re-presentation.
		// Permanently null per the plan's scope boundaries (SPEC §6.4 OPTIONAL).
		return null;
	}

	// ——— EudiAdapterExtensions ———————————————————————————————————————————————

	async function buildPresentationDeeplink(): Promise<URL> {
		throw new Error(
			'upact-eudi: buildPresentationDeeplink is not implemented in this build (authorization request side pending)',
		);
	}

	return { authenticate, currentUpactor, invalidate, issueRenewal, buildPresentationDeeplink };
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

// ——— Public surface ————————————————————————————————————————————————————————

export {
	freezeAttributePolicy,
	isDeclaredClaim,
	ALLOWED_CLAIM_PATHS,
	KNOWN_CREDENTIAL_TYPES,
} from './attribute-policy.js';
export type { AttributePolicy } from './attribute-policy.js';
export type {
	AttributeDeclaration,
	ClaimPath,
	EudiConfig,
	EudiCredential,
	EudiEndpoints,
	TrustAnchor,
} from './types.js';

export type {
	Upactor,
	IdentityLifecycle,
	Capability,
	Session,
	AuthError,
	AuthErrorCode,
	IdentityPort,
} from '@prefig/upact';
export { SubstrateUnavailableError } from '@prefig/upact';
