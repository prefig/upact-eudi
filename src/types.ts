// SPDX-License-Identifier: Apache-2.0
/**
 * Public types for @prefig/upact-eudi.
 *
 * The configuration is the registrable declaration: the attribute list a
 * relying party files with the registrar under CIR (EU) 2025/848 Art. 5(1)
 * and the DCQL query the adapter sends at runtime are derived from the same
 * `declaredAttributes` value. Anything outside it fails at construction.
 */

/**
 * A claim path within a credential, in DCQL claims-path-pointer form:
 * each element names one step into the credential's claim structure.
 * Example: `['age_equal_or_over', '18']`.
 */
export type ClaimPath = readonly string[];

/**
 * One credential the relying party declares it will request, mirroring the
 * attribute list filed with the registrar (CIR (EU) 2025/848 Art. 5(1)).
 * The DCQL builder may request exactly these claims and nothing else.
 */
export interface AttributeDeclaration {
	/**
	 * Credential format. v0.1 supports SD-JWT VC only (`dc+sd-jwt`, the
	 * OpenID4VP 1.0 format identifier). mdoc is deferred; see the plan's
	 * scope boundaries.
	 */
	format: 'dc+sd-jwt';
	/** Verifiable credential type, e.g. the German PID `urn:eudi:pid:de:1`. */
	vct: string;
	/**
	 * Declared claim paths. An empty array means possession-only: the wallet
	 * proves it holds a valid credential of this type and discloses nothing.
	 */
	claims: readonly ClaimPath[];
}

/** An X.509 root the issuer chain must terminate at (trust-list anchor). */
export interface TrustAnchor {
	/** PEM-encoded X.509 certificate. */
	certificate: string;
	/** Optional human-readable label, used in errors and conformance evidence. */
	name?: string;
}

/** Where the adapter's request/response handlers are reachable by the wallet. */
export interface EudiEndpoints {
	/**
	 * Public base URL under which the application mounts the adapter's
	 * handlers. Must be HTTPS unless `allowInsecureRequests` is set.
	 */
	baseUrl: string;
	/**
	 * Path (relative to `baseUrl`) where the wallet dereferences the signed
	 * request object (`request_uri`). Default: '/request'.
	 */
	requestPath?: string;
	/**
	 * Path (relative to `baseUrl`) receiving the wallet's `direct_post.jwt`
	 * response (`response_uri`). Default: '/response'.
	 */
	responsePath?: string;
	/**
	 * Path (relative to `baseUrl`) the wallet sends the user's browser to
	 * after a successful presentation (the `redirect_uri` in the adapter's
	 * response to the wallet, carrying a single-use `response_code` for
	 * session binding). Default: '/finish'.
	 */
	finishPath?: string;
}

/** Configuration for createEudiAdapter. */
export interface EudiConfig {
	/**
	 * The declared attribute surface: the same list filed with the registrar
	 * per CIR (EU) 2025/848 Art. 5(1). Validated and frozen at construction;
	 * an undeclarable claim path throws before any network activity.
	 */
	declaredAttributes: readonly AttributeDeclaration[];
	/**
	 * The relying party's verifier identity (e.g. its origin). Validated
	 * non-empty at construction as part of the registrable declaration.
	 *
	 * Note: this is not the audience the wallet cryptographically addresses a
	 * presentation to. Under OpenID4VP the presentation audience is the
	 * `client_id` (`x509_hash:...`, derived from the access certificate), and
	 * the KB-JWT `aud` is verified against that client_id. This field is kept
	 * for declaration/registration parity and is not itself enforced against
	 * presentations.
	 */
	audience: string;
	/**
	 * Sandbox-issued access certificate, PEM-encoded. Travels as the JOSE
	 * `x5c` of the signed request object; the `x509_hash:` client_id is
	 * derived from its DER. Dev-mode uses Erica's fake keys.
	 */
	accessCertificate: string;
	/**
	 * ES256 private key for the access certificate, PKCS#8 PEM. Signs the
	 * `oauth-authz-req+jwt` request object. Held in closure, never exposed.
	 */
	accessCertificateKey: string;
	/**
	 * Registration certificate JWT (compact serialization). Travels in the
	 * `verifier_info` request parameter per the BMI developer guide.
	 */
	registrationCertificate: string;
	/** Endpoint layout the application serves the adapter's handlers under. */
	endpoints: EudiEndpoints;
	/**
	 * Trust anchors the issuer chain must terminate at. Dev-mode uses the
	 * published mock trust lists.
	 */
	trustAnchors: readonly TrustAnchor[];
	/**
	 * Allow HTTP (non-TLS) endpoint URLs. Local development only.
	 * Production deployments MUST NOT set this.
	 */
	allowInsecureRequests?: boolean;
	/**
	 * Relax the RFC 5280 CA path constraint (basicConstraints CA:TRUE) on
	 * certificates that issue other certificates in the issuer chain. Test
	 * wallet simulators (BMI Erica's "DO NOT USE IN PRODUCTION" PID chain)
	 * sign the credential leaf with an issuer certificate that omits CA:TRUE,
	 * which strict validation correctly rejects. Set this only against such
	 * test issuers. Independent of `allowInsecureRequests` on purpose: the
	 * integration harness runs real HTTPS but against test certificates.
	 * Production deployments MUST NOT set this; the real German PID issuer's
	 * certificate shape is confirmed against the sandbox, not assumed. When
	 * set, the forged-sub-chain protection is also down, so this is a
	 * dev/test escape hatch only.
	 */
	allowTestIssuerCertificates?: boolean;
}

/**
 * Credential shape accepted by createEudiAdapter's authenticate():
 * the wallet's `direct_post.jwt` POST, wrapped by the application.
 * The init phase (building the wallet deeplink) is exposed via
 * buildPresentationDeeplink, an out-of-port method on the adapter
 * (pattern: upact-oidc's buildAuthRedirect).
 */
export type EudiCredential = { kind: 'eudi-response'; request: Request };
