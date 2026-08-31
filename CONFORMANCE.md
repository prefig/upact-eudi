# Conformance: @prefig/upact-eudi

**Spec version:** upact v0.2
**Package version:** 0.2.0
**Date:** 2026-07-13

## Substrate

The EUDI wallet ecosystem, spoken to as an OpenID4VP 1.0 / HAIP relying party (verifier). Same-device flow: signed request object by reference (`request_uri`, ES256, JOSE `x5c` carrying exactly the access certificate, `client_id` scheme `x509_hash:`), DCQL credential queries, encrypted `direct_post.jwt` responses (ECDH-ES / A128GCM, fresh P-256 keypair per transaction), SD-JWT VC verification per RFC 9901 (issuer x5c chain to configured trust anchors, KB-JWT, token status list). Credential type: the German PID, `urn:eudi:pid:de:1`. mdoc and cross-device are deferred (see README).

The adapter wraps `@openid4vc/openid4vp` (protocol envelope) and `@sd-jwt/sd-jwt-vc` (credential cryptography). The plan's first choice, `@credo-ts/openid4vc`, could not be contained behind the factory pattern; `docs/decisions.md` D1 records the spike evidence. The audit-heavy glue (trust-chain policy, status-list checks, JWE handling) is therefore this package's own code and is tested as such.

**Pinned references.** BMI EUDI wallet developer guide at <https://bmi.usercontent.opencode.de/eudi-wallet/developer-guide/>, consulted 2026-07-13. The guide carries no version number of its own; the newest entry in its change log at consultation was PID Provider 1.27.0 (2026-05-27). The guide's changelog moves monthly (the nbf/exp change landed March 2026); re-check before sandbox kick-off. Erica wallet simulator: gitlab.opencode.de/bmi/eudi-wallet/erica, commit `5bd801f` (2026-07-06).

## Threat model

The wallet is user-controlled and the issuer is trusted via configured trust anchors (in the sandbox, the published mock trust lists; in production, the ecosystem trust lists). The adapter verifies what a relying party must verify: request-object integrity (signed with the access certificate), response encryption to a per-transaction key, issuer chain to a trust anchor, KB-JWT holder binding (aud, nonce, iat freshness, sd_hash), credential status. It does not defend against a compromised wallet or issuer, and it does not establish sybil resistance: with a predicate-only declaration, one wallet can complete `authenticate()` any number of times, minting a fresh identity each time (see Identifier derivation). Deployments verified against Erica are sandbox-posture; production certificate handling is not yet documented by the ecosystem.

## Declared-attribute policy (SPEC §7; CIR (EU) 2025/848 Art. 5(1))

The construction-time centrepiece, generalising upact-oidc's scope policy. `EudiConfig.declaredAttributes` mirrors the attribute list a relying party files with its Member State registrar; `freezeAttributePolicy` validates it against the SPEC §7 privacy minima and deep-freezes it before any network activity. The DCQL query is derived once, from the frozen policy and nothing else; no caller argument or post-construction config mutation can widen it (`tests/request.test.ts`).

- Forbidden claim paths (legal names, birthdate fields, address, nationalities, contact identifiers, `personal_administrative_number`, portrait) throw at construction, naming the SPEC clause (§7.1 / §7.3).
- Declarable claim paths are boolean predicates only: `age_equal_or_over/<threshold>` (EU PID rulebook spelling) and `age_over_<threshold>` (the flat spelling Erica's BMI PID template discloses; `docs/decisions.md` D4). Thresholds: 12, 14, 16, 18, 21, 65. An empty claims list is possession-only.
- Response side: disclosed claims outside the declared set are dropped before mapping; the mapper's input type cannot carry them. Missing declared claims fail verification (`credential_invalid`).
- A declared predicate is a requirement: disclosed `false` throws `PredicateNotSatisfiedError`, normalised to `credential_rejected`. A successful `authenticate()` attests every declared predicate; no boolean rides on the `Upactor` (§7.2).

## Capabilities self-declared

`[]`: no capabilities declared. The v0.1 vocabulary is `email | recovery` (SPEC §5.1); an EUDI presentation carries neither an email channel nor an account-recovery path. Declared age predicates are not surfaced as adapter-local capabilities either; they are verification requirements (above), pending a port extension if a branch-on-value consumer surfaces.

## Lifecycle and provenance

Every `Upactor` returned by this adapter carries:

- `lifecycle.expires_at`: the earliest credential expiry among the verified presentations, when present.
- `lifecycle.renewable`: always `'reauth'`. EUDI renewal is re-presentation; there is no represence semantics.
- `provenance.substrate`: `'eudi'`.
- `provenance.instance`: the issuer URL of the (first) verified presentation.

## AuthError mapping table

| Substrate result | AuthErrorCode |
|---|---|
| Unrecognised credential shape (not `{ kind: 'eudi-response', request }`) | `credential_invalid` |
| JWE undecryptable, unknown/forged/replayed transaction (`kid`), state or nonce mismatch, sd_hash mismatch, tampered signature, expired credential, wrong vct, KB-JWT aud/iat failure, under-disclosure of a declared claim (`ResponseInvalidError` and library verification failures) | `credential_invalid` |
| Issuer chain does not terminate at a configured trust anchor (`TrustChainError`) | `credential_rejected` |
| Credential revoked or suspended per token status list (`CredentialStatusError`) | `credential_rejected` |
| Declared predicate disclosed as `false` (`PredicateNotSatisfiedError`) | `credential_rejected` |
| Token status list endpoint unreachable / non-2xx (`StatusListUnavailableError`) | `substrate_unavailable` |
| Token status list endpoint HTTP 429 | `rate_limited` |
| Any other error | `auth_failed` |

`identity_unavailable` is not emitted; the substrate does not surface an identity-existence distinction. Trust anchors are static configuration with no fetch to fail, so the network dependency that can be down at verification time is the status-list endpoint (`docs/decisions.md` D3).

## Session opacity (SPEC §7.4)

This adapter uses `createSessionBox` from `@prefig/upact/internal` for Session construction: one box is created per adapter instance inside the factory closure, and only that instance can unseal the Sessions it seals. The Session opaquely holds the mapped `Upactor`, the wallet-follow `redirect_uri`, and the single-use `response_code`; none of these, and no substrate material, is reachable except via `box.unseal` inside the adapter. A Session handed to a different instance's `respondToWallet` is foreign and takes the 400 `session was not produced by this adapter` path. `invalidate` revokes the unredeemed response code held in closure; there is nothing wallet-side to revoke.

## Adapter back-channel closure (SPEC §7.5)

Passes a reflection test at `tests/attribute-policy.test.ts` (`back-channel closure conformance` suite), parity with the sibling adapters. Sentinel values for the access certificate, its private key, the registration certificate JWT, and the trust anchors are verified unreachable through JSON.stringify, Object.keys, Object.getOwnPropertyNames, Reflect.ownKeys, Object.getOwnPropertySymbols, for-in, structuredClone (DataCloneError is the proof), util.inspect, direct property access by likely names (including the SPEC §7.5-named `client`), spread, replacer-wrapped stringify, and Object.entries. All substrate state (frozen policy, parsed certificate and key, transaction store, HMAC key, response codes) lives in the factory closure.

## Identifier derivation (SPEC §4.4, §7.3)

`Upactor.id` is per-authentication: the first 32 hex characters of a SHA-256 over the substrate tag, the single-use transaction nonce, and each verified presentation's issuer plus KB-JWT `sd_hash`. Equal ids mean the same successful `authenticate()` call; ids never repeat across authentications, so the adapter offers no cross-session recognition. No PID attribute value, and nothing user-supplied, enters the derivation.

`docs/identity-stability.md` is the conformance record for this derivation: the evidence (a bare `sd_hash` derivation is accidentally linkable when a wallet re-presents a stored credential, and accidentally unstable when it draws the next credential from a batch), the options weighed, and the stability promise stated honestly, including that one wallet can mint many identities and that deduplication belongs at the application layer.

## display_hint

Never populated. Everything human-readable in a PID is PII (SPEC §4.2 forbids contact identifiers, §7.1 forbids legal names).

## EudiAdapterExtensions

Out-of-port methods on the returned adapter (pattern: upact-oidc's `buildAuthRedirect`, Decision 10; the OpenID4VP init and wallet-response phases are substrate-specific concerns, not port primitives):

- `buildPresentationDeeplink(options?)`: begins a transaction, returns the `openid4vp://` deeplink (client_id, single-use signed `request_uri`, `request_uri_method`).
- `handleRequestUri(request)`: serves the ES256-signed request object (`application/oauth-authz-req+jwt`, `Cache-Control: no-store`); single-use; forged, expired, replayed, and foreign references are uniformly 404.
- `respondToWallet(outcome)`: the HTTP response to the wallet's POST; on success carries the wallet-follow `redirect_uri` with a single-use `response_code` per the developer guide's session-binding requirement.
- `redeemResponseCode(code)`: hands the application the `Upactor` exactly once at the finish path.

## Deviations from SHOULD clauses

- **`currentUpactor` always returns `null` and never throws `SubstrateUnavailableError`.** The adapter carries no browser-session machinery: the application binds its own session at the finish path via `redeemResponseCode` and owns it from there (EUDI has no wallet-side session to consult, so no request ever bears an adapter-managed session). The error type is re-exported for API symmetry.
- **§8 transparent refresh is not applicable.** There is no refresh channel; renewal is re-presentation.

## issueRenewal

Normatively OPTIONAL (SPEC §6.4). Permanently returns `null`: EUDI has no represence semantics, and re-presentation is a fresh `authenticate()` producing a fresh id.

## Protocol conformance evidence

Beyond the unit suites (149 tests, including a spec-correct wallet simulator at `tests/helpers/wallet.ts`), the integration suite drives the full same-device flow against a locally running Erica (commit pinned above): deeplink, `request_uri` dereference over HTTPS, Erica's HAIP profile validation, a real encrypted `direct_post.jwt` presentation, `authenticate()`, `Upactor`. Recorded evidence at `tests/integration/evidence/happy-path.json` (request validation with zero errors; two allowlisted WARNINGs: registrar trust, because only the sandbox registrar can issue a chained access certificate, and the loopback `response_uri` inherent to a local harness; Erica's own RP-side response validation 21/21) and `edge-cases.json`. Setup: `docs/erica-setup.md`. Erica is the fast local proxy; sandbox testing against the real wallet is the true check and is scheduled for the sandbox onboarding window.
