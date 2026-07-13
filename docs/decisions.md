# Decisions

## D1. U1 spike outcome: fallback to `@openid4vc/openid4vp` + `@sd-jwt/sd-jwt-vc`

Date: 2026-07-13. Status: decided by spike evidence.

The plan's first choice was to wrap `@credo-ts/openid4vc` (see the origin
decision doc, `applications/research/2026-07-13-eudi-verifier-library-decision.md`),
with a documented fallback if the Credo Agent abstraction could not be
contained behind `createEudiAdapter`. The U1 spike ran against
`@credo-ts/openid4vc@0.7.0` installed from npm, instantiating an Agent with
the verifier module inside a factory function. It could not be contained.
Three independent findings, each sufficient on its own:

1. **Forced server ownership.** `OpenId4VcVerifierModuleConfig` requires an
   Express `app` (`InternalOpenId4VcVerifierModuleConfigOptions.app: Express`,
   a required field), and the module's `configureRouter` registers Credo's
   own endpoints (`/authorization-requests`, `/authorize`) on it. `express`
   (^5.2.1) and `@types/express` are production dependencies of
   `@credo-ts/openid4vc`. The upact adapter contract is the inverse: the
   application owns the HTTP surface and the adapter exposes handlers
   (upact-oidc's `authenticate(credential.request)` takes a fetch `Request`;
   redirects are values the caller serves). Wrapping Credo would have meant
   either owning an Express app inside the factory or demanding one in
   config, and the `request_uri` dereference endpoint would live inside
   Credo's routing rather than as a handler the application mounts.

2. **Forced persistent storage.** `agent.initialize()` throws
   `CredoError: Missing required dependency: 'StorageService'. You can
   register it using the AskarModule, DrizzleStorageModule, or implement
   your own.` A relying-party verifier needs only transaction-scoped
   nonce/state (upact-oidc holds the equivalent in signed, short-lived
   cookies). Credo demands a wallet database (a native Askar binary or a
   Drizzle-backed store) before a single authorization request can be
   built. That is substrate state the factory cannot hold in a closure.

3. **Global mutable state on import.** Importing the module mutates
   `globalThis`: it installs the reflect-metadata polyfill on `Reflect`
   (`Reflect.getMetadata` appears), plants `classValidatorMetadataStorage`,
   tslib helper globals, and zod's global registry. Two adapters in one
   process would share this metadata state, and the package's
   `sideEffects: false` posture would be a lie.

Verdict: trigger the documented fallback. The adapter wraps
`@openid4vc/openid4vp` (protocol envelope: authorization request signing,
DCQL, `direct_post.jwt` response decryption) plus `@sd-jwt/sd-jwt-vc`
(SD-JWT VC and KB-JWT verification). Both are function libraries with
caller-supplied crypto callbacks; both are the engine Credo uses
internally, so the protocol surface is the same code paths minus the
framework. Spike-verified: importing them adds no `Reflect` polyfill and no
framework container; the only `globalThis` additions are zod's own registry
keys (`__zod_globalConfig`, `__zod_globalRegistry`), a value-level detail of
zod itself that is shared safely across adapter instances.

Cost accepted, as the origin doc priced it: the audit-heavy glue is ours to
assemble in U2/U3 (x5c trust-chain policy against the trust-list anchors,
token status list checks, JWE handling for `direct_post.jwt`). Those pieces
must be tested as if we wrote them, because we did. `@animo-id/mdoc` joins
later if mdoc verification lands.

## D2. U2: transactions are in-memory and instance-bound

Date: 2026-07-13. Status: decided.

The authorization request side needs per-transaction state three times over:
single-use enforcement on the `request_uri` dereference, the nonce/state the
U3 response side must check the presentation against, and the ephemeral
P-256 private key that decrypts the wallet's `direct_post.jwt` JWE. Unlike
upact-oidc, none of this can ride in a cookie: the party returning to us is
the wallet, not a browser carrying our cookie jar.

So the store is an in-memory Map in the factory closure, TTL-swept
(10 minutes, matching upact-oidc's state-cookie lifetime), with the
`request_uri` carrying an HMAC-SHA256-signed reference under an
instance-local random key. Consequences, stated plainly:

- A transaction is bound to the adapter instance that began it. Multi-process
  deployments where the deeplink is built by one process and the wallet's
  dereference lands on another will 404. That is out of scope for the
  sandbox target (a single locally-run relying party); if it surfaces, the
  fix is a pluggable store, not a signed stateless token, because the JWE
  private key cannot be safely round-tripped through the wallet.
- Restarting the process kills in-flight transactions. Same failure mode as
  losing upact-oidc's state cookies mid-login: the user retries.
- Forged or replayed references are indistinguishable from expired ones by
  design (uniform 404, no oracle).

The dev-mode `allowInsecureRequests` flag relaxes the wrapped library's
https-only URL validation via its module-global config for the duration of
one build call (set, await, restore). A concurrently-building secure
instance in the same process could theoretically observe the relaxed window;
acceptable for a flag documented as local-development-only.

## D3. U3: response-side shape

Date: 2026-07-13. Status: decided.

- **Transaction lookup by JWE `kid`.** The wallet's `direct_post.jwt` JWE
  names the encryption key it used; ours is `enc-<transaction id>` from
  `client_metadata.jwks`. A response without that kid cannot be matched to
  a transaction and is `credential_invalid`. There is no try-all-keys
  fallback: HAIP wallets echo the kid, and trying every live transaction's
  key would turn the store into a decryption oracle.
- **Single-use both ways.** `takeForResponse` requires the request object
  to have been dereferenced first (a wallet that never fetched the request
  cannot know the nonce) and deletes the transaction, so a replayed
  response finds nothing and normalises to `credential_invalid`, matching
  the plan's replay scenario.
- **The KB-JWT checks the library does not do are ours.** The wrapped
  verifier checks nonce and sd_hash but only the *presence* of `aud` and
  `iat`; the adapter additionally requires `aud` to equal the verifier's
  `x509_hash:` client_id and `iat` to fall inside a freshness window
  (`KB_JWT_MAX_AGE_SECONDS` past, `KB_JWT_IAT_SKEW_SECONDS` future).
- **Interim `Upactor.id`: per-presentation.** Derived from
  sha256(substrate, issuer, KB-JWT sd_hash), 32 hex chars. German PIDs
  disclose no stable identifier by default, so this build promises no
  cross-session stability: equal ids mean the same presentation. U4 decides
  the real stability semantics with sandbox presentations in hand; the
  claims mapper is the only file that changes.
- **Predicates stay off the port surface for now.** Declared boolean
  predicates (age_equal_or_over/18) are verified — present and boolean, or
  `credential_invalid` — but not mapped onto the Upactor; how they surface
  is U4's decision (plan decision 4). Over-disclosed claims are dropped
  before mapping (plan KTD3); the mapper's input type cannot even carry
  them.
- **Session binding via single-use response codes.** `authenticate` returns
  an opaque Session (createSession, SPEC §7.4) holding the wallet-follow
  `redirect_uri` (`<baseUrl><finishPath>?response_code=...`).
  `respondToWallet(outcome)` builds the wallet-facing HTTP response;
  `redeemResponseCode(code)` gives the application the Upactor exactly once
  at the finish path, per the developer guide's session-binding
  requirement. `invalidate` revokes an unredeemed code. The adapter carries
  no browser-session machinery beyond that; `currentUpactor` stays null and
  the application owns its session from redemption onward.
- **Status-list unavailability is `substrate_unavailable`.** The plan's
  "trust-list endpoint down" scenario: trust anchors themselves are static
  config (no fetch to fail), so the network dependency that can be down at
  verification time is the token status list endpoint. Unreachable/non-2xx
  → `substrate_unavailable`, 429 → `rate_limited`, revoked →
  `credential_rejected` via a typed error, not message matching.
- **Fixtures.** The BMI-published mock trust list was fetchable and is
  committed as a fixture (provenance in tests/fixtures/README.md); it
  anchors a negative test. Positive chains are locally generated test
  certificates labelled as such, because the sandbox issuer keys are
  rightly not ours to have. The JWE encryptor in the test helpers is
  written independently of the adapter's decryptor so the two check each
  other.

## D4. U5: the Erica harness, and what it changed

Date: 2026-07-13. Status: decided by running Erica locally
(gitlab.opencode.de/bmi/eudi-wallet/erica, commit 5bd801f).

Erica ran, natively (Node 22, no Docker), and the full same-device flow
completes against it: deeplink → request_uri dereference over real HTTPS →
Erica's HAIP validation → Erica's simulated wallet POSTing a real encrypted
`direct_post.jwt` → `authenticate()` → Upactor. Setup in
docs/erica-setup.md; suite in tests/integration/erica.e2e.test.ts; recorded
validation output in tests/integration/evidence/. What the harness forced
us to decide:

- **Registry extension: flat `age_over_<threshold>` predicates.** Erica's
  PID template (the BMI's own model of the sandbox PID) discloses flat
  `age_over_18`/`age_over_21` booleans, not the EU PID rulebook's nested
  `age_equal_or_over/<threshold>` sub-claims U1 allow-listed. Both are
  boolean predicates with identical privacy properties, so both spellings
  are now declarable (src/attribute-policy.ts). This is the registry
  extension U1 anticipated "when consumers surface"; Erica is the first
  consumer. Which spelling the real sandbox PID uses is a September
  question; the answer retires the loser.

- **Erica's trust anchor is fetched, not committed.** Erica generates its
  PID-issuer leaf certificate fresh per boot (signed by a stable committed
  root), so the harness fetches `GET /api/trust-anchor` at suite start and
  configures the adapter with it, the same move a sandbox RP makes with
  the published mock trust lists. Nothing Erica-specific is baked into the
  adapter.

- **Two Erica quirks are accommodated in the harness, not the adapter**
  (details and code pointers in tests/integration/erica-harness.ts):
  the KB-JWT audience derivation (Erica reads the JAR `aud` or a camelCase
  `clientId`, never the snake_case `client_id`, so the simulation call
  strips `aud` and mirrors `client_id`; the validation call sends the
  payload exactly as signed), and HAIP validation running on a separate
  `/api/debug` call from the simulation so neither is compromised.

- **Two Erica bugs are documented, not worked around.** Zero-disclosure
  presentations come out as `<JWT>~~<KB-JWT>` (an empty disclosure element,
  malformed per RFC 9901), so the possession-only e2e records the adapter's
  correct rejection rather than a success; the spec-correct possession-only
  path stays covered by the unit wallet. And `INVALID_SIGNATURE` mode
  cannot run at all (Erica's `INVALID_SIGNATURE_KEY` is not a valid P-256
  key pair, node's crypto rejects it), so tampered issuer signatures stay
  covered by the unit suite's `tamperIssuerSignature`. Both tests are
  written to fail loudly if Erica fixes itself, so the assertions get
  upgraded instead of silently rotting.

- **The adapter runs in production posture.** The harness RP server is
  HTTPS (self-signed fixture cert, tests/fixtures/rp-tls.pem), so
  `allowInsecureRequests` stays off and Erica's HAIP profile validation
  passes with zero errors. Two non-ERROR findings are knowingly accepted
  and allowlisted by checkId with reasons: the registrar-trust WARNING
  (our access certificate is a local test cert; only the sandbox registrar
  can issue a chained one) and the loopback-response_uri WARNING (inherent
  to a local harness). Anything else failing fails the suite.
