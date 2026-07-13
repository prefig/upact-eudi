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
