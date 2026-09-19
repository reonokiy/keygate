# Security model and verification

Keygate protects application API routes using long-lived random API keys. Applications are shared by all authenticated users. Each key belongs to its issuing OIDC subject; users can list and revoke only their own keys, including when another user created the application. Envoy controls which OIDC users/groups can access the manager. Keygate does not implement group or administrator privileges. Any admitted user may create a shared application, but this does not register a gateway route.

## Trust boundaries

- Envoy owns browser OAuth sessions. The manager requires an injected proxy credential and validates the forwarded ID token against the configured issuer, audience and JWKS. Subject-header mode is explicitly opt-in for controlled proxies.
- Envoy binds each protected route to an application UUID. Caller-supplied application/user headers never select authorization scope.
- The authorizer reads the route-bound application and matches the full API key digest against its stored keys. It returns the conventional `x-auth-request-user` and the equivalent custom `x-keygate-user-id`, `x-keygate-app` and `x-keygate-key-id`. Envoy must overwrite matching caller headers. Backends must reject direct access that bypasses Envoy.
- The user ID is `usr_` plus SHA-256 of the stored key owner subject. It is a stable identifier within the configured identity provider, not an authentication credential. Different issuers must not share a store without a migration/namespacing design.
- PostgreSQL is trusted to maintain records, with separate manager write and authorizer SELECT-only roles. Database write access can replace digests/ownership, so hashing does not make database integrity or credentials unimportant. Only hashes of 256-bit random key secrets are persisted; raw keys appear only in the creation response.
- API key checks do not consult the identity provider. Disabling a Pocket ID user does not automatically revoke that user's existing API keys. Revoke keys separately. Revocation affects new authorization checks after the configured cache TTL; existing streams are not terminated.

## Tests

`cargo coverage` runs the same unit/integration tests as `cargo test-all`, with a 100% per-file line and total function coverage gate for all production Rust sources, including the executable. Cargo-llvm-cov's standard exclusions cover test code and dependencies, not backend modules. Coverage is measured on Linux; platform-specific non-Unix signal handling is not exercised.

| Boundary | Assertions |
| --- | --- |
| Login | Reject absent/duplicate/invalid proxy and identity headers, malformed or forged JWTs, expired/not-yet-valid tokens, wrong issuer/audience, missing claims, invalid subjects, unsupported algorithms |
| Signing keys | Require signing use and verify operation when declared, match declared algorithm, reject ambiguous key IDs and invalid JWK encoding; bound fetches and fail closed on IdP faults |
| User isolation | Users share applications but cannot list or revoke another user’s keys; even an application creator has no privilege over others’ keys; client owner fields cannot assign ownership |
| Application isolation | A valid key for another application cannot match within the route-bound application; malformed, missing and duplicate credentials are denied |
| Backend identity | Derive user identity from the stored key owner; real Envoy overwrites forged user/app/key headers before forwarding to an upstream |
| Mutations | Same-origin + custom CSRF header; bounded request body, validated names, per-user, per-application key cap, no plaintext/digest in list responses, no-store responses |
| Storage | Atomic CAS, conflict rejection, persistence, malformed records/versions/IDs, read-only authorizer role, concurrent writer conflicts, missing schema and SQL failure sanitization |
| Cache | Fixed non-sliding TTL, independent node expiry, no stale fallback, bounded concurrency, queue/storage timeouts, queued cache recheck, corrupt plugin record rejection |
| Runtime | All server modes, startup configuration failures, bind errors, SIGINT/SIGTERM shutdown |
| Real services | Isolated PostgreSQL persistence and shared-user lifecycle; real Envoy allow/deny/revoke, identity-header replacement and SSE response |

Line and function coverage are execution metrics. They do not imply 100% branch coverage, exhaustive input testing, a formal proof, a dependency vulnerability audit, or a penetration test of the deployed cluster. No live Pocket ID browser login or Kubernetes node-local routing is claimed by the local suite. Deployment must verify the gateway's installed CRDs, OIDC forwarding, fail-closed configuration, network isolation, and credential rotation.

## Operational limits

- Bound public request rates at Envoy. Cache misses still require storage reads; no distributed abuse/rate-limiting service is provided.
- Cached authorizations remain usable until their fixed TTL during an outage. Set TTL to zero if every check must consult storage.
- API keys have format `kg-<43 base64url characters>` (46 characters total). The prefix is public metadata; security comes from 256 random bits generated by OS-backed OsRng. SHA-256 stores the digest, not the plaintext; it is not the random generator or a password KDF.
- Use TLS to trusted identity/storage endpoints and restrict service reachability. Never log Authorization, ID tokens, proxy credentials, or issuance response bodies at the gateway.
- CAS prevents concurrent lost updates, not privileged rollback of the storage system. Treat storage administration and snapshots as security-sensitive.
