# Security model and verification

Keygate protects application API routes using long-lived random API keys. Administrators define the shared application catalog in a JSON configuration file and own the corresponding Envoy routes and custom API policies. Each key belongs to its issuing OIDC subject; admitted users can issue keys for configured applications and list or revoke only their own keys. Users cannot create or modify applications through the service. Envoy controls which OIDC users/groups can access the manager; administrative changes happen through deployment configuration, not a manager role.

## Trust boundaries

- Envoy owns browser OAuth sessions. The manager requires an injected proxy credential and validates the forwarded ID token against the configured issuer, audience and JWKS. Subject-header mode is explicitly opt-in for controlled proxies.
- All modes require an administrator-controlled application configuration file. The loaded catalog is authoritative for both key management and authorization; database records alone cannot register an application. Restrict write access to this file and its deployment ConfigMap to administrators.
- Envoy binds each protected route to a configured application UUID. Caller-supplied application/user headers never select authorization scope. Administrators enforce HTTP method, path and custom API rules in Envoy; Keygate checks application membership and does not interpret those gateway rules.
- The authorizer reads the route-bound application and matches the full API key digest against its stored keys. It returns the conventional `x-auth-request-user` and the equivalent custom `x-keygate-user-id`, `x-keygate-app` and `x-keygate-key-id`. Envoy must overwrite matching caller headers. Backends must reject direct access that bypasses Envoy.
- The user ID is `usr_` plus SHA-256 of the stored key owner subject. It is a stable identifier within the configured identity provider, not an authentication credential. Different issuers must not share a store without a migration/namespacing design.
- PostgreSQL is trusted to maintain records, with separate manager write and authorizer SELECT-only roles. Database write access can replace digests/ownership, so hashing does not make database integrity or credentials unimportant. Only SHA-256 hashes of key secrets generated with at least 256 bits of random entropy are persisted; raw keys appear only in the creation response.
- API key checks do not consult the identity provider. Disabling a Pocket ID user does not automatically revoke that user's existing API keys. Revoke keys separately. Revocation affects new authorization checks after the configured cache TTL; existing streams are not terminated.

## Tests

`cargo coverage` runs the same unit/integration tests as `cargo test-all`, with a 100% per-file line and total function coverage gate for all production Rust sources, including the executable. Cargo-llvm-cov's standard exclusions cover test code and dependencies, not backend modules. Coverage is measured on Linux; platform-specific non-Unix signal handling is not exercised.

| Boundary | Assertions |
| --- | --- |
| Login | Reject absent/duplicate/invalid proxy and identity headers, malformed or forged JWTs, expired/not-yet-valid tokens, wrong issuer/audience, missing claims, invalid subjects, unsupported algorithms |
| Signing keys | Require signing use and verify operation when declared, match declared algorithm, reject ambiguous key IDs and invalid JWK encoding; bound fetches and fail closed on IdP faults |
| User isolation | Users share configured applications but cannot list or revoke another user’s keys; client owner fields cannot assign ownership |
| Application isolation | Users cannot create applications; applications outside the loaded catalog cannot be managed or authorized, including with stored keys; a valid key for another application cannot match within the route-bound application; malformed, missing and duplicate credentials are denied |
| Backend identity | Derive user identity from the stored key owner; real Envoy overwrites forged user/app/key headers before forwarding to an upstream |
| Mutations | Same-origin + custom CSRF header; bounded request body, validated names, per-user, per-application key cap, no plaintext/digest in list responses, no-store responses |
| Storage | Atomic CAS, conflict rejection, persistence, malformed records/versions/IDs, read-only authorizer role, concurrent writer conflicts, missing schema and SQL failure sanitization |
| Cache | Fixed non-sliding TTL, independent node expiry, no stale fallback, bounded concurrency, queue/storage timeouts, queued cache recheck, corrupt plugin record rejection |
| Runtime | All server modes, startup configuration failures, bind errors, SIGINT/SIGTERM shutdown |
| Real services | Isolated PostgreSQL persistence and shared-user lifecycle; real Envoy allow/deny/revoke, identity-header replacement and SSE response |

Line and function coverage are execution metrics. They do not imply 100% branch coverage, exhaustive input testing, a formal proof, a dependency vulnerability audit, or a penetration test of the deployed cluster. No live Pocket ID browser login or Kubernetes node-local routing is claimed by the local suite. Deployment must verify the gateway's installed CRDs, OIDC forwarding, fail-closed configuration, network isolation, and credential rotation.

## Operational limits

- Bound public request rates at Envoy. Cache misses still require storage reads; no distributed abuse/rate-limiting service is provided.
- Configuration is loaded once at startup. After an application change, coordinate restarts of the manager and every authorizer with the same configuration; a ConfigMap update alone does not reload running processes. Old processes retain their previous catalog until restarted.
- Removing an application prevents key management and authorization in processes that loaded the updated catalog; stored keys are retained. Keep UUIDs stable when renaming applications. Reintroducing a removed UUID re-enables its non-revoked keys. Remove the matching Envoy route when retiring an application and complete the rollout to all instances.
- Cached authorizations remain usable until their fixed TTL during an outage. Set TTL to zero if every check must consult storage.
- Newly issued API keys have format `kg-<46 ASCII letters>` (49 characters total). After the literal `kg-` prefix, only `A-Z` and `a-z` occur: no digits, underscores or additional hyphens. OS-backed `OsRng` samples uniformly from the 52-letter alphabet, providing about 262 bits of secret entropy. SHA-256 stores the digest, not the plaintext; it is not the random generator or a password KDF.
- Previously issued keys with `kg-` followed by 43 canonical unpadded base64url characters (46 characters total, encoding a 32-byte secret) remain accepted when their stored key is active and their application is configured. The new issuance format does not invalidate existing PostgreSQL keys.
- Use TLS to trusted identity/storage endpoints and restrict service reachability. Never log Authorization, ID tokens, proxy credentials, or issuance response bodies at the gateway.
- CAS prevents concurrent lost updates, not privileged rollback of the storage system. Treat storage administration and snapshots as security-sensitive.
