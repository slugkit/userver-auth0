# userver-auth0

[userver](https://userver.tech) components for validating Auth0 (and other OIDC) JWT access tokens against a remote JWKS.

## What it does

A `JwtValidator` component that:

- Fetches the issuer's JWKS on startup and refreshes it on a configurable interval (via `userver::components::CachingComponentBase`).
- Validates incoming JWTs: bearer prefix stripping, algorithm allowlist (RS256/RS384/RS512), `kid`-based key lookup, signature verification, `iss` and `aud` checks, and `exp`/`nbf` enforcement (via jwt-cpp).
- Extracts a configurable set of required and optional claims from header or payload, returning them as a flat `std::map<std::string, std::string>`.
- Extracts the standard `permissions` array as an `std::unordered_set<std::string>`.

The component returns a generic `(claims, permissions)` tuple — it has no opinion about how the consuming service maps that into a typed user. The consumer (e.g., a `pokeme-authx` service) takes the result and writes auth headers, queries its own database, etc.

## What it does NOT do

- No database access — the validator is pure crypto + claim extraction.
- No org / membership / permission model — the consuming service maps generic claims into its own domain.
- No HTTP middleware — the validator is invoked from your handler / auth checker.
- No symmetric (HMAC) algorithms — Auth0 uses RSA exclusively.

## Quick start

Add as a CMake subdirectory:

```cmake
set(AUTH0_BUILD_TESTS ON)
add_subdirectory(third-party/userver-auth0/auth0 auth0)
target_link_libraries(your_service PRIVATE auth0_validator)
```

`jwt-cpp` is pulled via CMake `FetchContent` (v0.7.1) — no system install needed. The fetch is guarded so a parent project that already declares `jwt-cpp` reuses its own copy.

Register the component in `main.cpp`:

```cpp
#include <userver_auth0/components/jwt_validator.hpp>

auto component_list = userver::components::MinimalServerComponentList()
                          .Append<userver::components::HttpClient>()
                          .Append<userver_auth0::components::JwtValidator>();
```

Configure in `static_config.yaml`:

```yaml
jwt-validator:
    update-interval: 30m
    domain: poke-me-dev.eu.auth0.com
    audience: https://api.poke-me.io
    issuer: https://poke-me-dev.eu.auth0.com/
    algorithms:
        - RS256
    token_prefix: Bearer
    well_known_keys: .well-known/jwks.json
    required_claims:
        sub: sub
    optional_claims:
        email: https://poke-me.io/email
```

Use it in a handler:

```cpp
auto& validator = context.FindComponent<userver_auth0::components::JwtValidator>();
auto [claims, permissions] = validator.Validate(request.GetHeader("Authorization"));
auto sub = claims.at("sub");
auto email_it = claims.find("email");
```

See [SETUP.md](SETUP.md) for the full Auth0 tenant configuration that produces the tokens this validator validates.

## Status

v0. Tests cover the JWT validation algorithm against an in-process keypair; the HTTP-backed JWKS fetch is exercised by integration tests in the consuming service.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
