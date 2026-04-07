#pragma once

/// @file userver_auth0/components/jwt_validator.hpp
/// @brief @copybrief userver_auth0::components::JwtValidator

#include <chrono>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_set>

#include <userver/cache/caching_component_base.hpp>
#include <userver/utils/fast_pimpl.hpp>
#include <userver/yaml_config/schema.hpp>

#include <jwt-cpp/jwt.h>

namespace userver_auth0::components {

using JsonTraits = jwt::traits::kazuho_picojson;
using Jwks = jwt::jwks<JsonTraits>;

/// @brief Validates Auth0 (or any OIDC) JWTs against a remote JWKS.
///
/// Caches the JWKS via userver's `CachingComponentBase` and refreshes on a
/// configurable interval. The validator strips an optional bearer prefix
/// (`Bearer ` by default), checks the algorithm against an allowlist,
/// looks up the signing key by `kid`, verifies the signature, and pulls
/// out the configured claims and the standard `permissions` array.
///
/// Returns a generic `(claims, permissions)` tuple — no opinion about
/// what the consumer does with them. The intended pattern is for the
/// consuming service to map claims into its own typed user representation
/// after validation succeeds.
///
/// @par Static config example:
/// @code
/// jwt-validator:
///     update-interval: 30m
///     domain: poke-me-dev.eu.auth0.com
///     audience: https://api.poke-me.io
///     issuer: https://poke-me-dev.eu.auth0.com/
///     algorithms:
///         - RS256
///     token_prefix: Bearer
///     well_known_keys: .well-known/jwks.json
///     required_claims:
///         sub: sub
///     optional_claims:
///         email: https://poke-me.io/email
/// @endcode
class JwtValidator final : public userver::components::CachingComponentBase<Jwks> {
public:
    static constexpr std::string_view kName = "jwt-validator";

    using BaseType = userver::components::CachingComponentBase<Jwks>;
    using Claims = std::map<std::string, std::string>;
    using Permissions = std::unordered_set<std::string>;
    using ValidationResult = std::tuple<Claims, Permissions>;

    JwtValidator(
        const userver::components::ComponentConfig& config,
        const userver::components::ComponentContext& context
    );
    ~JwtValidator() override;

    static auto GetStaticConfigSchema() -> userver::yaml_config::Schema;

    /// @brief Validate the given token. The token may include the bearer
    ///        prefix (e.g. `"Bearer eyJ..."`); the prefix is stripped
    ///        according to the configured `token_prefix`.
    /// @throws std::invalid_argument on missing/malformed token, unknown
    ///         algorithm, missing required claim, or any underlying
    ///         jwt-cpp verification failure.
    auto Validate(std::string_view token) const -> ValidationResult;

private:
    auto Update(
        userver::cache::UpdateType type,
        const std::chrono::system_clock::time_point& last_update,
        const std::chrono::system_clock::time_point& now,
        userver::cache::UpdateStatisticsScope& stats_scope
    ) -> void override;

    constexpr static auto kImplSize = 384UL;
    constexpr static auto kImplAlign = 8UL;
    struct Impl;
    userver::utils::FastPimpl<Impl, kImplSize, kImplAlign> impl_;
};

}  // namespace userver_auth0::components
