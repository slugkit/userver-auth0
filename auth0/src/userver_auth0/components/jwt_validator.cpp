#include <userver_auth0/components/jwt_validator.hpp>

#include <chrono>
#include <stdexcept>
#include <string>
#include <string_view>

#include <fmt/format.h>

#include <userver/clients/http/client.hpp>
#include <userver/clients/http/component.hpp>
#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/logging/log.hpp>
#include <userver/tracing/span.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

namespace userver_auth0::components {

namespace {

constexpr auto kDefaultTokenPrefix = "Bearer";
constexpr auto kDefaultWellKnownKeys = ".well-known/jwks.json";

const std::string kFetchStage = "auth0-jwt-fetch-jwks";
const std::string kValidateStage = "auth0-jwt-validate";
const std::string kDecodeStage = "auth0-jwt-decode";
const std::string kVerifyStage = "auth0-jwt-verify";
const std::string kExtractClaimsStage = "auth0-jwt-extract-claims";
const std::string kExtractPermissionsStage = "auth0-jwt-extract-permissions";

/// Build a jwt-cpp verifier configured for the requested algorithm. We
/// support the algorithms that Auth0 actually issues: RS256 (default),
/// RS384, RS512. Symmetric (HMAC) algorithms are intentionally not
/// supported because Auth0 never uses them for the JWKS-based flow.
template <typename Decoded>
auto MakeVerifierForAlgorithm(const std::string& alg, const std::string& pem) {
    if (alg == "RS256") {
        return jwt::verify<JsonTraits>().allow_algorithm(jwt::algorithm::rs256(pem, "", "", ""));
    }
    if (alg == "RS384") {
        return jwt::verify<JsonTraits>().allow_algorithm(jwt::algorithm::rs384(pem, "", "", ""));
    }
    if (alg == "RS512") {
        return jwt::verify<JsonTraits>().allow_algorithm(jwt::algorithm::rs512(pem, "", "", ""));
    }
    throw std::invalid_argument("Unsupported JWT algorithm: " + alg);
}

}  // namespace

namespace tracing = userver::tracing;

struct JwtValidator::Impl {
    using SharedReadablePtr = userver::utils::SharedReadablePtr<Jwks>;

    userver::components::HttpClient& http_client_;
    std::string domain_;
    std::string audience_;
    std::string issuer_;
    std::set<std::string> algorithms_;
    std::string token_prefix_;
    std::string well_known_keys_;
    Claims required_claims_;
    Claims optional_claims_;

    Impl(const userver::components::ComponentConfig& config,
         const userver::components::ComponentContext& context)
        : http_client_(context.FindComponent<userver::components::HttpClient>())
        , domain_(config["domain"].As<std::string>())
        , audience_(config["audience"].As<std::string>())
        , issuer_(config["issuer"].As<std::string>(""))
        , algorithms_(config["algorithms"].As<std::set<std::string>>())
        , token_prefix_(config["token_prefix"].As<std::string>(kDefaultTokenPrefix))
        , well_known_keys_(config["well_known_keys"].As<std::string>(kDefaultWellKnownKeys))
        , required_claims_(config["required_claims"].As<Claims>(Claims{}))
        , optional_claims_(config["optional_claims"].As<Claims>(Claims{})) {
        if (issuer_.empty()) {
            issuer_ = fmt::format("https://{}/", domain_);
        }
        if (algorithms_.empty()) {
            throw std::invalid_argument("auth0 jwt-validator: algorithms must be a non-empty list");
        }
    }

    auto FetchWellKnownKeys(userver::cache::UpdateStatisticsScope& stats_scope) const
        -> std::unique_ptr<Jwks> {
        auto scope = tracing::Span::CurrentSpan().CreateScopeTime(kFetchStage);
        auto well_known_keys_url = fmt::format("{}{}", issuer_, well_known_keys_);
        LOG_INFO() << "Fetching JWKS from " << well_known_keys_url;
        auto response = http_client_.GetHttpClient()
                            .CreateRequest()
                            .get(well_known_keys_url)
                            .timeout(std::chrono::seconds(10))
                            .perform();
        response->raise_for_status();
        auto body = response->body();
        auto jwks = std::make_unique<Jwks>(jwt::parse_jwks<JsonTraits>(body));
        stats_scope.IncreaseDocumentsReadCount(1);
        stats_scope.Finish(1);
        return jwks;
    }

    auto Validate(SharedReadablePtr jwks, std::string_view token) const -> ValidationResult {
        auto scope = tracing::Span::CurrentSpan().CreateScopeTime(kValidateStage);
        if (token.empty()) {
            throw std::invalid_argument("Missing token");
        }
        if (!token_prefix_.empty()) {
            if (token.size() < token_prefix_.size()) {
                throw std::invalid_argument("Invalid token");
            }
            if (token.substr(0, token_prefix_.size()) != token_prefix_) {
                throw std::invalid_argument("Invalid token");
            }
            token = token.substr(token_prefix_.size());
            while (!token.empty() && std::isspace(static_cast<unsigned char>(token.front()))) {
                token = token.substr(1);
            }
        }
        if (token.empty()) {
            throw std::invalid_argument("Invalid token");
        }

        scope.Reset(kDecodeStage);
        auto decoded = jwt::decode<JsonTraits>(std::string(token));
        auto alg = decoded.get_algorithm();
        if (algorithms_.find(alg) == algorithms_.end()) {
            throw std::invalid_argument("Algorithm not allowed: " + alg);
        }

        auto jwk = jwks->get_jwk(decoded.get_key_id());
        if (jwk.has_algorithm() && jwk.get_algorithm() != alg) {
            throw std::invalid_argument("Algorithm mismatch between token and JWKS entry");
        }

        scope.Reset(kVerifyStage);
        auto pem = jwt::helper::convert_base64_der_to_pem(jwk.get_x5c_key_value());
        auto verifier = MakeVerifierForAlgorithm<decltype(decoded)>(alg, pem).with_issuer(issuer_);
        if (!audience_.empty()) {
            verifier = verifier.with_audience(audience_);
        }
        verifier.verify(decoded);

        scope.Reset(kExtractClaimsStage);
        Claims claims;
        for (const auto& [claim, claim_key] : required_claims_) {
            if (decoded.has_header_claim(claim_key)) {
                claims[claim] = decoded.get_header_claim(claim_key).as_string();
                continue;
            }
            if (decoded.has_payload_claim(claim_key)) {
                claims[claim] = decoded.get_payload_claim(claim_key).as_string();
                continue;
            }
            throw std::invalid_argument(fmt::format("Missing required claim: {}", claim));
        }
        for (const auto& [claim, claim_key] : optional_claims_) {
            if (decoded.has_header_claim(claim_key)) {
                claims[claim] = decoded.get_header_claim(claim_key).as_string();
                continue;
            }
            if (decoded.has_payload_claim(claim_key)) {
                claims[claim] = decoded.get_payload_claim(claim_key).as_string();
            }
        }

        scope.Reset(kExtractPermissionsStage);
        Permissions permissions;
        if (decoded.has_payload_claim("permissions")) {
            auto permissions_claim = decoded.get_payload_claim("permissions").as_array();
            for (const auto& permission : permissions_claim) {
                permissions.insert(JsonTraits::as_string(permission));
            }
        }
        return std::make_tuple(std::move(claims), std::move(permissions));
    }
};

JwtValidator::JwtValidator(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context
)
    : BaseType(config, context)
    , impl_(config, context) {
    StartPeriodicUpdates();
}

JwtValidator::~JwtValidator() {
    StopPeriodicUpdates();
}

auto JwtValidator::GetStaticConfigSchema() -> userver::yaml_config::Schema {
    return userver::yaml_config::MergeSchemas<BaseType>(R"(
type: object
description: Auth0 / OIDC JWT validator
additionalProperties: false
properties:
    domain:
        type: string
        description: Tenant domain (e.g. poke-me-dev.eu.auth0.com). Used to derive issuer if `issuer` is empty.
    audience:
        type: string
        description: Required `aud` claim. Empty disables audience checking (not recommended).
    issuer:
        type: string
        description: Required `iss` claim. Defaults to `https://{domain}/`. Trailing slash matters — Auth0 emits it.
        defaultDescription: 'https://{domain}/'
    algorithms:
        type: array
        description: Allowed signing algorithms (RS256/RS384/RS512). Symmetric algorithms are not supported.
        items:
            type: string
    token_prefix:
        type: string
        description: Bearer prefix to strip from the input token. Default `Bearer`. Set to empty to skip stripping.
        defaultDescription: Bearer
    well_known_keys:
        type: string
        description: Path appended to issuer to fetch the JWKS.
        defaultDescription: .well-known/jwks.json
    required_claims:
        type: object
        description: |
            Map of output-key to JWT-claim-key. Each entry must be present in
            the validated token (header or payload). Use this to enforce
            critical claims like `sub`. Example: `sub: sub`.
        additionalProperties:
            type: string
        properties: {}
    optional_claims:
        type: object
        description: |
            Map of output-key to JWT-claim-key. Each entry is included in the
            result if present, ignored otherwise. Use this for namespaced
            custom claims like `email: https://your-app/email`.
        additionalProperties:
            type: string
        properties: {}
    )");
}

auto JwtValidator::Update(
    [[maybe_unused]] userver::cache::UpdateType type,
    [[maybe_unused]] const std::chrono::system_clock::time_point& last_update,
    [[maybe_unused]] const std::chrono::system_clock::time_point& now,
    userver::cache::UpdateStatisticsScope& stats_scope
) -> void {
    auto well_known_keys = impl_->FetchWellKnownKeys(stats_scope);
    this->Set(std::move(well_known_keys));
}

auto JwtValidator::Validate(std::string_view token) const -> ValidationResult {
    return impl_->Validate(this->Get(), token);
}

}  // namespace userver_auth0::components
