// Unit tests for the JWT validation algorithm. The CachingComponentBase
// wiring (HTTP fetch, periodic update) needs a userver test harness with
// a fake HTTP server, which is out of scope for these unit tests; a
// runtime test exercising the full component lives in the consuming
// service.
//
// What we DO test here is the JWT verification algorithm itself: signing
// a token with a known keypair and verifying it back with the matching
// public key, plus the standard set of negative cases (expired token,
// wrong audience, wrong issuer, custom claims, permissions array).
//
// The keypair below is a fresh test-only RSA-2048 keypair generated for
// these tests. It is NOT used in production.

#include <chrono>
#include <string>
#include <unordered_set>

#include <jwt-cpp/jwt.h>
#include <userver/utest/utest.hpp>

namespace {

using JsonTraits = jwt::traits::kazuho_picojson;

constexpr std::string_view kPrivKey = R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCkrW/vYZXEmeyX
csxtC50oozsx8J8txT/gF7M8mFgkgNWh6MhF3uL3yoOXgONXZ9pXbmvTgvq4pDd0
vVnSjGxJqZrHcZilbNAZeT89PbPiBtGXZdRob/BashW5qrxuuRmk3hH2Gbty4nz7
mVe1SL/EdsTWXjw4loOd6ZVuM7QcW4r1tJsqE32QiI+A22WBXHgf6KD4ln5yHBIo
h4ga8d9kxOV1IcFVxAKAkbOaXokkv3Wsn3CPvBnF5F0yJWwfroqaA9L94LXq3qrU
vfkQUGBiTnUS9c29x/FY2ng+lXRFIFTzb9cYGFlSEgZVo46BssK5HfKtGhkMAGOG
xhQ4ISeZAgMBAAECggEACEd3dpSkhdY6wrj47d0M/U1qlRXMvO17KwIqBth+avRm
uS2FvxyH8u8Fq2TlmR/9plJk/aTqw8RuzNHVvZwFeDUclN0hUGTOeA9kVmj/HZSb
7jWGhqslDXxBUxyyPUtVTpiDFOlBhzK7l58jnZe/G2qgtgnWE36+tn5XPst+6UN8
vjDRDTFNv4QCwfO8gGS9EkYiMApsPEEYJ8xeq1ZpIkmQ2SKwGWLTgdcy74KxdcA2
9zhUK94rkyTLg7jsIBXibvL5vO81Dqr4uPeUU29HBgUkqTMp3J+D+u1rwLNKUf8O
jUFqpjD7v0OTzq+6FT9NoqkQNjc/kksfea2SoUwXoQKBgQDdfTqU+a4uH0bWfUBA
jL9N+7qtS27SVyLqNS3QvTf54rc+H0IIv0dZ+p2VDpjqKiJywXqRQLuDc1YLvu53
YPClt0ANpYYWoe0WBX71DLoZ6n427rUK5dUk40TmlxiSQTywEvxtYK45Ml02QlVr
kYJ8VKkQqmHEmQZYl5UdU/Rx+QKBgQC+VhngHfk4Q5mEkmce2KTb+k38NZ7Ca2v1
pAo0ync+sqWKJRFrN0QdAaFZ5kTBCyEx7hBb8pDJWDppxIdktHwuTWt7xgvRurVb
DAohVWcs0JaMfcDjLoz1s3yiQxxECT2LdxZUkJ/AIVAN7i7fMtxmrZeh/whVulXj
XQzesu/KoQKBgBAnjhpHi7i5d0U1pXYPzfQ2JAt3sQGOcXF7p3fOFUMYkhzp0rso
mF+rs8qnYefSYujTy8jEW+jehKwepO34GBU+JGHabMlBzjUI+ZWN9BTn0YTYLEQ7
NyyVlvTqmFQyheahu9+OaaaqUbofZHOQDWBcHGimxLK+JoRXqfyVnwKhAoGBALIG
cnlPT7UydTqsfMs7MyeVfK+zr2SFeRrubaVm4hXAnlkRxrMTpB/FUJd3a0NsF4ZN
9vspbAcHAMvAyCqHLcdZHnlMie2Gxu372tXGvZQLHWUWkf1rouiFEsPqJVv1kJ0L
q9U42FKqVehRqYGWXtOi9jrNAYy9lmvssobxsptBAoGAOMHm9aHAtywEABX+Sr0L
WE1zo9QsXYe90eEJWqVcZ8Gr+DVEfz7LPFmLjegh+LhRVxhVHsAgtsZ3s8FxYJaz
Nk1awcN+O6raCYqW0b319MiLEH5O2OZecpZOu16NbYHjjKtE+woLM3MBxrA5hjQb
/TRQ2663fYs0B8AUNegeLtg=
-----END PRIVATE KEY-----
)";

constexpr std::string_view kPubKey = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApK1v72GVxJnsl3LMbQud
KKM7MfCfLcU/4BezPJhYJIDVoejIRd7i98qDl4DjV2faV25r04L6uKQ3dL1Z0oxs
Samax3GYpWzQGXk/PT2z4gbRl2XUaG/wWrIVuaq8brkZpN4R9hm7cuJ8+5lXtUi/
xHbE1l48OJaDnemVbjO0HFuK9bSbKhN9kIiPgNtlgVx4H+ig+JZ+chwSKIeIGvHf
ZMTldSHBVcQCgJGzml6JJL91rJ9wj7wZxeRdMiVsH66KmgPS/eC16t6q1L35EFBg
Yk51EvXNvcfxWNp4PpV0RSBU82/XGBhZUhIGVaOOgbLCuR3yrRoZDABjhsYUOCEn
mQIDAQAB
-----END PUBLIC KEY-----
)";

constexpr std::string_view kIssuer = "https://test-tenant.eu.auth0.com/";
constexpr std::string_view kAudience = "https://api.test-app/";
constexpr std::string_view kKid = "test-kid";

auto MakeRs256Signer() {
    return jwt::algorithm::rs256(std::string{kPubKey}, std::string{kPrivKey}, "", "");
}

auto MakeRs256Verifier() {
    return jwt::algorithm::rs256(std::string{kPubKey}, "", "", "");
}

auto BuildToken(
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now(),
    std::chrono::seconds lifetime = std::chrono::minutes(5),
    std::string iss = std::string{kIssuer},
    std::string aud = std::string{kAudience}
) -> std::string {
    return jwt::create<JsonTraits>()
        .set_type("JWT")
        .set_key_id(std::string{kKid})
        .set_issuer(iss)
        .set_audience(aud)
        .set_subject("auth0|test|alice")
        .set_issued_at(now)
        .set_expires_at(now + lifetime)
        .set_payload_claim("https://test-app/email", jwt::basic_claim<JsonTraits>(std::string{"alice@test.example"}))
        .sign(MakeRs256Signer());
}

}  // namespace

TEST(JwtValidator, ValidTokenRoundTrip) {
    auto token = BuildToken();
    auto decoded = jwt::decode<JsonTraits>(token);

    EXPECT_EQ(decoded.get_algorithm(), "RS256");
    EXPECT_EQ(decoded.get_issuer(), kIssuer);
    EXPECT_EQ(decoded.get_subject(), "auth0|test|alice");
    EXPECT_EQ(decoded.get_key_id(), kKid);

    auto verifier = jwt::verify<JsonTraits>()
                        .allow_algorithm(MakeRs256Verifier())
                        .with_issuer(std::string{kIssuer})
                        .with_audience(std::string{kAudience});
    EXPECT_NO_THROW(verifier.verify(decoded));
}

TEST(JwtValidator, ExpiredTokenIsRejected) {
    auto past = std::chrono::system_clock::now() - std::chrono::hours(2);
    auto token = BuildToken(past, std::chrono::minutes(5));

    auto decoded = jwt::decode<JsonTraits>(token);
    auto verifier = jwt::verify<JsonTraits>()
                        .allow_algorithm(MakeRs256Verifier())
                        .with_issuer(std::string{kIssuer})
                        .with_audience(std::string{kAudience});
    EXPECT_THROW(verifier.verify(decoded), std::exception);
}

TEST(JwtValidator, WrongAudienceIsRejected) {
    auto token = BuildToken();

    auto decoded = jwt::decode<JsonTraits>(token);
    auto verifier = jwt::verify<JsonTraits>()
                        .allow_algorithm(MakeRs256Verifier())
                        .with_issuer(std::string{kIssuer})
                        .with_audience(std::string{"https://api.WRONG/"});
    EXPECT_THROW(verifier.verify(decoded), std::exception);
}

TEST(JwtValidator, WrongIssuerIsRejected) {
    auto token = BuildToken();

    auto decoded = jwt::decode<JsonTraits>(token);
    auto verifier = jwt::verify<JsonTraits>()
                        .allow_algorithm(MakeRs256Verifier())
                        .with_issuer(std::string{"https://wrong-tenant.eu.auth0.com/"})
                        .with_audience(std::string{kAudience});
    EXPECT_THROW(verifier.verify(decoded), std::exception);
}

TEST(JwtValidator, CustomClaimRoundTrip) {
    auto token = BuildToken();
    auto decoded = jwt::decode<JsonTraits>(token);

    ASSERT_TRUE(decoded.has_payload_claim("https://test-app/email"));
    EXPECT_EQ(decoded.get_payload_claim("https://test-app/email").as_string(), "alice@test.example");
}

TEST(JwtValidator, PermissionsArrayRoundTrip) {
    picojson::array perms;
    perms.emplace_back(picojson::value{std::string{"read:channels"}});
    perms.emplace_back(picojson::value{std::string{"write:keys"}});

    auto now = std::chrono::system_clock::now();
    auto token = jwt::create<JsonTraits>()
                     .set_type("JWT")
                     .set_key_id(std::string{kKid})
                     .set_issuer(std::string{kIssuer})
                     .set_audience(std::string{kAudience})
                     .set_subject("auth0|test|alice")
                     .set_issued_at(now)
                     .set_expires_at(now + std::chrono::minutes(5))
                     .set_payload_claim("permissions", jwt::basic_claim<JsonTraits>(picojson::value{perms}))
                     .sign(MakeRs256Signer());

    auto decoded = jwt::decode<JsonTraits>(token);
    ASSERT_TRUE(decoded.has_payload_claim("permissions"));
    auto got = decoded.get_payload_claim("permissions").as_array();
    ASSERT_EQ(got.size(), 2u);

    std::unordered_set<std::string> set;
    for (const auto& p : got) {
        set.insert(JsonTraits::as_string(p));
    }
    EXPECT_EQ(set.count("read:channels"), 1u);
    EXPECT_EQ(set.count("write:keys"), 1u);
}
