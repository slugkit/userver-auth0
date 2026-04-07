# Setting up Auth0 for userver-auth0

This guide is the minimum Auth0 tenant configuration needed for the `JwtValidator` component to verify access tokens. It is **not** the comprehensive setup guide for any specific application — see your application's docs (e.g. `design-docs/backend/AUTH0_SETUP.md` in poke-me) for the full callback URL / SPA / custom action setup.

## What the validator needs

Five things, all read from `static_config.yaml`:

| Setting | Where it comes from |
|---|---|
| `domain` | Your Auth0 tenant's domain, e.g. `your-tenant.eu.auth0.com`. Found at the top of any application's settings. |
| `audience` | The API identifier you set when creating an Auth0 API. Becomes the `aud` claim. |
| `issuer` | `https://{domain}/` (note the trailing slash — Auth0 emits it verbatim). Defaults to this if you leave it empty. |
| `algorithms` | Allowed signing algorithms. Auth0 issues `RS256` by default; the validator accepts RS256 / RS384 / RS512. |
| `well_known_keys` | Path component appended to the issuer for the JWKS endpoint. Default `.well-known/jwks.json`. |

## Auth0 dashboard steps

1. **Create the API.** Applications → APIs → Create API. The Identifier becomes the `audience` (e.g. `https://api.your-app/`). RS256 is the default signing algorithm — keep it.
2. **Note the JWKS URL.** Auth0 publishes it at `https://{your-tenant}.auth0.com/.well-known/jwks.json`. The validator fetches this on startup and on every refresh interval.
3. **Add the API to your application.** When the SPA / mobile / backend client requests an access token, it must specify your API's identifier as the `audience` parameter — otherwise Auth0 issues a token for the userinfo endpoint instead, which won't pass `aud` validation.
4. **Optional: namespaced custom claims.** Auth0 puts the user's email in the `id_token` but not the `access_token`. If you need email (or other profile info) on the validated access token, add a Post-Login Action that copies them into a namespaced custom claim:
   ```javascript
   exports.onExecutePostLogin = async (event, api) => {
     const ns = 'https://your-app/';
     if (event.user.email) {
       api.accessToken.setCustomClaim(`${ns}email`, event.user.email);
     }
   };
   ```
   Then map the namespaced claim in the validator's `optional_claims`:
   ```yaml
   optional_claims:
     email: https://your-app/email
   ```

## Common pitfalls

- **Trailing slash on issuer.** Auth0 always appends `/` to the issuer URL in the `iss` claim. If your `issuer` config is `https://tenant.auth0.com` (no slash), validation fails with `issuer mismatch`. The validator will auto-derive `https://{domain}/` if you leave `issuer` empty — that's the safest option.
- **`aud` is an array, not a string.** Auth0 sometimes emits the audience as a JSON array. jwt-cpp handles this transparently inside `with_audience`, so if your config is `audience: "https://api.your-app/"` it matches both string and array forms.
- **Algorithm mismatch.** If your `algorithms` list omits the algorithm Auth0 actually uses, validation throws. Default Auth0 is RS256.
- **Stale JWKS.** When Auth0 rotates signing keys, the validator's cached JWKS may not have the new `kid` yet. The current implementation refreshes on `update-interval` (default 30 minutes); on-demand refresh on `kid` cache miss is a planned improvement.
- **Wrong audience requested by client.** A token issued for the wrong API has the wrong `aud`. Make sure your client requests `audience: https://api.your-app/` exactly.
