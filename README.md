# Auth0 nested LISA claims - ASP.NET Core MVC

Consumes a `_lisa` claim that carries **nested** records, in whatever shape the
IdP or Action emits, and projects it onto ordinary ASP.NET claims.

```
src/Auth0ClaimsSample      the web app
tests/Auth0ClaimsSample.Tests   28 parser tests
samples/                   payloads for local testing without a tenant
```

## Run it

```
dotnet test
dotnet run --project src/Auth0ClaimsSample --no-launch-profile --urls http://localhost:5080
```

`Auth0:Domain` and `Auth0:ClientId` are already pointed at the deployed
`WATech LISA Sample` client on `suresh-demo-2.cic-demo-platform.auth0app.com`.
The secret is held in user-secrets, not in `appsettings.json`.

The SDK defaults `ResponseType` to `id_token` and does **not** switch to code
flow merely because a secret is configured - `Program.cs` sets
`options.ResponseType = Code` explicitly when `Auth0:ClientSecret` is present.
This matters: a client whose `grant_types` omit `implicit` (the default for a
new Auth0 app) answers an `id_token` request with **403**. Both flows deliver
the LISA claim; only the code flow works against a default-configured client.

Keep the secret out of the config file:
`dotnet user-secrets set "Auth0:ClientSecret" "..."`.

### Local testing with no tenant

`GET /Home/Sample?name=lisa-dictionary` (Development only) parses a file from
`samples/` and returns the entries, the flattened claims and the parsed tree.
Sample names: `lisa-array`, `lisa-dictionary`, `lisa-nested`,
`lisa-scalar-dictionary`, `lisa-action-output`.

## Claim shapes handled

The original notes said the claim arrives as "a single claim whose Value is the
raw JSON array text". That is only true some of the time. When the ID token
holds an array of **objects**, `Microsoft.IdentityModel` expands it into **one
claim per array element**, each tagged `ValueType = "JSON"` - so
`FindFirst("_lisa").Value` returns only the *first* object and silently drops
the rest. `LisaClaimsParser` therefore reads `FindAll` and handles every shape:

| # | Shape | Example |
|---|-------|---------|
| 1 | whole array in one claim | `[{"guid":..,"username":..}, ..]` |
| 2 | one claim per object | two claims, each `{"guid":..,"username":..}` |
| 3 | dictionary keyed by guid | `{"DP6VP":{"username":"luke.harris"}}` |
| 4 | scalar dictionary | `{"DP6VP":"luke.harris"}` |
| 5 | wrapper object | `{"entries":[ .. ]}` |
| 6 | bare string | `luke.harris` |

Each may nest further records under `children`, `entries`, `subEntries`,
`accounts` or `delegates`, to any depth (capped by `Lisa:MaxDepth`).

Unrecognised properties are kept in `LisaEntry.Extra` rather than dropped.

## The two approaches, both wired up

1. **Flatten at sign-in** - `LisaClaimsEnricher` runs in `OnTokenValidated`
   (the authentication callback) and adds `lisa_username` / `lisa_guid` /
   `lisa_role` for every entry *at every depth*, so `[Authorize(Policy=..)]` and
   `User.HasClaim(..)` work normally. `lisa_entry` (`"guid:username"`) preserves
   the pairing that separate claims lose.

2. **Re-parse on demand** - `ILisaProfileAccessor.Current` returns the full
   nested `LisaProfile`, parsed once per request and cached in
   `HttpContext.Items`. Keeps pairing and nesting intact.

Turn on `Lisa:EmitPathClaims` for one claim per JSON leaf, typed by path
(`lisa:0.children[0].agency.code`). Off by default - it bloats the auth cookie.

## Configuration (`Lisa` section)

| Key | Default | Purpose |
|-----|---------|---------|
| `ClaimTypes` | `_lisa`, `https://watech.wa.gov/lisa` | claim names to look for |
| `NestedPropertyNames` | `children`, `entries`, ... | properties holding nested records |
| `DictionaryKeyIs` | `Guid` | what a dictionary key means |
| `EmitValueClaims` | `true` | `lisa_username` / `lisa_guid` / `lisa_role` |
| `EmitPairClaims` | `true` | `lisa_entry` = `guid:username` |
| `EmitPathClaims` | `false` | one claim per JSON leaf, typed by path |
| `RemoveRawClaim` | `false` | drop the raw claim after flattening |
| `MaxDepth` | `12` | recursion guard |
| `ThrowOnMalformed` | `false` | malformed claim fails sign-in instead of being skipped |

## Skipping the connection picker

Set `Auth0:Connection` to an enterprise connection name and every login goes
straight there - no "Continue" screen. Leave it empty for normal Universal
Login. For per-request selection, drop the setting and use
`.WithParameter("connection", ..)` in `AccountController.Login`.

## Tenant side

- `tenant/actions/lisaClaims/code.js` - post-login Action that emits the records
  as a dictionary keyed by guid, on both the ID and access token, namespaced
  (`https://watech.wa.gov/lisa`) and legacy (`_lisa`).
- `tenant/triggers/triggers.json` - `lisaClaims` runs **first** in post-login so
  the claim is set before any action that can redirect or deny.
- `tenant/clients/WATech LISA Sample.json` - the application, callbacks
  `http://localhost:5080/callback` and `https://localhost:5001/callback`.

### Deployed state

Live on `suresh-demo-2` as of 2026-09-19:

| Resource | Id |
|---|---|
| client `WATech LISA Sample` | `xpzxFY6hXtKtXWDLNhelYCXZZGRfUe5c` |
| action `lisaClaims` | `4f6ca208-06d7-4b74-a352-fa6c84697dac` (built, deployed) |
| post-login order | `lisaClaims` -> `add-role-to-tokens` -> `RequestRoleAccess.V1` -> `ApproverMFAStepUp` -> `ApproverReview.V1` |
| connection | `Username-Password-Authentication` enabled for the client |

Deployed by `scripts/deploy-lisa-claims.mjs` (creates only, refuses to overwrite)
and `scripts/enable-lisa-connection.mjs` (append-only). Verify with
`scripts/verify-lisa-deploy.mjs`.

**Not** `a0deploy import` - that pushes the whole `tenant/` directory, including
`flow-vault-connections` whose credential `setup` key does not survive export,
and would rewrite live approval infrastructure to deploy two new resources.
