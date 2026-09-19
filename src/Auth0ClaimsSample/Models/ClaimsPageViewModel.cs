using System.Security.Claims;

namespace Auth0ClaimsSample.Models;

/// <summary>
/// Everything /Home/Claims shows: the flat claim bag, the raw LISA claim as it
/// arrived, the nested objects parsed out of it, and the underlying
/// authentication response.
/// </summary>
public sealed class ClaimsPageViewModel
{
    /// <summary>Every claim on the principal, flat, in arrival order.</summary>
    public IReadOnlyList<Claim> Claims { get; init; } = Array.Empty<Claim>();

    /// <summary>Claim types that were searched, in precedence order.</summary>
    public IReadOnlyList<string> SearchedClaimTypes { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Every distinct claim type actually on the principal, with a count. Shown
    /// when no LISA claim is found so the mismatch is visible rather than
    /// guessed at - a claim present in the id_token but absent here means it was
    /// dropped between the token and the cookie.
    /// </summary>
    public IReadOnlyList<KeyValuePair<string, int>> ClaimTypeCensus { get; init; } =
        Array.Empty<KeyValuePair<string, int>>();

    /// <summary>The LISA claim(s) that won precedence, pretty-printed.</summary>
    public IReadOnlyList<RawClaimView> RawLisaClaims { get; init; } = Array.Empty<RawClaimView>();

    /// <summary>The parsed nested tree, re-serialised so the structure is visible.</summary>
    public string? ParsedProfileJson { get; init; }

    public int TopLevelEntries { get; init; }

    public int TotalEntries { get; init; }

    /// <summary>Decoded id_token. Null outside Development or when SaveTokens is off.</summary>
    public TokenView? IdToken { get; init; }

    /// <summary>Decoded access_token, when it is a JWT. Null outside Development.</summary>
    public TokenView? AccessToken { get; init; }

    /// <summary>Non-token entries from the authentication properties.</summary>
    public IReadOnlyList<KeyValuePair<string, string?>> AuthenticationProperties { get; init; } =
        Array.Empty<KeyValuePair<string, string?>>();

    /// <summary>True when token sections are shown at all.</summary>
    public bool ShowTokens { get; init; }

    public sealed class RawClaimView
    {
        public string Type { get; init; } = string.Empty;

        public string ValueType { get; init; } = string.Empty;

        /// <summary>Indented when the value parsed as JSON, verbatim otherwise.</summary>
        public string Value { get; init; } = string.Empty;

        public bool IsJson { get; init; }
    }

    public sealed class TokenView
    {
        public string Name { get; init; } = string.Empty;

        /// <summary>The compact JWT exactly as issued.</summary>
        public string Raw { get; init; } = string.Empty;

        public string? HeaderJson { get; init; }

        /// <summary>The claims Auth0 actually put in the token, before .NET touched them.</summary>
        public string? PayloadJson { get; init; }

        /// <summary>Set when the value was not a three-part JWT.</summary>
        public string? Note { get; init; }
    }
}
