using System.Security.Claims;
using Auth0ClaimsSample.Models;

namespace Auth0ClaimsSample.Claims;

/// <summary>
/// Approach 2 from the design notes: leave the raw claim alone and re-parse on
/// demand. Keeps guid/username pairing and nesting intact.
/// </summary>
public static class LisaClaimsPrincipalExtensions
{
    public static LisaProfile GetLisaProfile(this ClaimsPrincipal principal, LisaClaimsOptions options)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(options);

        var rawClaims = LisaClaimsParser.CollectRawClaims(principal, options).ToList();
        if (rawClaims.Count == 0)
        {
            return LisaProfile.Empty;
        }

        return new LisaProfile(LisaClaimsParser.Parse(rawClaims, options), rawClaims.Count);
    }

    /// <summary>Reads the flattened claims - only works after LisaClaimsEnricher has run.</summary>
    public static IEnumerable<string> LisaUsernames(this ClaimsPrincipal principal) =>
        principal.FindAll(LisaClaimTypes.Username).Select(c => c.Value);

    public static IEnumerable<string> LisaGuids(this ClaimsPrincipal principal) =>
        principal.FindAll(LisaClaimTypes.Guid).Select(c => c.Value);

    public static bool HasLisaUsername(this ClaimsPrincipal principal, string username) =>
        principal.HasClaim(c =>
            c.Type == LisaClaimTypes.Username &&
            string.Equals(c.Value, username, StringComparison.OrdinalIgnoreCase));

    public static bool HasLisaRole(this ClaimsPrincipal principal, string role) =>
        principal.HasClaim(c =>
            c.Type == LisaClaimTypes.Role &&
            string.Equals(c.Value, role, StringComparison.OrdinalIgnoreCase));
}
