using System.Security.Claims;

namespace Auth0ClaimsSample.Claims;

/// <summary>
/// Approach 1 from the design notes: flatten once, at sign-in, so the rest of
/// the app never touches JSON.
/// </summary>
public static class LisaClaimsEnricher
{
    /// <summary>Adds flattened LISA claims to the identity. Returns how many were added.</summary>
    public static int Enrich(ClaimsIdentity identity, LisaClaimsOptions options, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(options);

        var rawClaims = LisaClaimsParser.CollectRawClaims(identity, options).ToList();
        if (rawClaims.Count == 0)
        {
            logger?.LogDebug(
                "No LISA claim on the identity (looked for: {ClaimTypes})",
                string.Join(", ", options.EffectiveClaimTypes));
            return 0;
        }

        var entries = LisaClaimsParser.Parse(rawClaims, options);
        var flattened = LisaClaimsParser.Flatten(entries, options);

        identity.AddClaims(flattened);

        if (options.RemoveRawClaim)
        {
            foreach (var claim in rawClaims)
            {
                identity.TryRemoveClaim(claim);
            }
        }

        logger?.LogInformation(
            "Flattened {EntryCount} top-level LISA entries from {RawCount} raw claim(s) into {ClaimCount} claim(s)",
            entries.Count,
            rawClaims.Count,
            flattened.Count);

        return flattened.Count;
    }
}
