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

        var payload = LisaClaimsParser.ParsePayload(rawClaims, options);
        var flattened = LisaClaimsParser.Flatten(payload.Entries, options).ToList();

        // The envelope's own properties are per-user attributes, not records,
        // so they become claims in their own right rather than entry fields.
        var attributeClaims = options.EmitAttributeClaims
            ? payload.AttributeTexts
                .Select(pair => new Claim(
                    string.IsNullOrEmpty(options.AttributeClaimPrefix)
                        ? pair.Key
                        : $"{options.AttributeClaimPrefix}{pair.Key}",
                    pair.Value))
                .ToList()
            : new List<Claim>();

        // Never shadow a claim the IdP already issued - "_email" beside Auth0's
        // own "email" is fine, but two "_email" claims are not.
        var added = attributeClaims
            .Where(c => !identity.HasClaim(e => e.Type == c.Type))
            .ToList();

        identity.AddClaims(flattened);
        identity.AddClaims(added);

        if (options.RemoveRawClaim)
        {
            foreach (var claim in rawClaims)
            {
                identity.TryRemoveClaim(claim);
            }
        }

        logger?.LogInformation(
            "Flattened {EntryCount} top-level LISA entries from {RawCount} raw claim(s) into " +
            "{ClaimCount} claim(s), plus {AttributeCount} envelope attribute(s)",
            payload.Entries.Count,
            rawClaims.Count,
            flattened.Count,
            added.Count);

        return flattened.Count + added.Count;
    }
}
