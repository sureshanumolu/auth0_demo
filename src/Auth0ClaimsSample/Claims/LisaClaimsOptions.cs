using System.Linq;

namespace Auth0ClaimsSample.Claims;

/// <summary>Which half of a "key": value dictionary entry the key represents.</summary>
public enum LisaDictionaryKey
{
    Guid,
    Username,
}

/// <summary>
/// Controls how the raw LISA claim is located, parsed and projected onto the
/// <see cref="System.Security.Claims.ClaimsIdentity"/>. Bind from the "Lisa"
/// configuration section.
/// </summary>
public sealed class LisaClaimsOptions
{
    /// <summary>Used when nothing is configured. See <see cref="EffectiveClaimTypes"/>.</summary>
    private static readonly string[] DefaultClaimTypes = { LisaClaimTypes.Raw, LisaClaimTypes.Namespaced };

    /// <summary>
    /// Claim types to look for, in precedence order. Both names are worth
    /// checking: an enterprise IdP can pass "_lisa" straight through, while an
    /// Auth0 Action may namespace it for an OIDC-conformant client.
    ///
    /// Only the FIRST type that yields any claim is used - see
    /// <c>LisaClaimsParser.CollectRawClaims</c>.
    ///
    /// Deliberately empty by default. The configuration binder APPENDS to a
    /// collection that already holds items rather than replacing it, so seeding
    /// defaults here would make the "Lisa:ClaimTypes" array in appsettings.json
    /// unable to reorder or remove them - it could only add. Read through
    /// <see cref="EffectiveClaimTypes"/>, never directly.
    /// </summary>
    public List<string> ClaimTypes { get; set; } = new();

    /// <summary>
    /// The claim types actually searched: whatever was configured, or
    /// <see cref="DefaultClaimTypes"/> when configuration supplied none.
    /// Duplicates are dropped, first occurrence wins.
    /// </summary>
    public IReadOnlyList<string> EffectiveClaimTypes =>
        ClaimTypes.Count == 0
            ? DefaultClaimTypes
            : ClaimTypes.Distinct(StringComparer.Ordinal).ToList();

    /// <summary>Property names that hold nested LISA records.</summary>
    public List<string> NestedPropertyNames { get; set; } = new() { "children", "entries", "subEntries", "accounts", "delegates" };

    /// <summary>When the payload is a dictionary, what the key means.</summary>
    public LisaDictionaryKey DictionaryKeyIs { get; set; } = LisaDictionaryKey.Guid;

    /// <summary>Emit lisa_username / lisa_guid / lisa_role for every entry at every depth.</summary>
    public bool EmitValueClaims { get; set; } = true;

    /// <summary>Emit lisa_entry ("guid:username") so the pairing survives flattening.</summary>
    public bool EmitPairClaims { get; set; } = true;

    /// <summary>
    /// Emit the profile envelope's own properties (_auth0_guid, _email,
    /// _first_name, ...) as claims in their own right. They describe the user
    /// rather than any LISA record, so they are never folded into an entry.
    /// </summary>
    public bool EmitAttributeClaims { get; set; } = true;

    /// <summary>
    /// Prefix for attribute claim types. Empty keeps the IdP's own names
    /// (_email), which is usually what a consumer expects; set something like
    /// "lisa_attr" to namespace them away from collisions.
    /// </summary>
    public string AttributeClaimPrefix { get; set; } = string.Empty;

    /// <summary>
    /// Emit one claim per JSON leaf, typed by its path ("lisa:0.agency.code").
    /// Off by default: on a large payload this bloats the auth cookie.
    /// </summary>
    public bool EmitPathClaims { get; set; }

    /// <summary>
    /// Drop the raw claim after flattening. Shrinks the cookie, but on-demand
    /// re-parsing (ILisaProfileAccessor) then has nothing to read.
    /// </summary>
    public bool RemoveRawClaim { get; set; }

    /// <summary>Guard against pathological nesting in an attacker-influenced token.</summary>
    public int MaxDepth { get; set; } = 12;

    /// <summary>Throw instead of returning empty when the claim is not valid JSON.</summary>
    public bool ThrowOnMalformed { get; set; }
}
