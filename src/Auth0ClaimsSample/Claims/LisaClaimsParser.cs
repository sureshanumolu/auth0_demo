using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Auth0ClaimsSample.Models;

namespace Auth0ClaimsSample.Claims;

/// <summary>
/// Turns the raw LISA claim into <see cref="LisaEntry"/> objects, and those
/// objects back into flat claims.
///
/// The claim arrives in more shapes than the obvious one, so every shape below
/// is handled:
///
///   1. one claim holding a whole JSON array   [{"guid":..,"username":..}, ..]
///   2. several claims, one JSON object each   {"guid":..,"username":..}
///      (this is what Microsoft.IdentityModel actually produces for an array of
///      objects in a JWT - it expands the array into one claim per element and
///      tags each with ValueType "JSON")
///   3. a dictionary keyed by guid             {"DP6VP..":{"username":".."}}
///   4. a scalar dictionary                    {"DP6VP..":"luke.harris"}
///   5. a wrapper object                       {"entries":[ .. ]}
///   6. a bare string                          "luke.harris"
///
/// ...each of which may nest further entries to arbitrary depth.
/// </summary>
public static class LisaClaimsParser
{
    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
    };

    private static readonly string[] GuidNames = { "guid", "userGuid", "lisaGuid", "user_guid" };
    private static readonly string[] UsernameNames = { "username", "userName", "user_name", "user", "login" };
    private static readonly string[] RoleNames = { "roles", "role" };
    private static readonly string[] AgencyNames = { "agency", "org", "organization" };

    // ---------------------------------------------------------------- locate

    public static IEnumerable<Claim> CollectRawClaims(ClaimsPrincipal principal, LisaClaimsOptions options)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(options);
        return CollectFirstMatch(principal.FindAll, options);
    }

    public static IEnumerable<Claim> CollectRawClaims(ClaimsIdentity identity, LisaClaimsOptions options)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(options);
        return CollectFirstMatch(identity.FindAll, options);
    }

    /// <summary>
    /// Returns every claim of the FIRST configured type that yields any, not the
    /// union across types.
    ///
    /// An Action commonly emits the same payload twice - namespaced (which an
    /// OIDC-conformant client requires) and as the legacy bare name, for apps
    /// written before the namespace existed. Both land on the identity, so
    /// unioning them parses one payload twice and every entry appears double.
    /// They are alternative names for one payload, not two payloads.
    ///
    /// All claims of the winning type are returned, so shape 2 - an array of
    /// objects expanded by Microsoft.IdentityModel into one claim per element,
    /// all sharing a type - still parses completely.
    /// </summary>
    private static IEnumerable<Claim> CollectFirstMatch(
        Func<string, IEnumerable<Claim>> findAll,
        LisaClaimsOptions options)
    {
        foreach (var type in options.EffectiveClaimTypes)
        {
            var claims = findAll(type).ToList();
            if (claims.Count > 0)
            {
                return claims;
            }
        }

        return Array.Empty<Claim>();
    }

    // ----------------------------------------------------------------- parse

    public static IReadOnlyList<LisaEntry> Parse(IEnumerable<Claim> claims, LisaClaimsOptions options)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(options);

        var entries = new List<LisaEntry>();
        foreach (var claim in claims)
        {
            entries.AddRange(ParseValue(claim.Value, options));
        }

        return entries;
    }

    /// <summary>
    /// Parse claims into records AND the envelope attributes beside them.
    ///
    /// <see cref="Parse"/> returns records only, which is all a flat consumer
    /// needs. When the payload is a profile wrapper the scalars sitting next to
    /// the list - _auth0_guid, _email, _first_name - describe the user rather
    /// than any record, and this keeps the two apart instead of discarding the
    /// former.
    /// </summary>
    public static LisaPayload ParsePayload(IEnumerable<Claim> claims, LisaClaimsOptions options)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(options);

        var attributes = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        var entries = new List<LisaEntry>();

        foreach (var claim in claims)
        {
            var payload = ParsePayloadValue(claim.Value, options);

            foreach (var pair in payload.Attributes)
            {
                // First claim wins, so a multi-claim array cannot keep
                // overwriting attributes with the same values.
                attributes.TryAdd(pair.Key, pair.Value);
            }

            entries.AddRange(payload.Entries);
        }

        return new LisaPayload(attributes, entries);
    }

    /// <summary>Parse one claim value into records plus envelope attributes.</summary>
    public static LisaPayload ParsePayloadValue(string? value, LisaClaimsOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(value))
        {
            return LisaPayload.Empty;
        }

        var trimmed = value.Trim();
        if (trimmed[0] != '{')
        {
            // Only an object can carry attributes beside the list.
            return new LisaPayload(LisaPayload.Empty.Attributes, ParseValue(trimmed, options));
        }

        try
        {
            using var document = JsonDocument.Parse(trimmed, DocumentOptions);
            var root = document.RootElement;

            // Not a wrapper: an entry, or a dictionary of entries. No envelope.
            if (LooksLikeEntry(root) || !TryFindNested(root, options, out var nested))
            {
                return new LisaPayload(
                    LisaPayload.Empty.Attributes,
                    ReadEntries(root, options, 0));
            }

            var attributes = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
            {
                if (!IsNestedName(property.Name, options))
                {
                    // Clone() detaches the value from the JsonDocument we are
                    // about to dispose.
                    attributes[property.Name] = property.Value.Clone();
                }
            }

            return new LisaPayload(attributes, ReadEntries(nested, options, 1));
        }
        catch (JsonException)
        {
            if (options.ThrowOnMalformed)
            {
                throw;
            }

            return LisaPayload.Empty;
        }
    }

    /// <summary>Parse a single claim value (shapes 1-6 above).</summary>
    public static IReadOnlyList<LisaEntry> ParseValue(string? value, LisaClaimsOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(value))
        {
            return Array.Empty<LisaEntry>();
        }

        var trimmed = value.Trim();

        // Not JSON: the IdP sent a bare username.
        if (trimmed[0] != '[' && trimmed[0] != '{')
        {
            return new[] { new LisaEntry { Username = trimmed } };
        }

        try
        {
            using var document = JsonDocument.Parse(trimmed, DocumentOptions);
            return ReadEntries(document.RootElement, options, 0);
        }
        catch (JsonException)
        {
            // A single malformed claim must not fail the whole sign-in.
            if (options.ThrowOnMalformed)
            {
                throw;
            }

            return Array.Empty<LisaEntry>();
        }
    }

    private static List<LisaEntry> ReadEntries(JsonElement element, LisaClaimsOptions options, int depth)
    {
        var entries = new List<LisaEntry>();
        if (depth > options.MaxDepth)
        {
            return entries;
        }

        switch (element.ValueKind)
        {
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    entries.AddRange(ReadEntries(item, options, depth + 1));
                }

                break;

            case JsonValueKind.Object:
                if (LooksLikeEntry(element))
                {
                    entries.Add(ReadEntry(element, options, depth));
                }
                else if (TryFindNested(element, options, out var nested))
                {
                    // Wrapper: { "entries": [ ... ] }
                    entries.AddRange(ReadEntries(nested, options, depth + 1));
                }
                else
                {
                    // Dictionary: { "<key>": <entry>, ... }
                    foreach (var property in element.EnumerateObject())
                    {
                        entries.AddRange(ReadKeyedEntries(property, options, depth));
                    }
                }

                break;

            case JsonValueKind.String:
                var text = element.GetString();
                if (!string.IsNullOrWhiteSpace(text))
                {
                    entries.Add(new LisaEntry { Username = text });
                }

                break;
        }

        return entries;
    }

    /// <summary>
    /// A dictionary key carries identity the value may omit, so
    /// { "DP6VP..": { "username": "luke.harris" } } still yields both halves.
    /// </summary>
    private static List<LisaEntry> ReadKeyedEntries(JsonProperty property, LisaClaimsOptions options, int depth)
    {
        var entries = ReadEntries(property.Value, options, depth + 1);

        foreach (var entry in entries)
        {
            if (options.DictionaryKeyIs == LisaDictionaryKey.Guid)
            {
                if (string.IsNullOrEmpty(entry.Guid))
                {
                    entry.Guid = property.Name;
                }
            }
            else if (string.IsNullOrEmpty(entry.Username))
            {
                entry.Username = property.Name;
            }
        }

        return entries;
    }

    private static LisaEntry ReadEntry(JsonElement element, LisaClaimsOptions options, int depth)
    {
        var entry = new LisaEntry();

        foreach (var property in element.EnumerateObject())
        {
            if (IsAnyOf(property.Name, GuidNames))
            {
                entry.Guid = AsString(property.Value);
            }
            else if (IsAnyOf(property.Name, UsernameNames))
            {
                entry.Username = AsString(property.Value);
            }
            else if (IsAnyOf(property.Name, RoleNames))
            {
                entry.Roles.AddRange(AsStringList(property.Value));
            }
            else if (IsAnyOf(property.Name, AgencyNames))
            {
                entry.Agency = ReadAgency(property.Value);
            }
            else if (IsNestedName(property.Name, options))
            {
                entry.Children.AddRange(ReadEntries(property.Value, options, depth + 1));
            }
            else
            {
                // Clone() detaches the value from the JsonDocument we are about
                // to dispose - without it every Extra read would throw.
                entry.Extra[property.Name] = property.Value.Clone();
            }
        }

        return entry;
    }

    private static LisaAgency? ReadAgency(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.String)
        {
            return new LisaAgency { Code = element.GetString() };
        }

        if (element.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var agency = new LisaAgency();
        foreach (var property in element.EnumerateObject())
        {
            if (string.Equals(property.Name, "code", StringComparison.OrdinalIgnoreCase))
            {
                agency.Code = AsString(property.Value);
            }
            else if (string.Equals(property.Name, "name", StringComparison.OrdinalIgnoreCase))
            {
                agency.Name = AsString(property.Value);
            }
            else
            {
                agency.Extra[property.Name] = property.Value.Clone();
            }
        }

        return agency;
    }

    private static bool LooksLikeEntry(JsonElement element)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (IsAnyOf(property.Name, GuidNames) ||
                IsAnyOf(property.Name, UsernameNames) ||
                IsAnyOf(property.Name, RoleNames) ||
                IsAnyOf(property.Name, AgencyNames))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryFindNested(JsonElement element, LisaClaimsOptions options, out JsonElement nested)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (IsNestedName(property.Name, options) &&
                property.Value.ValueKind is JsonValueKind.Array or JsonValueKind.Object)
            {
                nested = property.Value;
                return true;
            }
        }

        nested = default;
        return false;
    }

    // --------------------------------------------------------------- flatten

    /// <summary>
    /// Project entries onto flat claims so [Authorize(Policy=..)] and
    /// User.HasClaim(..) work without any JSON awareness.
    /// </summary>
    public static IReadOnlyList<Claim> Flatten(IEnumerable<LisaEntry> entries, LisaClaimsOptions options)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(options);

        var claims = new List<Claim>();
        var index = 0;
        foreach (var entry in entries)
        {
            FlattenEntry(entry, index.ToString(CultureInfo.InvariantCulture), claims, options, 0);
            index++;
        }

        return Deduplicate(claims);
    }

    private static void FlattenEntry(
        LisaEntry entry,
        string path,
        List<Claim> claims,
        LisaClaimsOptions options,
        int depth)
    {
        if (depth > options.MaxDepth)
        {
            return;
        }

        if (options.EmitValueClaims)
        {
            if (!string.IsNullOrEmpty(entry.Username))
            {
                claims.Add(new Claim(LisaClaimTypes.Username, entry.Username));
            }

            if (!string.IsNullOrEmpty(entry.Guid))
            {
                claims.Add(new Claim(LisaClaimTypes.Guid, entry.Guid));
            }

            foreach (var role in entry.Roles.Where(r => !string.IsNullOrEmpty(r)))
            {
                claims.Add(new Claim(LisaClaimTypes.Role, role));
            }
        }

        if (options.EmitPairClaims && (entry.Guid is not null || entry.Username is not null))
        {
            claims.Add(new Claim(LisaClaimTypes.Entry, $"{entry.Guid}:{entry.Username}"));
        }

        if (options.EmitPathClaims)
        {
            AddPathClaim(claims, $"{path}.guid", entry.Guid);
            AddPathClaim(claims, $"{path}.username", entry.Username);

            for (var i = 0; i < entry.Roles.Count; i++)
            {
                AddPathClaim(claims, $"{path}.roles[{i}]", entry.Roles[i]);
            }

            if (entry.Agency is not null)
            {
                AddPathClaim(claims, $"{path}.agency.code", entry.Agency.Code);
                AddPathClaim(claims, $"{path}.agency.name", entry.Agency.Name);
                foreach (var extra in entry.Agency.Extra)
                {
                    FlattenElement(extra.Value, $"{path}.agency.{extra.Key}", claims, options, depth + 1);
                }
            }

            foreach (var extra in entry.Extra)
            {
                FlattenElement(extra.Value, $"{path}.{extra.Key}", claims, options, depth + 1);
            }
        }

        for (var i = 0; i < entry.Children.Count; i++)
        {
            FlattenEntry(entry.Children[i], $"{path}.children[{i}]", claims, options, depth + 1);
        }
    }

    private static void FlattenElement(
        JsonElement element,
        string path,
        List<Claim> claims,
        LisaClaimsOptions options,
        int depth)
    {
        if (depth > options.MaxDepth)
        {
            return;
        }

        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    FlattenElement(property.Value, $"{path}.{property.Name}", claims, options, depth + 1);
                }

                break;

            case JsonValueKind.Array:
                var index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    FlattenElement(item, $"{path}[{index}]", claims, options, depth + 1);
                    index++;
                }

                break;

            default:
                AddPathClaim(claims, path, AsString(element));
                break;
        }
    }

    private static void AddPathClaim(List<Claim> claims, string path, string? value)
    {
        if (!string.IsNullOrEmpty(value))
        {
            claims.Add(new Claim($"{LisaClaimTypes.PathPrefix}{path}", value));
        }
    }

    private static List<Claim> Deduplicate(List<Claim> claims)
    {
        var seen = new HashSet<(string Type, string Value)>();
        var result = new List<Claim>(claims.Count);

        foreach (var claim in claims)
        {
            if (seen.Add((claim.Type, claim.Value)))
            {
                result.Add(claim);
            }
        }

        return result;
    }

    // --------------------------------------------------------------- helpers

    private static bool IsAnyOf(string name, string[] candidates) =>
        candidates.Any(candidate => string.Equals(candidate, name, StringComparison.OrdinalIgnoreCase));

    private static bool IsNestedName(string name, LisaClaimsOptions options) =>
        options.NestedPropertyNames.Any(candidate => string.Equals(candidate, name, StringComparison.OrdinalIgnoreCase));

    private static string? AsString(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String => element.GetString(),
        JsonValueKind.Number => element.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Null or JsonValueKind.Undefined => null,
        _ => element.GetRawText(),
    };

    private static IEnumerable<string> AsStringList(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                var value = AsString(item);
                if (!string.IsNullOrEmpty(value))
                {
                    yield return value;
                }
            }
        }
        else
        {
            var value = AsString(element);
            if (!string.IsNullOrEmpty(value))
            {
                yield return value;
            }
        }
    }
}
