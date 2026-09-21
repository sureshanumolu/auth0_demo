using System.Text.Json;

namespace Auth0ClaimsSample.Models;

/// <summary>
/// The parsed LISA payload for one signed-in user. Produced once per request by
/// <c>ILisaProfileAccessor</c> so views and controllers never re-parse the raw
/// claim themselves.
/// </summary>
public sealed class LisaProfile
{
    public static readonly LisaProfile Empty = new(Array.Empty<LisaEntry>(), 0);

    public LisaProfile(IReadOnlyList<LisaEntry> entries, int rawClaimCount)
        : this(entries, rawClaimCount, new Dictionary<string, JsonElement>())
    {
    }

    public LisaProfile(
        IReadOnlyList<LisaEntry> entries,
        int rawClaimCount,
        IReadOnlyDictionary<string, JsonElement> attributes)
    {
        Entries = entries;
        RawClaimCount = rawClaimCount;
        Attributes = attributes;
    }

    /// <summary>Top-level entries, in the order the IdP emitted them.</summary>
    public IReadOnlyList<LisaEntry> Entries { get; }

    /// <summary>
    /// Root-level properties that sat BESIDE the record list in the profile
    /// envelope (_auth0_guid, _email, _first_name, ...). These describe the
    /// user, not any record, so they are kept out of <see cref="Entries"/>.
    /// </summary>
    public IReadOnlyDictionary<string, JsonElement> Attributes { get; }

    /// <summary>An envelope attribute as text, or null when absent.</summary>
    public string? Attribute(string name) =>
        Attributes.TryGetValue(name, out var value)
            ? value.ValueKind == JsonValueKind.String ? value.GetString() : value.GetRawText()
            : null;

    /// <summary>Every envelope attribute as a name/text pair.</summary>
    public IEnumerable<KeyValuePair<string, string>> AttributeTexts =>
        Attributes.Select(pair => new KeyValuePair<string, string>(
            pair.Key,
            pair.Value.ValueKind == JsonValueKind.String
                ? pair.Value.GetString() ?? string.Empty
                : pair.Value.GetRawText()));

    /// <summary>How many raw claims the entries were parsed out of.</summary>
    public int RawClaimCount { get; }

    public bool IsEmpty => Entries.Count == 0 && Attributes.Count == 0;

    /// <summary>Every entry at every depth, flattened depth-first.</summary>
    public IEnumerable<LisaEntry> All => Entries.SelectMany(e => e.SelfAndDescendants());

    public IEnumerable<string> Usernames =>
        All.Select(e => e.Username).Where(u => !string.IsNullOrEmpty(u)).Select(u => u!).Distinct();

    public IEnumerable<string> Guids =>
        All.Select(e => e.Guid).Where(g => !string.IsNullOrEmpty(g)).Select(g => g!).Distinct();

    public IEnumerable<string> Roles =>
        All.SelectMany(e => e.Roles).Where(r => !string.IsNullOrEmpty(r)).Distinct();

    public LisaEntry? FindByUsername(string username) =>
        All.FirstOrDefault(e => string.Equals(e.Username, username, StringComparison.OrdinalIgnoreCase));

    public LisaEntry? FindByGuid(string guid) =>
        All.FirstOrDefault(e => string.Equals(e.Guid, guid, StringComparison.OrdinalIgnoreCase));
}
