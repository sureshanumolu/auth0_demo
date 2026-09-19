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
    {
        Entries = entries;
        RawClaimCount = rawClaimCount;
    }

    /// <summary>Top-level entries, in the order the IdP emitted them.</summary>
    public IReadOnlyList<LisaEntry> Entries { get; }

    /// <summary>How many raw claims the entries were parsed out of.</summary>
    public int RawClaimCount { get; }

    public bool IsEmpty => Entries.Count == 0;

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
