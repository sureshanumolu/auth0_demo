using System.Text.Json;
using System.Text.Json.Serialization;

namespace Auth0ClaimsSample.Models;

/// <summary>
/// One LISA record. Nothing is guaranteed to be present: the upstream IdP may
/// emit a bare username, a { guid, username } pair, or a deep tree of delegated
/// accounts. Unrecognised properties are preserved in <see cref="Extra"/> so the
/// app never silently drops data when the LISA schema grows.
/// </summary>
public sealed class LisaEntry
{
    [JsonPropertyName("guid")]
    public string? Guid { get; set; }

    [JsonPropertyName("username")]
    public string? Username { get; set; }

    [JsonPropertyName("agency")]
    public LisaAgency? Agency { get; set; }

    [JsonPropertyName("roles")]
    public List<string> Roles { get; set; } = new();

    /// <summary>Nested LISA records (delegated / subordinate accounts).</summary>
    [JsonPropertyName("children")]
    public List<LisaEntry> Children { get; set; } = new();

    /// <summary>Any property the model does not know about, kept verbatim.</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Extra { get; set; } = new();

    /// <summary>This entry followed by every descendant, depth-first.</summary>
    public IEnumerable<LisaEntry> SelfAndDescendants()
    {
        yield return this;
        foreach (var child in Children)
        {
            foreach (var descendant in child.SelfAndDescendants())
            {
                yield return descendant;
            }
        }
    }

    public override string ToString() =>
        string.IsNullOrEmpty(Guid) ? Username ?? "(empty)" : $"{Username} ({Guid})";
}
