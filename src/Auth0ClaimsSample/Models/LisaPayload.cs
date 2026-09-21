using System.Text.Json;

namespace Auth0ClaimsSample.Models;

/// <summary>
/// One parsed LISA claim, split into its two halves.
///
/// The IdP sends a profile envelope:
///
///   { "_auth0_guid": "..", "_email": "..", "_lisa": [ {..}, {..} ] }
///
/// The scalars beside the list describe the USER; the list holds the LISA
/// RECORDS. Merging them loses that distinction - the scalars end up parsed as
/// records keyed by their property name - so they are kept apart here.
/// </summary>
public sealed class LisaPayload
{
    public static readonly LisaPayload Empty =
        new(new Dictionary<string, JsonElement>(), Array.Empty<LisaEntry>());

    public LisaPayload(IReadOnlyDictionary<string, JsonElement> attributes, IReadOnlyList<LisaEntry> entries)
    {
        Attributes = attributes;
        Entries = entries;
    }

    /// <summary>
    /// Root-level properties sitting BESIDE the record list (_auth0_guid,
    /// _email, _first_name, ...). Kept as <see cref="JsonElement"/> so a nested
    /// object survives; use <see cref="AttributeText"/> for a display string.
    /// </summary>
    public IReadOnlyDictionary<string, JsonElement> Attributes { get; }

    /// <summary>The records from the list, nesting intact.</summary>
    public IReadOnlyList<LisaEntry> Entries { get; }

    public bool IsEmpty => Attributes.Count == 0 && Entries.Count == 0;

    /// <summary>An attribute as text: the string itself, or its JSON otherwise.</summary>
    public string? AttributeText(string name) =>
        Attributes.TryGetValue(name, out var value)
            ? value.ValueKind == JsonValueKind.String ? value.GetString() : value.GetRawText()
            : null;

    /// <summary>Every attribute as a name/text pair, in arrival order.</summary>
    public IEnumerable<KeyValuePair<string, string>> AttributeTexts =>
        Attributes.Select(pair => new KeyValuePair<string, string>(
            pair.Key,
            pair.Value.ValueKind == JsonValueKind.String
                ? pair.Value.GetString() ?? string.Empty
                : pair.Value.GetRawText()));
}
