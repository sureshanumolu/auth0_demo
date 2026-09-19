using System.Text.Json;
using System.Text.Json.Serialization;

namespace Auth0ClaimsSample.Models;

/// <summary>Nested object hanging off a <see cref="LisaEntry"/>.</summary>
public sealed class LisaAgency
{
    [JsonPropertyName("code")]
    public string? Code { get; set; }

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement> Extra { get; set; } = new();

    public override string ToString() =>
        string.IsNullOrEmpty(Code) ? Name ?? "(unknown agency)" : $"{Code} - {Name}";
}
