using System.Text;
using System.Text.Json;

namespace Auth0ClaimsSample.Claims;

/// <summary>
/// Decodes a compact JWT for DISPLAY only - it does not verify the signature.
/// The OIDC middleware already validated the token before the principal was
/// built; this exists so the page can show what Auth0 actually sent.
/// </summary>
public static class JwtDisplay
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    /// <summary>Pretty-prints JSON, returning null when the text is not JSON.</summary>
    public static string? TryFormatJson(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(text);
            return JsonSerializer.Serialize(document.RootElement, Indented);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Decodes the header and payload segments of a compact JWT.</summary>
    public static (string? Header, string? Payload, string? Note) Decode(string? jwt)
    {
        if (string.IsNullOrWhiteSpace(jwt))
        {
            return (null, null, "no token");
        }

        var parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            // Auth0 issues opaque access tokens when no audience is requested.
            return (null, null, $"not a JWT ({parts.Length} segment(s)) - opaque token");
        }

        var header = TryFormatJson(DecodeSegment(parts[0]));
        var payload = TryFormatJson(DecodeSegment(parts[1]));

        return (header, payload, payload is null ? "payload did not decode as JSON" : null);
    }

    /// <summary>base64url -> UTF-8. Padding is stripped in JWTs and must be restored.</summary>
    private static string? DecodeSegment(string segment)
    {
        var normalised = segment.Replace('-', '+').Replace('_', '/');
        normalised = (normalised.Length % 4) switch
        {
            2 => normalised + "==",
            3 => normalised + "=",
            0 => normalised,
            _ => null!,
        };

        if (normalised is null)
        {
            return null;
        }

        try
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(normalised));
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
