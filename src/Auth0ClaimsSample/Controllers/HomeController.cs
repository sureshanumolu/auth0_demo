using System.Diagnostics;
using System.Text.Json;
using Auth0ClaimsSample.Claims;
using Auth0ClaimsSample.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Auth0ClaimsSample.Controllers;

public sealed class HomeController : Controller
{
    private readonly ILisaProfileAccessor _lisa;
    private readonly LisaClaimsOptions _options;
    private readonly IWebHostEnvironment _environment;

    public HomeController(
        ILisaProfileAccessor lisa,
        IOptions<LisaClaimsOptions> options,
        IWebHostEnvironment environment)
    {
        _lisa = lisa;
        _options = options.Value;
        _environment = environment;
    }

    /// <summary>Renders the nested LISA tree for the signed-in user.</summary>
    public IActionResult Index() => View(_lisa.Current);

    /// <summary>
    /// Everything the authentication produced: the flat claim bag, the raw LISA
    /// claim as it arrived, the nested objects parsed out of it, and the
    /// underlying token response.
    ///
    /// The token sections are Development-only - an id_token on a page is a
    /// bearer credential, and this one carries the whole LISA payload.
    /// </summary>
    public async Task<IActionResult> Claims()
    {
        var showTokens = _environment.IsDevelopment();

        var rawClaims = LisaClaimsParser.CollectRawClaims(User, _options).ToList();
        var profile = _lisa.Current;

        var model = new ClaimsPageViewModel
        {
            Claims = User.Claims.ToList(),
            SearchedClaimTypes = _options.EffectiveClaimTypes,
            RawLisaClaims = rawClaims.Select(c =>
            {
                var formatted = JwtDisplay.TryFormatJson(c.Value);
                return new ClaimsPageViewModel.RawClaimView
                {
                    Type = c.Type,
                    ValueType = c.ValueType,
                    Value = formatted ?? c.Value,
                    IsJson = formatted is not null,
                };
            }).ToList(),
            ParsedProfileJson = profile.IsEmpty
                ? null
                : JsonSerializer.Serialize(profile.Entries, new JsonSerializerOptions { WriteIndented = true }),
            TopLevelEntries = profile.Entries.Count,
            TotalEntries = profile.All.Count(),
            ShowTokens = showTokens,
            IdToken = showTokens ? await ReadTokenAsync("id_token") : null,
            AccessToken = showTokens ? await ReadTokenAsync("access_token") : null,
            AuthenticationProperties = showTokens
                ? await ReadNonTokenPropertiesAsync()
                : Array.Empty<KeyValuePair<string, string?>>(),

            // Only worth computing when the lookup failed.
            ClaimTypeCensus = rawClaims.Count > 0
                ? Array.Empty<KeyValuePair<string, int>>()
                : User.Claims
                    .GroupBy(c => c.Type, StringComparer.Ordinal)
                    .Select(g => new KeyValuePair<string, int>(g.Key, g.Count()))
                    .OrderBy(p => p.Key, StringComparer.Ordinal)
                    .ToList(),
        };

        return View(model);
    }

    private async Task<ClaimsPageViewModel.TokenView?> ReadTokenAsync(string name)
    {
        var value = await HttpContext.GetTokenAsync(name);
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        var (header, payload, note) = JwtDisplay.Decode(value);

        return new ClaimsPageViewModel.TokenView
        {
            Name = name,
            Raw = value,
            HeaderJson = header,
            PayloadJson = payload,
            Note = note,
        };
    }

    /// <summary>Auth properties minus the tokens, which get their own sections.</summary>
    private async Task<IReadOnlyList<KeyValuePair<string, string?>>> ReadNonTokenPropertiesAsync()
    {
        var result = await HttpContext.AuthenticateAsync();

        return result.Properties?.Items
            .Where(i => !i.Key.StartsWith(".Token.", StringComparison.Ordinal))
            .OrderBy(i => i.Key, StringComparer.Ordinal)
            .ToList()
            ?? new List<KeyValuePair<string, string?>>();
    }

    /// <summary>
    /// Parses a sample payload with no Auth0 round trip, so the nested-claim
    /// logic can be exercised locally. Development only.
    /// </summary>
    [AllowAnonymous]
    public IActionResult Sample(string? name)
    {
        if (!_environment.IsDevelopment())
        {
            return NotFound();
        }

        var directory = Path.Combine(_environment.ContentRootPath, "..", "..", "samples");
        var file = Path.GetFullPath(Path.Combine(directory, $"{name ?? "lisa-dictionary"}.json"));

        // Keep the traversal inside samples/.
        if (!file.StartsWith(Path.GetFullPath(directory), StringComparison.OrdinalIgnoreCase) ||
            !System.IO.File.Exists(file))
        {
            return NotFound($"No sample payload at {file}");
        }

        var json = System.IO.File.ReadAllText(file);
        var entries = LisaClaimsParser.ParseValue(json, _options);
        var flattened = LisaClaimsParser.Flatten(entries, _options);

        return Json(
            new
            {
                source = Path.GetFileName(file),
                topLevelEntries = entries.Count,
                totalEntries = entries.SelectMany(e => e.SelfAndDescendants()).Count(),
                usernames = entries.SelectMany(e => e.SelfAndDescendants()).Select(e => e.Username),
                flattenedClaims = flattened.Select(c => new { type = c.Type, value = c.Value }),
                parsed = entries,
            },
            new JsonSerializerOptions { WriteIndented = true });
    }

    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error() =>
        View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
}
