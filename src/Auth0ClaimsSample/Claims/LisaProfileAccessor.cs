using Auth0ClaimsSample.Models;
using Microsoft.Extensions.Options;

namespace Auth0ClaimsSample.Claims;

/// <summary>Per-request access to the parsed LISA payload.</summary>
public interface ILisaProfileAccessor
{
    LisaProfile Current { get; }
}

/// <summary>
/// Re-parses the raw claim once per request and caches it in HttpContext.Items,
/// so "parse on demand" costs one parse per request rather than one per read.
/// </summary>
internal sealed class LisaProfileAccessor : ILisaProfileAccessor
{
    private const string CacheKey = "__lisa_profile";

    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly LisaClaimsOptions _options;

    public LisaProfileAccessor(IHttpContextAccessor httpContextAccessor, IOptions<LisaClaimsOptions> options)
    {
        _httpContextAccessor = httpContextAccessor;
        _options = options.Value;
    }

    public LisaProfile Current
    {
        get
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext?.User is null)
            {
                return LisaProfile.Empty;
            }

            if (httpContext.Items.TryGetValue(CacheKey, out var cached) && cached is LisaProfile cachedProfile)
            {
                return cachedProfile;
            }

            var profile = httpContext.User.GetLisaProfile(_options);
            httpContext.Items[CacheKey] = profile;
            return profile;
        }
    }
}
