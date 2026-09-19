using System.Collections.Generic;
using System.Linq;
using Auth0ClaimsSample.Claims;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Auth0ClaimsSample.Tests;

/// <summary>
/// Pins how the "Lisa" configuration section lands on LisaClaimsOptions.
///
/// The binder APPENDS to a collection that already holds items rather than
/// replacing it. LisaClaimsOptions.ClaimTypes is therefore empty by default and
/// read through EffectiveClaimTypes, so appsettings.json really is authoritative
/// - including its ORDER, which decides claim precedence.
/// </summary>
public class OptionsBindingTests
{
    private static LisaClaimsOptions Bind(Dictionary<string, string?> values)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        var services = new ServiceCollection();
        services.AddLisaClaims(configuration.GetSection("Lisa"));

        return services.BuildServiceProvider()
            .GetRequiredService<IOptions<LisaClaimsOptions>>().Value;
    }

    [Fact]
    public void ClaimTypes_FromConfiguration_AreUsedExactlyAndInOrder()
    {
        var options = Bind(new Dictionary<string, string?>
        {
            ["Lisa:ClaimTypes:0"] = "_lisa",
            ["Lisa:ClaimTypes:1"] = "https://watech.wa.gov/lisa",
        });

        Assert.Equal(
            new[] { "_lisa", "https://watech.wa.gov/lisa" },
            options.EffectiveClaimTypes);
    }

    [Fact]
    public void ClaimTypes_DuplicatesInConfiguration_AreCollapsed()
    {
        var options = Bind(new Dictionary<string, string?>
        {
            ["Lisa:ClaimTypes:0"] = "_lisa",
            ["Lisa:ClaimTypes:1"] = "_lisa",
        });

        Assert.Equal(new[] { "_lisa" }, options.EffectiveClaimTypes);
    }

    [Fact]
    public void ScalarSettings_FromConfiguration_Override()
    {
        var options = Bind(new Dictionary<string, string?>
        {
            ["Lisa:EmitPathClaims"] = "true",
            ["Lisa:MaxDepth"] = "3",
        });

        Assert.True(options.EmitPathClaims);
        Assert.Equal(3, options.MaxDepth);
    }

    [Fact]
    public void EmptySection_LeavesDefaultsIntact()
    {
        var options = Bind(new Dictionary<string, string?>());

        Assert.Empty(options.ClaimTypes);
        Assert.Equal(
            new[] { LisaClaimTypes.Raw, LisaClaimTypes.Namespaced },
            options.EffectiveClaimTypes);
    }
}
