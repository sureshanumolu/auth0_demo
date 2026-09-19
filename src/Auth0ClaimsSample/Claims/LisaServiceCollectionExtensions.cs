namespace Auth0ClaimsSample.Claims;

public static class LisaServiceCollectionExtensions
{
    /// <summary>Registers LISA options and the per-request profile accessor.</summary>
    public static IServiceCollection AddLisaClaims(
        this IServiceCollection services,
        IConfiguration? configuration = null)
    {
        services.AddHttpContextAccessor();

        if (configuration is not null)
        {
            services.Configure<LisaClaimsOptions>(configuration);
        }
        else
        {
            services.AddOptions<LisaClaimsOptions>();
        }

        services.AddScoped<ILisaProfileAccessor, LisaProfileAccessor>();
        return services;
    }
}
