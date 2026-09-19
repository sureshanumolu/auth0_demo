using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Claims;
using Auth0.AspNetCore.Authentication;
using Auth0ClaimsSample.Claims;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

// LISA options ("Lisa" section) + per-request ILisaProfileAccessor.
builder.Services.AddLisaClaims(builder.Configuration.GetSection("Lisa"));

builder.Services.AddAuth0WebAppAuthentication(options =>
{
    options.Domain = builder.Configuration["Auth0:Domain"] ?? string.Empty;
    options.ClientId = builder.Configuration["Auth0:ClientId"] ?? string.Empty;

    // The SDK defaults ResponseType to id_token and does NOT switch to code
    // flow on its own just because a secret is present, so set it explicitly.
    // A client whose grant_types omit "implicit" rejects id_token with a 403.
    var clientSecret = builder.Configuration["Auth0:ClientSecret"];
    if (!string.IsNullOrWhiteSpace(clientSecret))
    {
        options.ClientSecret = clientSecret;
        options.ResponseType = OpenIdConnectResponseType.Code;
    }

    options.Scope = builder.Configuration["Auth0:Scope"] ?? "openid profile email";

    // Skip Auth0's connection picker ("Continue" screen) by sending every
    // /Account/Login challenge straight to one enterprise connection. Leave
    // Auth0:Connection unset to keep the normal Universal Login experience.
    var connection = builder.Configuration["Auth0:Connection"];
    if (!string.IsNullOrWhiteSpace(connection))
    {
        options.LoginParameters = new Dictionary<string, string> { { "connection", connection } };
    }

    options.OpenIdConnectEvents = new OpenIdConnectEvents
    {
        // The authentication callback. The ID token has been validated and
        // projected onto a ClaimsPrincipal; this is where the nested LISA
        // payload becomes ordinary claims.
        OnTokenValidated = context =>
        {
            if (context.Principal?.Identity is ClaimsIdentity identity)
            {
                var services = context.HttpContext.RequestServices;
                var lisaOptions = services.GetRequiredService<IOptions<LisaClaimsOptions>>().Value;
                var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("Lisa");

                LisaClaimsEnricher.Enrich(identity, lisaOptions, logger);
            }

            return Task.CompletedTask;
        },

        OnRemoteFailure = context =>
        {
            var logger = context.HttpContext.RequestServices
                .GetRequiredService<ILoggerFactory>()
                .CreateLogger("Lisa");

            logger.LogError(context.Failure, "Auth0 remote failure during the authentication callback");

            context.Response.Redirect("/Home/Error");
            context.HandleResponse();
            return Task.CompletedTask;
        },
    };
});

// Keep the id_token/access_token in the auth cookie so /Home/Claims can show the
// raw authentication response. Auth0WebAppOptions does not surface SaveTokens,
// so it is set on the OpenIdConnectOptions the SDK registers underneath.
// Cost: the tokens ride in the cookie on every request. Worth it for a sample;
// for a real app, prefer a server-side ticket store.
builder.Services
    .AddOptions<OpenIdConnectOptions>(Auth0Constants.AuthenticationScheme)
    .Configure(options => options.SaveTokens = true);

builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
