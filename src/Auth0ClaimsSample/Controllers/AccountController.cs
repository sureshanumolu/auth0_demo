using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Auth0ClaimsSample.Controllers;

public sealed class AccountController : Controller
{
    [AllowAnonymous]
    public async Task Login(string returnUrl = "/")
    {
        // Per-request connection selection would go here instead of the
        // app-wide Auth0:Connection setting:
        //   .WithParameter("connection", connectionForThisRequest)
        var properties = new LoginAuthenticationPropertiesBuilder()
            .WithRedirectUri(returnUrl)
            .Build();

        await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, properties);
    }

    [Authorize]
    public async Task Logout()
    {
        var properties = new LogoutAuthenticationPropertiesBuilder()
            .WithRedirectUri("/")
            .Build();

        await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, properties);
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    [AllowAnonymous]
    public IActionResult AccessDenied() => View();
}
