namespace Auth0ClaimsSample.Claims;

/// <summary>Claim type names used on both sides of the LISA pipeline.</summary>
public static class LisaClaimTypes
{
    /// <summary>Non-namespaced claim, as passed through from an enterprise IdP.</summary>
    public const string Raw = "_lisa";

    /// <summary>Namespaced claim, as an Auth0 Action must emit it.</summary>
    public const string Namespaced = "https://watech.wa.gov/lisa";

    /// <summary>Every username found at any depth.</summary>
    public const string Username = "lisa_username";

    /// <summary>Every guid found at any depth.</summary>
    public const string Guid = "lisa_guid";

    /// <summary>Every role found at any depth.</summary>
    public const string Role = "lisa_role";

    /// <summary>"guid:username" - keeps the pairing that separate claims lose.</summary>
    public const string Entry = "lisa_entry";

    /// <summary>Prefix for full-path claims, e.g. "lisa:0.children[1].agency.code".</summary>
    public const string PathPrefix = "lisa:";
}
