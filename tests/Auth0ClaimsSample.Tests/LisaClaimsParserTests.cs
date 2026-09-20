using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using Auth0ClaimsSample.Claims;
using Xunit;

namespace Auth0ClaimsSample.Tests;

public class LisaClaimsParserTests
{
    private static LisaClaimsOptions Options() => new();

    // ---------------------------------------------------------- claim shapes

    [Fact]
    public void ParseValue_WholeArrayInOneClaim_ReturnsEveryEntry()
    {
        const string json = """
            [ { "guid": "DP6VP", "username": "luke.harris" },
              { "guid": "DL6TV", "username": "lukh461" } ]
            """;

        var entries = LisaClaimsParser.ParseValue(json, Options());

        Assert.Equal(2, entries.Count);
        Assert.Equal("luke.harris", entries[0].Username);
        Assert.Equal("DP6VP", entries[0].Guid);
        Assert.Equal("lukh461", entries[1].Username);
    }

    [Fact]
    public void Parse_OneClaimPerObject_ReturnsEveryEntry()
    {
        // This is what Microsoft.IdentityModel actually produces for a JWT array
        // of objects: the array is expanded into one claim per element.
        var claims = new[]
        {
            new Claim("_lisa", """{ "guid": "DP6VP", "username": "luke.harris" }""", "JSON"),
            new Claim("_lisa", """{ "guid": "DL6TV", "username": "lukh461" }""", "JSON"),
        };

        var entries = LisaClaimsParser.Parse(claims, Options());

        Assert.Equal(2, entries.Count);
        Assert.Equal(new[] { "luke.harris", "lukh461" }, entries.Select(e => e.Username));
    }

    [Fact]
    public void ParseValue_DictionaryKeyedByGuid_PromotesKeyToGuid()
    {
        const string json = """
            { "DP6VP": { "username": "luke.harris" },
              "DL6TV": { "username": "lukh461" } }
            """;

        var entries = LisaClaimsParser.ParseValue(json, Options());

        Assert.Equal(2, entries.Count);
        Assert.Equal("DP6VP", entries[0].Guid);
        Assert.Equal("luke.harris", entries[0].Username);
        Assert.Equal("DL6TV", entries[1].Guid);
        Assert.Equal("lukh461", entries[1].Username);
    }

    [Fact]
    public void ParseValue_ScalarDictionary_MapsKeyAndValue()
    {
        const string json = """{ "DP6VP": "luke.harris", "DL6TV": "lukh461" }""";

        var entries = LisaClaimsParser.ParseValue(json, Options());

        Assert.Equal(2, entries.Count);
        Assert.Equal("DP6VP", entries[0].Guid);
        Assert.Equal("luke.harris", entries[0].Username);
    }

    [Fact]
    public void ParseValue_DictionaryKeyIsUsername_PromotesKeyToUsername()
    {
        const string json = """{ "luke.harris": { "guid": "DP6VP" } }""";
        var options = Options();
        options.DictionaryKeyIs = LisaDictionaryKey.Username;

        var entries = LisaClaimsParser.ParseValue(json, options);

        var entry = Assert.Single(entries);
        Assert.Equal("luke.harris", entry.Username);
        Assert.Equal("DP6VP", entry.Guid);
    }

    [Fact]
    public void ParseValue_WrapperObject_UnwrapsToEntries()
    {
        const string json = """{ "entries": [ { "username": "luke.harris" } ] }""";

        var entries = LisaClaimsParser.ParseValue(json, Options());

        var entry = Assert.Single(entries);
        Assert.Equal("luke.harris", entry.Username);
    }

    [Fact]
    public void ParseValue_BareString_BecomesUsername()
    {
        var entries = LisaClaimsParser.ParseValue("luke.harris", Options());

        Assert.Equal("luke.harris", Assert.Single(entries).Username);
    }

    // --------------------------------------------------------------- nesting

    [Fact]
    public void ParseValue_NestedChildren_ParsesFullTree()
    {
        const string json = """
            [ { "guid": "A", "username": "top",
                "children": [
                  { "guid": "B", "username": "middle",
                    "children": [ { "guid": "C", "username": "leaf" } ] } ] } ]
            """;

        var entries = LisaClaimsParser.ParseValue(json, Options());

        var top = Assert.Single(entries);
        var middle = Assert.Single(top.Children);
        var leaf = Assert.Single(middle.Children);

        Assert.Equal("leaf", leaf.Username);
        Assert.Equal(new[] { "top", "middle", "leaf" }, top.SelfAndDescendants().Select(e => e.Username));
    }

    [Fact]
    public void ParseValue_NestedUnderAlternateKey_StillParses()
    {
        const string json = """
            [ { "username": "top", "accounts": [ { "username": "delegated" } ] } ]
            """;

        var entries = LisaClaimsParser.ParseValue(json, Options());

        Assert.Equal("delegated", Assert.Single(Assert.Single(entries).Children).Username);
    }

    [Fact]
    public void ParseValue_NestedDictionary_ParsesChildren()
    {
        const string json = """
            { "A": { "username": "top", "children": { "B": { "username": "leaf" } } } }
            """;

        var entries = LisaClaimsParser.ParseValue(json, Options());

        var top = Assert.Single(entries);
        var leaf = Assert.Single(top.Children);
        Assert.Equal("A", top.Guid);
        Assert.Equal("B", leaf.Guid);
        Assert.Equal("leaf", leaf.Username);
    }

    [Fact]
    public void ParseValue_BeyondMaxDepth_StopsRecursing()
    {
        const string json = """
            [ { "username": "a", "children": [ { "username": "b", "children": [ { "username": "c" } ] } ] } ]
            """;
        var options = Options();
        options.MaxDepth = 2;

        var entries = LisaClaimsParser.ParseValue(json, options);

        // Depth-limited: the deepest generation is dropped rather than throwing.
        Assert.True(entries.SelectMany(e => e.SelfAndDescendants()).Count() < 3);
    }

    // ----------------------------------------------------------- field shapes

    [Fact]
    public void ParseValue_RolesAsArrayOrScalar_BothBecomeLists()
    {
        var asArray = LisaClaimsParser.ParseValue("""[{ "username": "a", "roles": ["x", "y"] }]""", Options());
        var asScalar = LisaClaimsParser.ParseValue("""[{ "username": "b", "role": "x" }]""", Options());

        Assert.Equal(new[] { "x", "y" }, Assert.Single(asArray).Roles);
        Assert.Equal(new[] { "x" }, Assert.Single(asScalar).Roles);
    }

    [Fact]
    public void ParseValue_Agency_ParsesNestedObjectAndExtras()
    {
        const string json = """
            [{ "username": "a", "agency": { "code": "WATECH", "name": "WA Tech", "region": "west" } }]
            """;

        var entry = Assert.Single(LisaClaimsParser.ParseValue(json, Options()));

        Assert.NotNull(entry.Agency);
        Assert.Equal("WATECH", entry.Agency!.Code);
        Assert.Equal("WA Tech", entry.Agency.Name);
        Assert.Equal("west", entry.Agency.Extra["region"].GetString());
    }

    [Fact]
    public void ParseValue_UnknownProperties_SurviveDocumentDisposal()
    {
        const string json = """[{ "username": "a", "status": "active", "level": 3 }]""";

        var entry = Assert.Single(LisaClaimsParser.ParseValue(json, Options()));

        // JsonElement.Clone() in the parser is what makes these readable after
        // the JsonDocument was disposed.
        Assert.Equal("active", entry.Extra["status"].GetString());
        Assert.Equal(3, entry.Extra["level"].GetInt32());
    }

    [Fact]
    public void ParseValue_NumericAndBooleanFields_Stringify()
    {
        const string json = """[{ "username": 12345, "roles": [true, 7] }]""";

        var entry = Assert.Single(LisaClaimsParser.ParseValue(json, Options()));

        Assert.Equal("12345", entry.Username);
        Assert.Equal(new[] { "true", "7" }, entry.Roles);
    }

    // ------------------------------------------------------------ resilience

    [Fact]
    public void ParseValue_Malformed_ReturnsEmptyByDefault()
    {
        Assert.Empty(LisaClaimsParser.ParseValue("""[{ "username": """, Options()));
    }

    [Fact]
    public void ParseValue_Malformed_ThrowsWhenConfigured()
    {
        var options = Options();
        options.ThrowOnMalformed = true;

        Assert.ThrowsAny<JsonException>(() => LisaClaimsParser.ParseValue("""[{ "username": """, options));
    }

    [Fact]
    public void ParseValue_EmptyOrWhitespace_ReturnsEmpty()
    {
        Assert.Empty(LisaClaimsParser.ParseValue(null, Options()));
        Assert.Empty(LisaClaimsParser.ParseValue("   ", Options()));
    }

    // -------------------------------------------------------------- flatten

    [Fact]
    public void Flatten_EmitsValueClaimsForEveryDepth()
    {
        const string json = """
            [{ "guid": "A", "username": "top", "roles": ["r1"],
               "children": [{ "guid": "B", "username": "leaf", "roles": ["r2"] }] }]
            """;
        var options = Options();

        var claims = LisaClaimsParser.Flatten(LisaClaimsParser.ParseValue(json, options), options);

        var usernames = claims.Where(c => c.Type == LisaClaimTypes.Username).Select(c => c.Value);
        var roles = claims.Where(c => c.Type == LisaClaimTypes.Role).Select(c => c.Value);

        Assert.Equal(new[] { "top", "leaf" }, usernames);
        Assert.Equal(new[] { "r1", "r2" }, roles);
    }

    [Fact]
    public void Flatten_PairClaim_KeepsGuidUsernamePairing()
    {
        const string json = """[{ "guid": "A", "username": "top" }, { "guid": "B", "username": "leaf" }]""";
        var options = Options();

        var claims = LisaClaimsParser.Flatten(LisaClaimsParser.ParseValue(json, options), options);

        var pairs = claims.Where(c => c.Type == LisaClaimTypes.Entry).Select(c => c.Value);
        Assert.Equal(new[] { "A:top", "B:leaf" }, pairs);
    }

    [Fact]
    public void Flatten_PathClaims_UseIndexedPaths()
    {
        const string json = """
            [{ "username": "top", "agency": { "code": "WATECH" },
               "children": [{ "username": "leaf" }] }]
            """;
        var options = Options();
        options.EmitPathClaims = true;

        var claims = LisaClaimsParser.Flatten(LisaClaimsParser.ParseValue(json, options), options);
        var types = claims.Select(c => c.Type).ToList();

        Assert.Contains("lisa:0.username", types);
        Assert.Contains("lisa:0.agency.code", types);
        Assert.Contains("lisa:0.children[0].username", types);
    }

    [Fact]
    public void Flatten_Deduplicates()
    {
        const string json = """[{ "username": "same" }, { "username": "same" }]""";
        var options = Options();

        var claims = LisaClaimsParser.Flatten(LisaClaimsParser.ParseValue(json, options), options);

        Assert.Single(claims, c => c.Type == LisaClaimTypes.Username);
    }

    [Fact]
    public void Flatten_ValueClaimsDisabled_EmitsNone()
    {
        var options = Options();
        options.EmitValueClaims = false;
        options.EmitPairClaims = false;

        var claims = LisaClaimsParser.Flatten(
            LisaClaimsParser.ParseValue("""[{ "username": "a" }]""", options),
            options);

        Assert.Empty(claims);
    }

    // -------------------------------------------------------------- enricher

    [Fact]
    public void Enrich_AddsFlattenedClaimsToIdentity()
    {
        var identity = new ClaimsIdentity("test");
        identity.AddClaim(new Claim("_lisa", """[{ "guid": "A", "username": "luke.harris" }]"""));
        var options = Options();

        var added = LisaClaimsEnricher.Enrich(identity, options);

        Assert.True(added > 0);
        var principal = new ClaimsPrincipal(identity);
        Assert.True(principal.HasLisaUsername("LUKE.HARRIS"));
        Assert.Contains("A", principal.LisaGuids());
        // Raw claim is kept so on-demand re-parsing still works.
        Assert.NotNull(identity.FindFirst("_lisa"));
    }

    [Fact]
    public void Enrich_RemoveRawClaim_DropsTheRawClaim()
    {
        var identity = new ClaimsIdentity("test");
        identity.AddClaim(new Claim("_lisa", """[{ "username": "luke.harris" }]"""));
        var options = Options();
        options.RemoveRawClaim = true;

        LisaClaimsEnricher.Enrich(identity, options);

        Assert.Null(identity.FindFirst("_lisa"));
        Assert.NotNull(identity.FindFirst(LisaClaimTypes.Username));
    }

    [Fact]
    public void Enrich_NamespacedClaim_IsFoundToo()
    {
        var identity = new ClaimsIdentity("test");
        identity.AddClaim(new Claim(LisaClaimTypes.Namespaced, """[{ "username": "luke.harris" }]"""));

        LisaClaimsEnricher.Enrich(identity, Options());

        Assert.Equal("luke.harris", identity.FindFirst(LisaClaimTypes.Username)?.Value);
    }

    [Fact]
    public void Enrich_NoLisaClaim_IsANoOp()
    {
        var identity = new ClaimsIdentity("test");
        identity.AddClaim(new Claim("sub", "auth0|123"));

        Assert.Equal(0, LisaClaimsEnricher.Enrich(identity, Options()));
    }

    // --------------------------------------------------------------- profile

    [Fact]
    public void GetLisaProfile_ExposesFlattenedHelpers()
    {
        var identity = new ClaimsIdentity("test");
        identity.AddClaim(new Claim("_lisa", """
            { "A": { "username": "top", "roles": ["r1"],
                     "children": { "B": { "username": "leaf", "roles": ["r2"] } } } }
            """));

        var profile = new ClaimsPrincipal(identity).GetLisaProfile(Options());

        Assert.Single(profile.Entries);
        Assert.Equal(2, profile.All.Count());
        Assert.Equal(new[] { "top", "leaf" }, profile.Usernames);
        Assert.Equal(new[] { "r1", "r2" }, profile.Roles);
        Assert.Equal("leaf", profile.FindByGuid("B")?.Username);
        Assert.Equal("A", profile.FindByUsername("TOP")?.Guid);
    }

    // ------------------------------------------------- duplicate claim names

    [Fact]
    public void CollectRawClaims_SamePayloadUnderBothNames_IsNotCountedTwice()
    {
        // What the deployed Action actually produces: the identical dictionary
        // set as both the namespaced and the legacy claim.
        const string payload = """
            { "DP6VP4K2QY": { "username": "luke.harris", "roles": ["lisa_admin"],
                "children": { "DQ2XX8T7RR": { "username": "luke.harris.svc", "role": "lisa_service" } } } }
            """;

        var identity = new ClaimsIdentity("test");
        identity.AddClaim(new Claim(LisaClaimTypes.Namespaced, payload));
        identity.AddClaim(new Claim(LisaClaimTypes.Raw, payload));

        var raw = LisaClaimsParser.CollectRawClaims(identity, Options()).ToList();
        var entries = LisaClaimsParser.Parse(raw, Options());

        Assert.Single(raw);
        Assert.Single(entries);
        Assert.Equal("luke.harris", entries[0].Username);
        Assert.Single(entries[0].Children);
        Assert.Equal("luke.harris.svc", entries[0].Children[0].Username);
    }

    [Fact]
    public void CollectRawClaims_BothPresent_UsesConfiguredPrecedenceOrder()
    {
        var identity = new ClaimsIdentity("test");
        identity.AddClaim(new Claim(LisaClaimTypes.Raw, """{ "A": { "username": "bare" } }"""));
        identity.AddClaim(new Claim(LisaClaimTypes.Namespaced, """{ "A": { "username": "namespaced" } }"""));

        // Default order is { Raw, Namespaced } - the bare name the Action emits.
        var byDefault = LisaClaimsParser.Parse(
            LisaClaimsParser.CollectRawClaims(identity, Options()), Options());

        Assert.Equal("bare", Assert.Single(byDefault).Username);

        // Flipping ClaimTypes flips which claim wins - nothing else changes.
        var flipped = new LisaClaimsOptions
        {
            ClaimTypes = { LisaClaimTypes.Namespaced, LisaClaimTypes.Raw },
        };

        var reordered = LisaClaimsParser.Parse(
            LisaClaimsParser.CollectRawClaims(identity, flipped), flipped);

        Assert.Equal("namespaced", Assert.Single(reordered).Username);
    }

    [Fact]
    public void CollectRawClaims_FallsBackToRawWhenNamespacedAbsent()
    {
        var identity = new ClaimsIdentity("test");
        identity.AddClaim(new Claim(LisaClaimTypes.Raw, """{ "A": { "username": "passthrough" } }"""));

        var entries = LisaClaimsParser.Parse(
            LisaClaimsParser.CollectRawClaims(identity, Options()), Options());

        Assert.Equal("passthrough", Assert.Single(entries).Username);
    }

    [Fact]
    public void CollectRawClaims_MultipleClaimsOfWinningType_AreAllKept()
    {
        // Shape 2: Microsoft.IdentityModel expands an array of objects into one
        // claim per element, all sharing a type. First-match-wins must not
        // truncate that to a single claim.
        var identity = new ClaimsIdentity("test");
        identity.AddClaim(new Claim(LisaClaimTypes.Namespaced, """{ "guid": "A", "username": "one" }"""));
        identity.AddClaim(new Claim(LisaClaimTypes.Namespaced, """{ "guid": "B", "username": "two" }"""));

        var raw = LisaClaimsParser.CollectRawClaims(identity, Options()).ToList();
        var entries = LisaClaimsParser.Parse(raw, Options());

        Assert.Equal(2, raw.Count);
        Assert.Equal(new[] { "one", "two" }, entries.Select(e => e.Username));
    }

    // ------------------------------------------------------- profile wrapper

    /// <summary>
    /// The IdP sends the records inside a profile envelope. Listing "_lisa" in
    /// NestedPropertyNames is what makes the parser descend into the list
    /// instead of reading _email/_first_name/... as records.
    /// </summary>
    private const string Wrapper = """
        {
          "_auth0_guid": "auth0|6a5e87edd6878c570943cf15",
          "_email": "lukh461@okta.com",
          "_first_name": "Luke",
          "_last_name": "Harris",
          "_lisa": [
            { "guid": "TEST-1PM2QP7FL4-D1LW4VZ0FD-OKTA", "username": "luke.harris" },
            { "guid": "TEST-5DL7WL1DQ-DD7WV4ZZ8D-OKTA", "username": "lukh461" },
            { "guid": "TEST-1QM6LW0LT-DD7WV4ZZ8D-OKTA", "username": "lharris" }
          ]
        }
        """;

    [Fact]
    public void Wrapper_WithLisaListed_ReadsOnlyTheRecords()
    {
        var options = new LisaClaimsOptions { NestedPropertyNames = { "_lisa" } };

        var entries = LisaClaimsParser.ParseValue(Wrapper, options);

        Assert.Equal(3, entries.Count);
        Assert.Equal(
            new[] { "luke.harris", "lukh461", "lharris" },
            entries.Select(e => e.Username));
        Assert.Equal("TEST-1PM2QP7FL4-D1LW4VZ0FD-OKTA", entries[0].Guid);

        // The envelope's own fields must not become records.
        Assert.DoesNotContain(entries, e => e.Username == "lukh461@okta.com");
        Assert.DoesNotContain(entries, e => e.Username == "Luke");
    }

    [Fact]
    public void Wrapper_WithoutLisaListed_AlsoYieldsTheEnvelopeFieldsAsRecords()
    {
        // Pins the failure mode. Without "_lisa" the object is read as a
        // dictionary: every sibling becomes a record keyed by its property name.
        // The real records survive - ReadKeyedEntries still recurses into the
        // array - so the damage is contamination, not loss. That is a softer
        // failure than the Action's, where the array was dropped outright.
        var options = new LisaClaimsOptions();
        Assert.DoesNotContain("_lisa", options.NestedPropertyNames);

        var entries = LisaClaimsParser.ParseValue(Wrapper, options);

        Assert.Contains(entries, e => e.Username == "luke.harris");
        Assert.Contains(entries, e => e.Username == "lukh461@okta.com");
        Assert.Contains(entries, e => e.Username == "Luke");
        Assert.True(entries.Count > 3, $"expected contamination, got {entries.Count}");
    }
}
