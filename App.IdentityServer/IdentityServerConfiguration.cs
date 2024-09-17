using IdentityServer4.Models;

namespace App.IdentityServer;

public static class IdentityServerConfiguration
{
    public static IEnumerable<ApiScope> GetApiScopes()
    {
        return new List<ApiScope>
            {
                new ApiScope("my-api", "Access to My API") // Đăng ký scope "my-api"
            };
    }
    public static IEnumerable<ApiResource> GetAllApiResources()
    {
        return new List<ApiResource>
            {
                new ApiResource("my-api", "My API")
                {
                    Scopes = { "my-api" }
                }
            };
    }

    public static IEnumerable<Client> GetClients()
    {
        return new List<Client>
            {
                new Client
                {
                    ClientId = "my-client",
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    ClientSecrets = { new Secret("my-api-secret".Sha256()) },
                    AllowedScopes = { "my-api" }
                }
            };
    }
}
