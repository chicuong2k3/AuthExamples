using App.IdentityServer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddIdentityServer()
    .AddDeveloperSigningCredential()
    .AddInMemoryApiScopes(IdentityServerConfiguration.GetApiScopes())
    .AddInMemoryApiResources(IdentityServerConfiguration.GetAllApiResources())
    .AddInMemoryClients(IdentityServerConfiguration.GetClients());



var app = builder.Build();

app.UseIdentityServer();

app.Run();
