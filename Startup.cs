using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Quickstart.UI;
using IdentityServer4.Saml;
using IdentityServer4.Saml.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace SAML2IdentityServer4ZendDesk
{
    public class Startup
    {
        public IHostingEnvironment Environment { get; }

        public Startup(IHostingEnvironment environment)
        {
            Environment = environment;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            ///IdentityServer 4 as a SAML Identity Provider
            services
                .AddMvc()
                .Services
                .AddMemoryCache()
                .AddIdentityServer()
                .AddSigningCredential(
                    new X509Certificate2(
                        Path.Combine(Environment.ContentRootPath, "zenddesk.pfx"), "mypassword"))
                .AddSamlPlugin(options =>
                {
                    options.Licensee = "";
                    options.LicenseKey = "";
                    options.WantAuthenticationRequestsSigned = false;
                })
                .AddInMemoryIdentityResources(new List<IdentityResource>
                {
                    new IdentityResources.OpenId(),
                    new IdentityResources.Profile(),
                    new IdentityResources.Email(),
                    new IdentityResource
                    {
                        Name = "zendesk",
                        UserClaims = { JwtClaimTypes.Name, JwtClaimTypes.Email, JwtClaimTypes.Role }
                    }
                })
                .AddInMemoryApiResources(new List<ApiResource>())
                .AddInMemoryClients(new List<Client>()
                {
                    new Client {
                          ClientId = "https://<yoursubdomain>.zendesk.com",
                          ClientName = "RSK SAML2P Test Client",
                          ProtocolType = IdentityServerConstants.ProtocolTypes.Saml2p,
                          AllowedScopes = { "openid", "profile", "email", "zendesk" },
                          RedirectUris = { "https://<yoursubdomain>.zendesk.com/access/saml" }
                    }
                })
                .AddInMemoryServiceProviders(new List<IdentityServer4.Saml.Models.ServiceProvider>()
                {
                    new IdentityServer4.Saml.Models.ServiceProvider
                    {
                        EntityId = "https://<yoursubdomain>.zendesk.com",
                        SigningCertificates = {new X509Certificate2(Path.Combine(Environment.ContentRootPath, "zenddesk.cer"))},
                        AssertionConsumerServices = { new Service(SamlConstants.BindingTypes.HttpPost, "https://<yoursubdomain>.zendesk.com/access/saml") },
                        RequireSamlRequestDestination = false,
                        ClaimsMapping = new Dictionary<string,string>
                        {
                            { JwtClaimTypes.Role, JwtClaimTypes.Role },
                            { JwtClaimTypes.Email, JwtClaimTypes.Email },
                            { JwtClaimTypes.Name, JwtClaimTypes.Name }
                        }
                    }
                })
                .AddTestUsers(TestUsers.Users);
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app
                .UseIdentityServer()
                .UseIdentityServerSamlPlugin()
                .UseStaticFiles()
                .UseMvcWithDefaultRoute();
        }
    }
}
