using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AzureADIDTokenValidationLab
{
    class Program
    {
        static void Main(string[] args)
        {
            var idToken = "#AAD ID Token#";
            var accessToken = "#AAD Access Token#";
            try
            {
                var d = Validate(idToken).Result;
                var vT = d.ValidTo;
                var vF = d.ValidFrom;
                var name = d.Payload["name"];
                var preferred_username = d.Payload["preferred_username"];
                Console.WriteLine($"name: {name}, preferred_username: {preferred_username}");
            }
            catch (AggregateException ex1)
            {
                Console.WriteLine(ex1.InnerException.Message);
            }
            catch (SecurityTokenInvalidSignatureException ex2)
            {
                Console.WriteLine(ex2.InnerException.Message);
            }
            Console.ReadKey();
        }

        private static bool CustomLifetimeValidator(DateTime? notBefore, DateTime? expires, SecurityToken tokenToValidate, TokenValidationParameters @param)
        {
            if (expires != null)
            {
                return expires > DateTime.UtcNow;
            }
            return false;
        }

        async static Task<JwtSecurityToken> Validate(string token)
        {
            string stsDiscoveryEndpoint = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration";

            ConfigurationManager<OpenIdConnectConfiguration> configManager = new ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint, new OpenIdConnectConfigurationRetriever());
            OpenIdConnectConfiguration config = configManager.GetConfigurationAsync().Result;
            var openidConfiguration = await OpenIdConnectConfigurationRetriever.GetAsync(stsDiscoveryEndpoint, CancellationToken.None);

            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                IssuerSigningKeys = openidConfiguration.SigningKeys,
                ValidateLifetime = true,
                LifetimeValidator = CustomLifetimeValidator,
            };

            JwtSecurityTokenHandler tokendHandler = new JwtSecurityTokenHandler();

            SecurityToken jwt;

            var result = tokendHandler.ValidateToken(token, validationParameters, out jwt);

            return jwt as JwtSecurityToken;
        }
    }
}
