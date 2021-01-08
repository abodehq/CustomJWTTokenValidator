using System;
using Microsoft.AspNetCore.Authentication;

namespace Lc.Gateway.Authentication
{
    public static class AuthenticationBuilderExtensions
    {
        // Custom authentication extension method
        public static AuthenticationBuilder AddKeycloakAuth(this AuthenticationBuilder builder, Action<KeycloakAuthOptions> configureOptions)
        {
            // Add custom authentication scheme with custom options and custom handler
            return builder.AddScheme<KeycloakAuthOptions, KeycloakAuthHandler>(KeycloakAuthOptions.DefaultScheme, configureOptions);
        }
    }
}
