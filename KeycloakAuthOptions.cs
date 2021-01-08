using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;

namespace Lc.Gateway.Authentication
{
    public class KeycloakAuthOptions : AuthenticationSchemeOptions
    {
        public const string DefaultScheme = "KeycloakAuth";
        public string Scheme => DefaultScheme;
        //public StringValues AuthKey { get; set; }
    }
}