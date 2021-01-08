using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Lc.Gateway.Authentication
{
	public class KeycloakAuthHandler : AuthenticationHandler<KeycloakAuthOptions>
	{
		public KeycloakAuthHandler(IOptionsMonitor<KeycloakAuthOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
			: base(options, logger, encoder, clock)
		{
		}
		protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
		{
			var authorization = Request.Headers[HeaderNames.Authorization];
			if (!AuthenticationHeaderValue.TryParse(authorization, out var headerValue))//Read Auth From Header
				return AuthenticateResult.Fail("Cannot read authorization header.");
			var scheme = headerValue.Scheme;
			if (scheme!= JwtBearerDefaults.AuthenticationScheme) //Check if the Auth is Bearer
				return AuthenticateResult.Fail("Invalid Authentication Scheme.");
			var jwtToken = headerValue.Parameter;//get the token from the Header.
			var handler = new JwtSecurityTokenHandler();//Inital JWT Security Handler
			if (handler.CanReadToken(jwtToken))//check if we can read the Token
			{
				try
				{
					string issuer = "http://localhost:8080/auth/realms/master";
					//Get Openid configuration using Discovery Metadata Url 
					var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
					 issuer + "/.well-known/openid-configuration",
					new OpenIdConnectConfigurationRetriever(),
					new HttpDocumentRetriever() { RequireHttps = false });//just for development
					//Our Custom JWT Validator
					var JwtSecurityToken = await TokenValidator.ValidateToken(jwtToken, issuer,configurationManager);
					if (JwtSecurityToken == null)
						return AuthenticateResult.Fail("Failed to validate the token.");
					//Validation Success 
					SecurityToken validatedToken;
					ClaimsPrincipal principal;
				}
				catch (Exception e)
				{
					return AuthenticateResult.Fail("Failed to validate the token.");
				}
			}else
				return AuthenticateResult.Fail("Invalid token.");
			// Create authenticated user
			var identities = new List<ClaimsIdentity> { new ClaimsIdentity("KeycloakAuth") };
			var ticket = new AuthenticationTicket(new ClaimsPrincipal(identities), Options.Scheme);
			return AuthenticateResult.Success(ticket);
		}
	}

}