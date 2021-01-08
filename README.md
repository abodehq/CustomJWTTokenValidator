# CustomJWTTokenValidator

to use the Token Custom validator in the startup

services.AddAuthentication(options =>
			{
				options.DefaultAuthenticateScheme = KeycloakAuthOptions.DefaultScheme;
				options.DefaultChallengeScheme = KeycloakAuthOptions.DefaultScheme;
			})
			// Call custom authentication extension method
			.AddKeycloakAuth(options =>
			{
			});
