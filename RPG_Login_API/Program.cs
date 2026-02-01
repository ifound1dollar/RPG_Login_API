
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using RPG_Login_API.Configuration;
using RPG_Login_API.Services;
using RPG_Login_API.Utility;
using System.Security.Claims;
using System.Text;

namespace RPG_Login_API
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);



            // Database settings. These are stored in secrets.json, accessible by [right click project] -> Manage User Secrets.
            builder.Services.Configure<DatabaseSettings>(builder.Configuration.GetSection("DatabaseSettings"));

            // Security token (JWT) settings, also stored in secrets.json.
            var tokenSettings = builder.Configuration.GetSection("TokenSettings");
            builder.Services.Configure<TokenSettings>(tokenSettings);

            // Configure and add JWT token authentication, passing token settings from config section above.
            ConfigureJwtValidation(builder, tokenSettings);

            // Configure our logger. Currently only uses the console, but can be easily extended.
            builder.Logging.ClearProviders().AddConsole();

            // Add our desired services. Registers them to enable constructor injection.
            builder.Services.AddSingleton<DatabaseService>();
            builder.Services.AddSingleton<TokenService>();
            builder.Services.AddSingleton<LoginApiService>();   // Token and Database services must be registered before this.

            // Add our controller(s). Adds an additional JSON option to remove the special naming policy from serialization
            //  behavior, which will retain PascalCase (as used by C#) rather than re-formatting to camelCase (the default).
            builder.Services.AddControllers().AddJsonOptions(
                options => options.JsonSerializerOptions.PropertyNamingPolicy = null);



            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();



            // After build but before run, test the database connection.
            using (var scope = app.Services.CreateScope())
            {
                var databaseService = scope.ServiceProvider.GetRequiredService<DatabaseService>();
                if (!databaseService.CheckConnectionStatus()) return;   // Exit application if not connected.
            }



            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }

        private static void ConfigureJwtValidation(WebApplicationBuilder builder, IConfigurationSection section)
        {
            // Bind configuration section to new TokenSettings object (normally auto-handled with Services.Configure<>()).
            var tokenSettings = new TokenSettings();
            section.Bind(tokenSettings);

            // Read JWT key from TokenSettings and ensure validity.
            var jwtKey = tokenSettings.JwtKey;
            if (jwtKey == null)
            {
                Console.WriteLine("[ERROR] Startup: Failed to retrieve authentication JWT token key. Exiting.");
                Environment.Exit(1);
            }

            // Use JWT key to create token validation parameters.
            byte[] jwtKeyBytes = Encoding.UTF8.GetBytes(jwtKey);
            TokenValidationParameters parameters = new()
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(jwtKeyBytes),
                RoleClaimType = ClaimTypes.Role     // Configure the [Authorize] behavior in Controllers to use Roles.
            };


            // Add authentication configuration to builder's services, which will handle automatic bearer token validation.
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false;
                options.SaveToken = true;
                options.TokenValidationParameters = parameters;
            });
        }
    }
}
