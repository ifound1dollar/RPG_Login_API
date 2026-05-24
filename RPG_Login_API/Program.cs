
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using RPG_Login_API.Configuration;
using RPG_Login_API.Services;
using RPG_Login_API.Services.Interfaces;
using RPG_Login_API.Utility;
using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;

namespace RPG_Login_API
{
    public class Program
    {
        public static bool IsDevelopment { get; } = true;

        public static void Main(string[] args)
        {
            if (IsDevelopment)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine(" <----- API RUNNING IN DEVELOPMENT MODE ----->");
                Console.WriteLine();
                Console.ResetColor();
            }



            var builder = WebApplication.CreateBuilder(args);



            // Database settings. These are stored in secrets.json, accessible by [right click project] -> Manage User Secrets.
            builder.Services.Configure<DatabaseSettings>(builder.Configuration.GetSection("DatabaseSettings"));

            // Security token (JWT) settings, also stored in secrets.json.
            var tokenSettings = builder.Configuration.GetSection("TokenSettings");
            builder.Services.Configure<TokenSettings>(tokenSettings);

            // Email SMTP service settings (in secrets.json).
            builder.Services.Configure<EmailServiceSettings>(builder.Configuration.GetSection("EmailServiceSettings"));

            // Configure and add JWT token authentication, passing token settings from config section above.
            ConfigureJwtValidation(builder, tokenSettings);

            // Configure our logger. Currently only uses the console, but can be easily extended.
            builder.Logging.ClearProviders().AddConsole();

            // Add our desired services. Registers them to enable constructor injection.
            builder.Services.AddSingleton<IDatabaseService, DatabaseService>();
            builder.Services.AddSingleton<ITokenService, TokenService>();
            builder.Services.AddSingleton<IEmailCodeService, EmailCodeService>();
            builder.Services.AddSingleton<ILoginApiService, LoginApiService>(); // Token and Database services must be registered before this.

            // Add our controller(s). Adds an additional JSON option to remove the special naming policy from serialization
            //  behavior, which will retain PascalCase (as used by C#) rather than re-formatting to camelCase (the default).
            builder.Services.AddControllers().AddJsonOptions(
                options => options.JsonSerializerOptions.PropertyNamingPolicy = null);

            // Add our custom UniversalExceptionHandler.
            builder.Services.AddExceptionHandler<UniversalExceptionHandler>();
            builder.Services.AddProblemDetails();

            // Add per-IP rate limiter. https://learn.microsoft.com/en-us/aspnet/core/performance/rate-limit?view=aspnetcore-7.0#sliding-window-limiter
            builder.Services.AddRateLimiter(options =>
            {
                options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
                options.AddPolicy("IpLimitPolicy", context =>
                    RateLimitPartition.GetSlidingWindowLimiter(
                        partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                        factory: _ => new SlidingWindowRateLimiterOptions
                        {
                            PermitLimit = 10,                   // Request limit
                            Window = TimeSpan.FromMinutes(1),   // Time window
                            SegmentsPerWindow = 3,              // Number of segments within one window
                            QueueLimit = 0                      // Disallow queue to block immediately on rate limit exceeded
                        }));
            });



            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();



            // After build but before run, test the database connection.
            using (var scope = app.Services.CreateScope())
            {
                var databaseService = scope.ServiceProvider.GetRequiredService<IDatabaseService>();
                if (!databaseService.CheckConnectionStatus()) return;   // Exit application if not connected.
            }



            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseRateLimiter();           // Use our defined rate limiter above.
            app.UseExceptionHandler();      // Use our custom exception handler added above.

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
