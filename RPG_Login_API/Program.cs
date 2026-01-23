
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using RPG_Login_API.Database;
using RPG_Login_API.Services;
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

            // Add our desired service(s). Registers them to enable constructor injection (ctor receives DatabaseSettings).
            builder.Services.AddSingleton<LoginApiService>();

            // Add our controller(s). Adds an additional JSON option to remove the special naming policy from serialization
            //  behavior, which will retain PascalCase (as used by C#) rather than re-formatting to camelCase (the default).
            builder.Services.AddControllers().AddJsonOptions(
                options => options.JsonSerializerOptions.PropertyNamingPolicy = null);

            // Add JWT token authentication configuration, retrieving the token key from secrets.json.
            var jwtKey = builder.Configuration.GetSection("JwtKey").ToString();
            if (jwtKey == null)
            {
                // TODO: USE CUSTOM LOGGER UTILITY INSTEAD OF RAW CONSOLE.WRITELINE()
                Console.WriteLine("Failed to retrieve authentication JWT token key. Exiting.");
                return;
            }
            byte[] jwtKeyBytes = Encoding.UTF8.GetBytes(jwtKey);
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false;
                options.SaveToken = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(jwtKeyBytes),
                    RoleClaimType = ClaimTypes.Role     // Configure the [Authorize] behavior in Controllers to use Roles.
                };
            });
            LoginApiService.SetJwtKey(jwtKeyBytes);     // Also set in-memory JWT key in Service (required for token generation).





            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();



            // After build but before run, test the database connection.
            using (var scope = app.Services.CreateScope())
            {
                var loginApiService = scope.ServiceProvider.GetRequiredService<LoginApiService>();
                if (!loginApiService.CheckConnectionStatus()) return;   // Exit application if not connected.
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
    }
}
