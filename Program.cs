using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AspAuthorsApp
{
    class User
    {
        public string Login { set; get; }
        public string Password { set; get; }
    };
    
    
    public class AuthOptions
    {
        public const string ISSUER = "AuthServer";
        public const string AUDIENCE = "AuthClient";
        const string KEY = "abcdefghij123456";
        public static SymmetricSecurityKey GetSymmetricSecurityKey()
            => new SymmetricSecurityKey(Encoding.UTF8.GetBytes(KEY));
    }
    public class Program
    {
        public static void Main(string[] args)
        {
            var users = new List<User>
            {
                new(){ Login = "bob", Password = "12345"},
                new(){ Login = "joe", Password = "54321"},
            };

            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                            .AddJwtBearer(options =>
                            {
                                options.TokenValidationParameters = new TokenValidationParameters
                                {
                                    ValidateIssuer = true,
                                    ValidIssuer = AuthOptions.ISSUER,
                                    ValidateAudience = true,
                                    ValidAudience = AuthOptions.AUDIENCE,
                                    ValidateLifetime = true,
                                    IssuerSigningKey = AuthOptions.GetSymmetricSecurityKey(),
                                    ValidateIssuerSigningKey = true,
                                };
                            });


            builder.Services.AddAuthorization();
            

            var app = builder.Build();

            app.UseDefaultFiles();
            app.UseStaticFiles();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapPost("/auth", (User userData) =>
            {
                User? user = users
                            .FirstOrDefault(u
                                => u.Login == userData.Login && u.Password == userData.Password);
                if (user is null)
                    return Results.Unauthorized();

                var claims = new List<Claim> { new Claim(ClaimTypes.Name, user.Login) };
                var token = new JwtSecurityToken(
                    issuer: AuthOptions.ISSUER,
                    audience: AuthOptions.AUDIENCE,
                    claims: claims,
                    expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)),
                    signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), 
                                                               SecurityAlgorithms.HmacSha256)
                    );
                var response = new
                {
                    access_token = new JwtSecurityTokenHandler().WriteToken(token),
                    username = user.Login
                };
                return Results.Json(response);
            });

            app.Map("/hello", [Authorize] (HttpContext context) => new { message = "Hello world" });
           

            app.Run();
        }
    }
}