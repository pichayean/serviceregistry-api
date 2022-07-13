using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using service_register;
using static System.Net.Mime.MediaTypeNames;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddScoped<IServiceRegisterService, ServiceRegisterService>();

builder.Services.AddControllers()
    .AddJsonOptions(o => o.JsonSerializerOptions
        .ReferenceHandler = ReferenceHandler.Preserve);
var securityScheme = new OpenApiSecurityScheme()
{
    Name = "Authorization",
    Type = SecuritySchemeType.ApiKey,
    Scheme = "Bearer",
    BearerFormat = "JWT",
    In = ParameterLocation.Header,
    Description = "JSON Web Token based security",
};

var securityReq = new OpenApiSecurityRequirement()
{
    {
        new OpenApiSecurityScheme
        {
            Reference = new OpenApiReference
            {
                Type = ReferenceType.SecurityScheme,
                Id = "Bearer"
            }
        },
        new string[] {}
    }
};

var info = new OpenApiInfo()
{
    Version = "V1",
    Title = "Service Registries Api with JWT Authentication",
    Description = "Service Registries Api with JWT Authentication",
    Contact = new OpenApiContact()
    {
        Name = "trustmacus",
        Email = "trustmacus@trustmacus.com",
        Url = new Uri("https://trustmacus.com")
    },
    License = new OpenApiLicense()
    {
        Name = "Free License",
    }
};
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", info);
    options.AddSecurityDefinition("Bearer", securityScheme);
    options.AddSecurityRequirement(securityReq);
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        ValidateAudience = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
        ValidateLifetime = false, // In any other application other then demo this needs to be true,
        ValidateIssuerSigningKey = true
    };
});

builder.Services.AddAuthentication();
builder.Services.AddAuthorization();


var app = builder.Build();
 app.UseCors(builder => builder
 .AllowAnyOrigin()
 .AllowAnyMethod()
 .AllowAnyHeader());
 
app.UseExceptionHandler(exceptionHandlerApp =>
{
    exceptionHandlerApp.Run(async context =>
    {
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;

        // using static System.Net.Mime.MediaTypeNames;
        context.Response.ContentType = Application.Json;

        var exceptionHandlerPathFeature =
            context.Features.Get<IExceptionHandlerPathFeature>();

        var json = JsonSerializer.Serialize(new ErrorResponse(exceptionHandlerPathFeature?.Error?.Message));
        await context.Response.WriteAsync(json);

        if (exceptionHandlerPathFeature?.Error is FileNotFoundException)
        {
            await context.Response.WriteAsync(" The file was not found.");
        }

        if (exceptionHandlerPathFeature?.Path == "/")
        {
            await context.Response.WriteAsync(" Page: Home.");
        }
    });
});

app.MapGet("ServiceRegistrations", [Authorize] (IServiceRegisterService service) =>
{
    return Results.Ok(service.Get());
});

app.MapGet("ServiceRegistrations/{id}", [Authorize] (int id, IServiceRegisterService service) =>
{
    return Results.Ok(service.Get(id));
});

app.MapPut("ServiceRegistration", [Authorize] async (ServiceRegistration model, IServiceRegisterService service) =>
{
    var response = await service.UpdateAsync(model);
    return Results.Ok(new
    {
        result = response
    });
});

app.MapPost("ServiceRegistration", [Authorize] async (ServiceRegistration model, IServiceRegisterService service) =>
{
    var response = await service.CreateAsync(model);
    return Results.Ok(new
    {
        result = response
    });
});

app.MapDelete("ServiceRegistration/{id}", [Authorize] async (int id, IServiceRegisterService service) =>
{
    var response = await service.DeleteAsync(id);
    return Results.Ok(new
    {
        result = response
    });
});

app.MapPost("/accounts/login", [AllowAnonymous] (UserDto user) =>
{
    if (user.username == "admin" && user.password == "Password123")
    {
        var secureKey = Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]);

        var issuer = builder.Configuration["Jwt:Issuer"];
        var audience = builder.Configuration["Jwt:Audience"];
        var securityKey = new SymmetricSecurityKey(secureKey);
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512);

        var jwtTokenHandler = new JwtSecurityTokenHandler();

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] {
                new Claim("Id", "1"),
                new Claim(JwtRegisteredClaimNames.Sub, user.username),
                new Claim(JwtRegisteredClaimNames.Email, user.username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            }),
            Expires = DateTime.Now.AddMinutes(5),
            Audience = audience,
            Issuer = issuer,
            SigningCredentials = credentials
        };

        var token = jwtTokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = jwtTokenHandler.WriteToken(token);
        return Results.Ok(jwtToken);
    }
    return Results.Unauthorized();
});

app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();
app.UseAuthorization();

app.Run();

record UserDto(string username, string password);
record ErrorResponse(string message);