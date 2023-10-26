using IdentityNetCore.Data;
using IdentityNetCore.Service;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Add DB Context 
builder.Services.AddDbContext<ApplicationDBContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnectionString"))
    );

// setup identity 
builder.Services.AddIdentityCore<IdentityUser>()
    .AddRoles<IdentityRole>()
    .AddTokenProvider<DataProtectorTokenProvider<IdentityUser>>("AspnetIdentityAuth")
    .AddEntityFrameworkStores<ApplicationDBContext>()
    .AddDefaultTokenProviders();

//setup identityoption 
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequiredLength = 6;
    options.Password.RequiredUniqueChars = 1;
    options.SignIn.RequireConfirmedEmail = true;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Identity/Signin";
    options.AccessDeniedPath = "/Identity/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromHours(10);
});

builder.Services.Configure<SmtpOptions>(builder.Configuration.GetSection("Smtp"));
builder.Services.AddSingleton<IEmailSender, SmtpEmailSender>();

//Adding claim or policy 
//builder.Services.AddAuthorization(options =>
//{
//    options.AddPolicy("Dep", p =>
//    {
//        p.RequireClaim("Department", "Tech","Account");
//    });
//});

//combine claim policy with Roles 
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("MemberDep", p =>
    {
        p.RequireClaim("Department", "Tech").RequireRole("Member");
    });

    // Add more policies  like for admin
    //options.AddPolicy("AdminDep", p =>
    //{
    //    p.RequireClaim("Department", "Tech").RequireRole("Admin");
    //});

});

var issuer = builder.Configuration["Tokens:issuer"];
var audience = builder.Configuration["Tokens:Audience"];
var key = builder.Configuration["Tokens:Key"];


builder.Services.AddAuthentication().AddFacebook(options =>
{
    options.AppId = builder.Configuration["FacebookAppId"];
    options.AppSecret = builder.Configuration["FacebookAppSecret"];
}).AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true,
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidIssuer = issuer,
        ValidAudience = audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key))
    };
});

// 2 way Enable CORS inject it in middleware 
builder.Services.AddCors(options =>
{
    options.AddPolicy("MyCorsPolicy", cors =>
    {
        cors.WithOrigins("http://localhost:53742").WithMethods("Get").AllowAnyHeader();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

//1 way Enable CORS  --client url--
//app.UseCors(options =>
//{
//    options.WithOrigins("http://localhost:53742").WithMethods("Get").AllowAnyHeader();
//});

//2 way Enable CORS matches with policy name in services collection 
app.UseCors("MyCorsPolicy");

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
