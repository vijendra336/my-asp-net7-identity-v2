using IdentityNetCore.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace IdentityNetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ApiSecurityController : ControllerBase
    {
        private readonly IConfiguration configuration;
        private readonly SignInManager<IdentityUser> signinManager;
        private readonly UserManager<IdentityUser> userManager;

        public ApiSecurityController(IConfiguration configuration,SignInManager<IdentityUser> signinManager,
            UserManager<IdentityUser> userManager)
        {
            this.configuration = configuration;
            this.signinManager = signinManager;
            this.userManager = userManager;
        }

        [AllowAnonymous]
        [Route(template:"Auth")]
        public async Task<IActionResult> TokenAuth(SigninViewModel model)
        {
            var issuer = configuration["Tokens:issuer"];
            var audience = configuration["Tokens:Audience"];
            var key = configuration["Tokens:Key"];

            if (ModelState.IsValid)
            {
                var signinResult = await signinManager.PasswordSignInAsync(model.Username, model.Password, isPersistent:false, lockoutOnFailure: false);

                if (signinResult.Succeeded)
                {
                    var user = await userManager.FindByEmailAsync(model.Username);
                    if(user != null)
                    {
                        var claims = new[]
                        {
                            new Claim(type:JwtRegisteredClaimNames.Email, value:user.Email),
                            new Claim(type:JwtRegisteredClaimNames.Jti, value:user.Id),
                        };

                        var keyBytes  = Encoding.UTF8.GetBytes(key);
                        var theKey = new SymmetricSecurityKey(keyBytes);
                        var creds = new SigningCredentials(theKey, SecurityAlgorithms.HmacSha256);
                        var token = new JwtSecurityToken(issuer, audience, claims, expires: DateTime.Now.AddMinutes(30), signingCredentials: creds);

                        return Ok(new {token= new JwtSecurityTokenHandler().WriteToken(token)});

                    }
                    
                }
            }
            return BadRequest();
        }
    }
}
