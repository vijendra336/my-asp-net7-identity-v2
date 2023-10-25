using IdentityNetCore.Models;
using IdentityNetCore.Service;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ActionConstraints;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using System.Numerics;
using System.Security.Claims;

namespace IdentityNetCore.Controllers
{
    public class IdentityController : Controller
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly IEmailSender emailSender;
        private readonly SignInManager<IdentityUser> signinManager;
        private readonly RoleManager<IdentityRole> roleManager;

        public IdentityController(UserManager<IdentityUser> userManager, IEmailSender emailSender
            , SignInManager<IdentityUser> signinManager, RoleManager<IdentityRole> roleManager)
        {
            this.userManager = userManager;
            this.emailSender = emailSender;
            this.signinManager = signinManager;
            this.roleManager = roleManager;
        }
        public async Task<IActionResult> Signup()
        {
            var model = new SignupViewModel() { Role = "Member" };

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupViewModel model)
        {
            if (ModelState.IsValid)
            {
                if (!(await roleManager.RoleExistsAsync(model.Role)))
                {
                    var role = new IdentityRole { Name = model.Role };
                    // creating role 
                    var roleResult = await roleManager.CreateAsync(role);

                    if (!roleResult.Succeeded)
                    {
                        var errors = roleResult.Errors.Select(s => s.Description);
                        ModelState.AddModelError("Role", string.Join(",", errors));
                    }
                }

                var checkUserEmail = await userManager.FindByEmailAsync(model.Email);

                if (checkUserEmail != null)
                {
                    var user = new IdentityUser
                    {
                        Email = model.Email,
                        UserName = model.Email,
                    };

                    var result = await userManager.CreateAsync(user, model.Password);

                    user = await userManager.FindByEmailAsync(user.Email);

                    var token = await userManager.GenerateEmailConfirmationTokenAsync(user);

                    if (result.Succeeded)
                    {
                        // adding department into claim
                        var claim = new Claim("Department", model.Department);
                        await userManager.AddClaimAsync(user, claim);

                        // adding user role 
                        await userManager.AddToRoleAsync(user, model.Role);

                        // send confirmation link to email 
                        var confirmationLink = Url.ActionLink("ConfirmEmail", "Identity", new { userId = user.Id, @token = token });

                        await emailSender.SendEmailAsync("info@mydomain.com", user.Email, "Confirm your email address.", confirmationLink);
                        return RedirectToAction("Signin", "Identity");
                    }

                    ModelState.AddModelError("Signup", string.Join("", result.Errors.Select(s => s.Description)));
                    return View(model);
                }
            }
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await userManager.FindByIdAsync(userId);

            var result = userManager.ConfirmEmailAsync(user, token);

            if (result.IsCompletedSuccessfully)
            {
                return RedirectToAction("Signin");
            }

            return new NotFoundResult();
        }

        public IActionResult Signin()
        {
            return View(new SigninViewModel());
        }

        [HttpPost]
        public async Task<IActionResult> Signin(SigninViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await signinManager.PasswordSignInAsync(model.Username, model.Password, model.RememberMe, false);
                if (result.Succeeded)
                {
                    var user = await userManager.FindByEmailAsync(model.Username);
                    var userClaims = await userManager.GetClaimsAsync(user);

                    // Instead use policies -> to check claims using Authorize Attribute 
                    //if (!userClaims.Any(claim=>claim.Type=="Department"))
                    //{
                    //    ModelState.AddModelError("Claim", "User not in Tech department.");
                    //    return View(model);
                    //}

                    if (await userManager.IsInRoleAsync(user, "Member"))
                    {
                        return RedirectToAction("Member");
                    }
                    else if (await userManager.IsInRoleAsync(user, "Admin"))
                    {
                        return RedirectToAction("Admin");
                    }
                    return RedirectToAction("Index");
                }
                else
                {
                    // Either use 2 factor authentication or islockedout 
                    ModelState.AddModelError("Login", "Cannot login.");
                }
            }

            return View(model);
        }

        public async Task<IActionResult> AccessDenied()
        {
            return View();
        }

        public async Task<IActionResult> Signout()
        {
            await signinManager.SignOutAsync();

            return RedirectToAction("Signin");
        }


        public async Task<IActionResult> MFASetup()
        {
            const string provider = "aspnetidentity";
            // generate token for MFA
            var user = await userManager.GetUserAsync(User);
            // reset the 2FA or MFA token 
            await userManager.ResetAuthenticatorKeyAsync(user); 

            var token = await userManager.GetAuthenticatorKeyAsync(user);

            //QR Code url 
            var qrCodeUrl = $"otpauth://totp/{provider}:{user.Email}?secret={token}&issuer={provider}&digit=6";

            var model = new MFAViewModel() { Token = token , QRCodeUrl=qrCodeUrl};

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> MFASetup(MFAViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await userManager.GetUserAsync(User);
                var succeeded= await userManager.VerifyTwoFactorTokenAsync(user, userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
                if (succeeded)
                {
                    // enable 2 factor authentication
                    // this user so that next time they try to  log in, we ask for the two factor authentication code
                    await userManager.SetTwoFactorEnabledAsync(user, true);

                }
                else
                {
                    ModelState.AddModelError("Verify", "Your MFA code could not be validated");
                }
            }

            return View(model);
        }

        [HttpPost]
        public IActionResult ExternalLogin(string provider, string returnUrl=null)
        {
            // Either Redirect to Facebook or Google based on provider
            var properties = signinManager.ConfigureExternalAuthenticationProperties(provider, returnUrl);

            // helper class Url - create a link to call  ExternalLoginCallback action method 
            var callbackUrl = Url.Action("ExternalLoginCallback");

            properties.RedirectUri = callbackUrl;

            // sending the user back to external provider.
            return Challenge(properties, provider);

        }

        [HttpPost]
        public async Task<IActionResult> ExternalLoginCallback()
        {
            return View();
        }
    }
}
