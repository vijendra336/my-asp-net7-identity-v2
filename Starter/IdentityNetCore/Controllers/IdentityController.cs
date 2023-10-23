using IdentityNetCore.Models;
using IdentityNetCore.Service;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

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
            var model = new SignupViewModel() { Role= "Member"};

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
                        ModelState.AddModelError("Role",string.Join(",", errors));
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
                var result =await signinManager.PasswordSignInAsync(model.Username, model.Password, model.RememberMe, false);
                if(result.Succeeded)
                {
                    var user = await userManager.FindByEmailAsync(model.Username);
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
    }
}
