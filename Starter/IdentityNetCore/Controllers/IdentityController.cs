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

        public IdentityController(UserManager<IdentityUser> userManager, IEmailSender emailSender)
        {
            this.userManager = userManager;
            this.emailSender = emailSender;
        }
        public async Task<IActionResult> Signup()
        {
            var model = new SignupViewModel();

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupViewModel model)
        {
            if(ModelState.IsValid)
            {
               var checkUserEmail = await userManager.FindByEmailAsync(model.Email);

               if(checkUserEmail != null)
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
                       var confirmationLink= Url.ActionLink("ConfirmEmail", "Identity", new { userId= user.Id, @token = token });

                        await emailSender.SendEmailAsync("info@mydomain.com", user.Email , "Confirm your email address.", confirmationLink);
                        return RedirectToAction("Signin", "Identity");
                    }

                    ModelState.AddModelError("Signup", string.Join("",result.Errors.Select(s=>s.Description)));
                    return View(model);
                }
            }
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await userManager.FindByIdAsync(userId);

            var result =userManager.ConfirmEmailAsync(user, token);

            if (result.IsCompletedSuccessfully)
            {
                return RedirectToAction("Signin");
            }

            return new NotFoundResult();
        }

        public async Task<IActionResult> Signin()
        {
            return View();
        }

        public async Task<IActionResult> AccessDenied()
        {
            return View();
        }
    }
}
