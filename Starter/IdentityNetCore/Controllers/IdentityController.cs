using IdentityNetCore.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityNetCore.Controllers
{
    public class IdentityController : Controller
    {
        private readonly UserManager<IdentityUser> userManager;

        public IdentityController(UserManager<IdentityUser> userManager)
        {
            this.userManager = userManager;
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

                    if (result.Succeeded)
                    {
                        return RedirectToAction("Signin", "Identity");
                    }

                    ModelState.AddModelError("Signup", string.Join("",result.Errors.Select(s=>s.Description)));
                    return View(model);
                }
            }
            return View(model);
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
