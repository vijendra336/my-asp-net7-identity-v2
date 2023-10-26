using Microsoft.AspNetCore.Mvc;
using StudentEnroll.Models;

namespace StudentEnroll.Controllers
{
    public class StudentsController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Signup(StudentViewModel model)
        {
            return View("Result",model);
        }
    }
}
