using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace IdentityNetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProductsController : ControllerBase
    {
        [HttpGet]
        [Route(template:"List")]
        public List<Product> GetProducts()
        {
            var chair = new Product { Name = "Chair", Price = 100 };
            var desk = new Product { Name = "Desk", Price = 50 };
            
            return new List<Product> { chair, desk };   
        }
    }
}
