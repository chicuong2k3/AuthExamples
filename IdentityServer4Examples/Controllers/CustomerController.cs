using IdentityServer4Examples.Database;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServer4Examples.Controllers
{
    public class CustomerController : ControllerBase
    {
        private readonly AppDbContext dbContext;

        public CustomerController(AppDbContext dbContext)
        {
            this.dbContext = dbContext;
        }
        [HttpGet("/customer/{id}")]
        public async Task<ActionResult> GetAsync(Guid id)
        {
            var customer = await dbContext.Customers.FindAsync(id);
            return Ok(customer);
        }

    }
}
