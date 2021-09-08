using APIJWTAuthentication.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace APIJWTAuthentication.Data
{
    public class ApplicationContext : IdentityDbContext<ApplicationUser, IdentityRole, string>
    {
        public ApplicationContext(DbContextOptions options) : base(options)
        {
        }
    }
}
