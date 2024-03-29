﻿using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityNetCore.Data
{
    public class ApplicationDBContext : IdentityDbContext 
    {
        public ApplicationDBContext()
        { }

        public ApplicationDBContext(DbContextOptions<ApplicationDBContext> options): base(options)
        {
                
        }
    }
}
