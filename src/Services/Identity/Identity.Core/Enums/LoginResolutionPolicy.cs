using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Identity.Core.Enums
{
    // From where should the login be sourced
    // by default it's sourced from Username
    public enum LoginResolutionPolicy
    {
        Username = 0,
        Email = 1,
        PhoneNumber = 2
    }
}
