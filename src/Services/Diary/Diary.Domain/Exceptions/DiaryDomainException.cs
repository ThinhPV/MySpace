using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Diary.Domain.Exceptions
{
    /// <summary>
    /// Exception type for domain exceptions
    /// </summary>
    public class DiaryDomainException : Exception
    {
        public DiaryDomainException()
        { }

        public DiaryDomainException(string message)
            : base(message)
        { }

        public DiaryDomainException(string message, Exception innerException)
            : base(message, innerException)
        { }
    }
}
