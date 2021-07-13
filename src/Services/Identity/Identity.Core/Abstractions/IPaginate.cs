using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Identity.Core.Abstractions
{
    public interface IPaginate<T> where T : class
    {
        int PageIndex { get; }
        int PageSize { get; }
        int TotalRecords { get; }
        int TotalPages { get; }
        IList<T> Data { get; }
        bool HasPrevious { get; }
        bool HasNext { get; }
    }
}
