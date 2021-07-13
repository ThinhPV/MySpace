using Identity.Core.Abstractions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Identity.Core.DTOs.Shared
{
    public class Paginate<T> : IPaginate<T> where T : class
    {
        #region Fields
        public int PageIndex { get; set; }
        public int PageSize { get; set; }
        public int TotalRecords { get; set; }
        public int TotalPages { get; set; }
        public IList<T> Data { get; set; }
        public bool HasPrevious => PageIndex > 1;
        public bool HasNext => PageIndex < TotalPages;
        #endregion

        public Paginate()
        {
            Data = new T[0];
        }

        public Paginate(IEnumerable<T> source, int pageIndex, int pageSize)
        {
            var enumerable = source as T[] ?? source.ToArray();

            PageIndex = pageIndex;
            PageSize = pageSize;
            TotalRecords = source.Count();
            TotalPages = (int)Math.Ceiling(TotalRecords / (double)PageSize);

            if (source is IQueryable<T> queryable)
            {
                Data = queryable.Skip((pageIndex - 1) * pageSize).Take(pageSize).ToList();
            }
            else
            {
                Data = enumerable.Skip((pageIndex - 1) * pageSize).Take(pageSize).ToList();
            }
        }
    }

    public class Paginate<TSource, TResult> : IPaginate<TResult>
        where TSource : class
        where TResult : class
    {
        #region Fields
        public int PageIndex { get; set; }
        public int PageSize { get; set; }
        public int TotalRecords { get; set; }
        public int TotalPages { get; set; }
        public IList<TResult> Data { get; set; }
        public bool HasPrevious => PageIndex > 1;
        public bool HasNext => PageIndex < TotalPages;
        #endregion

        public Paginate(
            IEnumerable<TSource> source,
            Func<IEnumerable<TSource>, IEnumerable<TResult>> converter,
            int pageIndex,
            int pageSize)
        {
            PageIndex = pageIndex;
            PageSize = pageSize;
            TotalRecords = source.Count();
            TotalPages = (int)Math.Ceiling(TotalRecords / (double)PageSize);
            var items = source.Skip((pageIndex - 1) * pageSize).Take(pageSize).ToArray();
            Data = new List<TResult>(converter(items));
        }

        public Paginate(
            IPaginate<TSource> source,
            Func<IEnumerable<TSource>,
            IEnumerable<TResult>> converter)
        {
            PageIndex = source.PageIndex;
            PageSize = source.PageSize;
            TotalRecords = source.TotalRecords;
            TotalPages = source.TotalPages;
            Data = new List<TResult>(converter(source.Data));
        }
    }
}
