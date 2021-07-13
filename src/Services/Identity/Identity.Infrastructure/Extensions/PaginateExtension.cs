using Identity.Core.Abstractions;
using Identity.Core.DTOs.Shared;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Identity.Infrastructure.Extensions
{
    public static class PaginateExtension
    {
        public static async Task<IPaginate<T>> ToPaginateAsync<T>(this IEnumerable<T> source, int pageIndex, int pageSize)
            where T : class
        {
            var enumerable = source as T[] ?? source.ToArray();

            if (pageIndex <= 0)
            {
                return await FitToOnePageAsync(source);
            }

            var totalRecords = source.Count();
            return new Paginate<T>()
            {
                PageIndex = pageIndex,
                PageSize = pageSize,
                TotalRecords = totalRecords,
                TotalPages = (int)Math.Ceiling(totalRecords / (double)pageSize),
                Data = source is IQueryable<T> queryable
                    ? await queryable.Skip((pageIndex - 1) * pageSize).Take(pageSize).ToListAsync()
                    : enumerable.Skip((pageIndex - 1) * pageSize).Take(pageSize).ToList()
            };
        }

        public static IPaginate<TResult> ToPaginate<TSource, TResult>(
            this IEnumerable<TSource> source,
            Func<IEnumerable<TSource>, IEnumerable<TResult>> converter,
            int pageIndex,
            int pageSize)
            where TSource : class
            where TResult : class
        {
            return new Paginate<TSource, TResult>(source, converter, pageIndex, pageSize);
        }


        private static async Task<Paginate<T>> FitToOnePageAsync<T>(IEnumerable<T> source)
            where T : class
        {
            var totalRecord = source.Count();

            return new Paginate<T>()
            {
                PageSize = totalRecord,
                TotalRecords = totalRecord,
                PageIndex = 1,
                TotalPages = 1,
                Data = source is IQueryable<T> queryable
                        ? await queryable.ToListAsync()
                        : source.ToList()
            };
        }
    }
}
