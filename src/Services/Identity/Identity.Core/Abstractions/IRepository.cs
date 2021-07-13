using Microsoft.EntityFrameworkCore.Query;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;

namespace Identity.Core.Abstractions
{
    public interface IRepository<T> : IDisposable where T : class
    {
        /// <summary>
        /// Finds an entity with the given primary key values. If an entity with the given primary key values
        /// is being tracked by the context, then it is returned immediately without making a request to the database.
        /// Otherwise, a query is made to the database for an entity with the given primary key values
        /// and this entity, if found, is attached to the context an returned.
        /// If no entity is found, then null is returned.
        /// </summary>
        /// <param name="keyValues">The values of the primary key for the entity to be found.</param>
        /// <returns></returns>
        T Find(params object[] keyValues);

        /// <summary>
        /// Finds an entity with the given primary key values. If an entity with the given primary key values
        /// is being tracked by the context, then it is returned immediately without making a request to the database.
        /// Otherwise, a query is made to the database for an entity with the given primary key values
        /// and this entity, if found, is attached to the context an returned.
        /// If no entity is found, then null is returned.
        /// </summary>
        /// <param name="keyValues">The values of the primary key for the entity to be found.</param>
        /// <returns></returns>
        Task<T> FindAsync(params object[] keyValues);

        /// <summary>
        /// Get the first or default entity based on a predicate, orderby delegate and include delegate.
        /// This method default no-tracking query.
        /// </summary>
        /// <param name="predicate">A function to test each element for a condition.</param>
        /// <param name="orderBy">A function to order elements.</param>
        /// <param name="include">A function to include navigate properties.</param>
        /// <param name="disableTracking"><c>True</c> to disable changing tracking; otherwise, <c>False</c></param>
        /// <returns></returns>
        T FirstOrDefault(
            Expression<Func<T, bool>> predicate = null,
            Func<IQueryable<T>, IOrderedQueryable<T>> orderBy = null,
            Func<IQueryable<T>, IIncludableQueryable<T, object>> include = null,
            bool disableTracking = true);


        /// <summary>
        /// Get the first or default entity based on a predicate, orderby delegate and include delegate.
        /// This method default no-tracking query.
        /// </summary>
        /// <param name="predicate">A function to test each element for a condition.</param>
        /// <param name="orderBy">A function to order elements.</param>
        /// <param name="include">A function to include navigate properties.</param>
        /// <param name="disableTracking"><c>True</c> to disable changing tracking; otherwise, <c>False</c></param>
        /// <returns></returns>
        Task<T> FirstOrDefaultAsync(
            Expression<Func<T, bool>> predicate = null,
            Func<IQueryable<T>, IOrderedQueryable<T>> orderBy = null,
            Func<IQueryable<T>, IIncludableQueryable<T, object>> include = null,
            bool disableTracking = true);

        /// <summary>
        /// Get the first or default entity based on a predicate, orderby delegate and include delegate.
        /// This method default no-tracking query.
        /// </summary>
        /// <typeparam name="TResult"></typeparam>
        /// <param name="selector">The selector for projection.</param>
        /// <param name="predicate">A function to test each element for a condition.</param>
        /// <param name="orderBy">A function to order elements.</param>
        /// <param name="include">A function to include navigate properties.</param>
        /// <param name="disableTracking"><c>True</c> to disable changing tracking; otherwise, <c>False</c></param>
        /// <returns></returns>
        Task<TResult> FirstOrDefaultAsync<TResult>(
            Expression<Func<T, TResult>> selector = null,
            Expression<Func<T, bool>> predicate = null,
            Func<IQueryable<T>, IOrderedQueryable<T>> orderBy = null,
            Func<IQueryable<T>, IIncludableQueryable<T, object>> include = null,
            bool disableTracking = true);

        /// <summary>
        /// Get list entity based on predicate, orderby delegate and include delegate
        /// This method default no-tracking query
        /// </summary>
        /// <param name="predicate">A funcation to test each element for a condition</param>
        /// <param name="orderBy">A function to order elements</param>
        /// <param name="include">A function to navigate properties</param>
        /// <param name="disableTracking"><c>True</c> to disable changing tracking; otherwise, <c>False</c></param>
        /// <returns></returns>
        IEnumerable<T> GetList(
            Expression<Func<T, bool>> predicate = null,
            Func<IQueryable<T>, IOrderedQueryable<T>> orderBy = null,
            Func<IQueryable<T>, IIncludableQueryable<T, object>> include = null,
            bool disableTracking = true);

        /// <summary>
        /// Get list entity based on predicate, orderby delegate and include delegate
        /// This method default no-tracking query
        /// </summary>
        /// <param name="predicate">A funcation to test each element for a condition</param>
        /// <param name="orderBy">A function to order elements</param>
        /// <param name="include">A function to navigate properties</param>
        /// <param name="disableTracking"><c>True</c> to disable changing tracking; otherwise, <c>False</c></param>
        /// <returns></returns>
        Task<IEnumerable<T>> GetListAsync(
            Expression<Func<T, bool>> predicate = null,
            Func<IQueryable<T>, IOrderedQueryable<T>> orderBy = null,
            Func<IQueryable<T>, IIncludableQueryable<T, object>> include = null,
            bool disableTracking = true);

        /// <summary>
        /// Get list entity based on predicate, orderby delegate and include delegate
        /// This method default no-tracking query
        /// </summary>
        /// <param name="selector">The selector for projection</param>
        /// <param name="predicate">A funcation to test each element for a condition</param>
        /// <param name="orderBy">A function to order elements</param>
        /// <param name="include">A function to navigate properties</param>
        /// <param name="disableTracking"><c>True</c> to disable changing tracking; otherwise, <c>False</c></param>
        /// <returns></returns>
        Task<IEnumerable<TResult>> GetListAsync<TResult>(
            Expression<Func<T, TResult>> selector = null,
            Expression<Func<T, bool>> predicate = null,
            Func<IQueryable<T>, IOrderedQueryable<T>> orderBy = null,
            Func<IQueryable<T>, IIncludableQueryable<T, object>> include = null,
            bool disableTracking = true);

        /// <summary>
        /// Get an <see cref="IPaginate{T}"/> that contains elements that satisfy the condition specified by <paramref name="predicate"/>
        /// </summary>
        /// <param name="predicate">A function to test each element for a condition</param>
        /// <param name="orderBy">A function to order elements</param>
        /// <param name="include">A function to navigate properties</param>
        /// <param name="pageIndex">The page index</param>
        /// <param name="pageSize">The page size</param>
        /// <param name="diableTracking"><c>True</c> to disable changing tracking; otherwise, <c>False</c></param>
        /// <returns>An <see cref="IPaginate{T}"/> that contains elements that satisfy the condition specified by <paramref name="predicate"/>.</returns>
        /// <remarks>This method default no-tracking query</remarks>
        Task<IPaginate<T>> GetPagedListAsync(
            Expression<Func<T, bool>> predicate = null,
            Func<IQueryable<T>, IOrderedEnumerable<T>> orderBy = null,
            Func<IQueryable<T>, IIncludableQueryable<T, object>> include = null,
            int pageIndex = 1,
            int pageSize = 20,
            bool diableTracking = true);

        /// <summary>
        /// Get an <see cref="IPaginate{T}"/> that contains elements that satisfy the condition specified by <paramref name="predicate"/> 
        /// </summary>
        /// <typeparam name="TResult"></typeparam>
        /// <param name="selector">The selector for projection</param>
        /// <param name="predicate">A function to test each element for a condition</param>
        /// <param name="orderBy">A function to order elements</param>
        /// <param name="include">A function to navigate properties</param>
        /// <param name="pageIndex">The page index</param>
        /// <param name="pageSize">The page size</param>
        /// <param name="diableTracking"><c>True</c> to disable changing tracking; otherwise, <c>False</c></param>
        /// <returns>An <see cref="IPaginate{T}"/> that contains elements that satisfy the condition specified by <paramref name="predicate"/>.</returns>
        /// <remarks>This method default no-tracking query</remarks>
        Task<IPaginate<TResult>> GetPagedListAsync<TResult>(
            Expression<Func<T, TResult>> selector,
            Expression<Func<T, bool>> predicate = null,
            Func<IQueryable<T>, IOrderedQueryable<T>> orderBy = null,
            Func<IQueryable<T>, IIncludableQueryable<T, object>> include = null,
            int pageIndex = 1,
            int pageSize = 20,
            bool diableTracking = true) where TResult : class;
    }
}
