using Diary.Domain.Common;
using Diary.Domain.Exceptions;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Diary.Domain.AggregatesModel.DiaryAggregate
{
    public class DiaryStatus : Enumeration
    {
        public static DiaryStatus Draft = new DiaryStatus(1, nameof(Draft).ToLowerInvariant());
        public static DiaryStatus AwaitingValidation = new DiaryStatus(2, nameof(AwaitingValidation).ToLowerInvariant());
        public static DiaryStatus Published = new DiaryStatus(3, nameof(Published).ToLowerInvariant());
        public static DiaryStatus Cancelled = new DiaryStatus(4, nameof(Cancelled).ToLowerInvariant());
        public static DiaryStatus Deleted = new DiaryStatus(5, nameof(Deleted).ToLowerInvariant());

        public DiaryStatus(int id, string name)
            : base(id, name)
        {
        }


        public static IEnumerable<DiaryStatus> List() =>
            new[] { Draft, AwaitingValidation, Published, Cancelled, Deleted};

        public static DiaryStatus FromName(string name)
        {
            var state = List()
                .SingleOrDefault(s => String.Equals(s.Name, name, StringComparison.CurrentCultureIgnoreCase));

            if (state == null)
            {
                throw new DiaryDomainException($"Possible values for DiaryStatus: {String.Join(",", List().Select(s => s.Name))}");
            }

            return state;
        }

        public static DiaryStatus From(int id)
        {
            var state = List().SingleOrDefault(s => s.Id == id);

            if (state == null)
            {
                throw new DiaryDomainException($"Possible values for DiaryStatus: {String.Join(",", List().Select(s => s.Name))}");
            }

            return state;
        }
    }
}
