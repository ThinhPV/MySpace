using Diary.Domain.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Diary.Domain.AggregatesModel.DiaryAggregate
{
    public class DiaryDetail : Entity
    {
        // DDD Patterns comment
        // Using private fields, allowed since EF Core 1.1, is a much better encapsulation
        // aligned with DDD Aggregates and Domain Entities (Instead of properties and property collections)
        private DateTime _eventDate;

        // Address is a Value Object pattern example persisted as EF Core 2.0 owned entity
        public Address Address { get; private set; }

        public int? GetUserId => _userId;
        private int? _userId;

        public DiaryStatus DiaryStatus { get; private set; }
        private int _diaryStatusId;

    }
}
