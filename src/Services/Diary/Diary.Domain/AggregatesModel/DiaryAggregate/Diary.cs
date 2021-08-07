using Diary.Domain.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Diary.Domain.AggregatesModel.DiaryAggregate
{
    public class Diary : Entity, IAggregateRoot
    {
        // DDD Patterns comment
        // Using private fields, allowed since EF Core 1.1, is a much better encapsulation
        // aligned with DDD Aggregates and Domain Entities (Instead of properties and property collections)
        private string _coverPictureUrl;
        private string _title;
        
        private int _diaryStatusId;
        public DiaryStatus DiaryStatus { get; private set; }

        // Draft orders have this set to true. Currently we don't check anywhere the draft status of an Order, but we could do it if needed
        private bool _isDraft;

        // DDD Patterns comment
        // Using a private field, better for DDD Aggregate's encapsulation
        // so DiaryDetail cannot be added from "outside the AggregateRoot" directly to the collection,
        // but only through the method OrderAggrergateRoot.AddOrderItem() which includes behaviour.
        private readonly DiaryDetail _diaryDetail;
        public DiaryDetail DiaryDetail => _diaryDetail;

        public static Diary NewDraft()
        {
            var diary = new Diary();
            diary._isDraft = true;
            return diary;
        }

        protected Diary()
        {
            _diaryDetail = new DiaryDetail();
            _isDraft = false;
        }


    }
}
