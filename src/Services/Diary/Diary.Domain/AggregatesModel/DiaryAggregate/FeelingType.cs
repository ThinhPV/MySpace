using Diary.Domain.Common;

namespace Diary.Domain.AggregatesModel.DiaryAggregate
{
    public class FeelingType : Enumeration
    {
        public static FeelingType Happy = new(1, nameof(Happy));
        public static FeelingType Confident = new(2, nameof(Confident));
        public static FeelingType Ecstatic = new(3, nameof(Ecstatic));
        public static FeelingType Confused = new(4, nameof(Confused));
        public static FeelingType Angry = new(5, nameof(Angry));
        public static FeelingType Sick = new(6, nameof(Sick));
        public static FeelingType Bored = new(7, nameof(Bored));
        public static FeelingType Hot = new(8, nameof(Hot));
        public static FeelingType Loving = new(9, nameof(Loving));

        public FeelingType(int id, string name)
            : base(id, name)
        {
        }
    }
}
