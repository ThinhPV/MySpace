using Diary.Domain.Common;

namespace Diary.Domain.AggregatesModel.DiaryAggregate
{
    public class WaetherType : Enumeration
    {
        public static WaetherType Sunny = new(1, nameof(Sunny));
        public static WaetherType PartiallyCloudy = new(2, nameof(PartiallyCloudy));
        public static WaetherType Cloudy = new(3, nameof(Cloudy));
        public static WaetherType Overcast = new(4, nameof(Overcast));
        public static WaetherType Rain = new(5, nameof(Rain));
        public static WaetherType Drizzle = new(6, nameof(Drizzle));
        public static WaetherType Snow = new(7, nameof(Snow));
        public static WaetherType Stormy = new(8, nameof(Stormy));
        public static WaetherType Fog = new(9, nameof(Fog));

        public WaetherType(int id, string name)
            : base(id, name)
        {
        }
    }
}
