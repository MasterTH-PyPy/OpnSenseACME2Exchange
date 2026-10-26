using System.Globalization;

namespace OpnSenseACME2Exchange.Core.Scheduling;

public static class DailySchedule
{
    public static bool TryParseTime(string? text, out TimeOnly time) =>
        TimeOnly.TryParseExact((text ?? "").Trim(), new[] { "HH:mm", "H:mm", "HH:mm:ss" },
            CultureInfo.InvariantCulture, DateTimeStyles.None, out time);

    /// <summary>
    /// Nächster Lauf. Wurde der heutige Termin verpasst (Programm lief nicht), wird am selben Tag nachgeholt –
    /// aber nur, wenn es schon einmal einen Lauf gab (beim ersten Aktivieren nicht sofort losrennen).
    /// </summary>
    public static DateTime NextRun(DateTime now, TimeOnly time, DateTime? lastRun)
    {
        var today = now.Date + time.ToTimeSpan();
        if (lastRun.HasValue && lastRun.Value >= today) return today.AddDays(1);
        if (now < today) return today;
        if (lastRun.HasValue && lastRun.Value.Date < now.Date) return now; // heute verpasst -> nachholen
        return today.AddDays(1);
    }

    public static bool IsDue(DateTime now, TimeOnly time, DateTime? lastRun) => NextRun(now, time, lastRun) <= now;
}
