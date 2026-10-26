using System.Text;
using System.Text.RegularExpressions;
using OpnSenseACME2Exchange.Core.Ipc;

namespace OpnSenseACME2Exchange.Core.Logging;

/// <summary>Liefert Logdateien stückweise an die GUI (nur eigene Logdateien, keine Pfade von außen).</summary>
public static class LogReader
{
    private static readonly Regex ValidName = new(@"^" + Regex.Escape(Log.FilePrefix) + @"\d{4}-\d{2}-\d{2}\.log$", RegexOptions.Compiled);
    public const int MaxChunk = 512 * 1024;

    public static LogListDto List(string directory)
    {
        var files = new List<LogFileDto>();
        if (Directory.Exists(directory))
        {
            foreach (var f in Directory.EnumerateFiles(directory, Log.FilePrefix + "*.log"))
            {
                var fi = new FileInfo(f);
                if (ValidName.IsMatch(fi.Name)) files.Add(new LogFileDto(fi.Name, fi.Length, fi.LastWriteTime));
            }
        }
        var current = Path.GetFileName(Log.FileFor(DateTime.Now));
        if (!files.Any(f => f.Name == current)) files.Add(new LogFileDto(current, 0, DateTime.Now));
        return new LogListDto(files.OrderByDescending(f => f.Name, StringComparer.Ordinal).ToList(), current);
    }

    public static LogChunkDto Read(string directory, string name, long offset)
    {
        if (!ValidName.IsMatch(name)) throw new ArgumentException("Ungültiger Logdateiname.");
        var path = Path.Combine(directory, name);
        if (!File.Exists(path)) return new LogChunkDto(name, "", 0, 0, offset != 0);

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var length = fs.Length;
        bool reset = false;
        if (offset > length || offset < 0) { offset = 0; reset = true; }

        // Bei großen Dateien nur das Ende liefern
        if (offset == 0 && length > MaxChunk) { offset = length - MaxChunk; reset = true; }

        fs.Seek(offset, SeekOrigin.Begin);
        var count = (int)Math.Min(MaxChunk, length - offset);
        var buf = new byte[count];
        int read = 0;
        while (read < count)
        {
            var n = fs.Read(buf, read, count - read);
            if (n == 0) break;
            read += n;
        }
        if (read == 0) return new LogChunkDto(name, "", offset, length, reset);
        // Nur vollständige Zeilen liefern, damit nichts mitten in einem UTF-8-Zeichen abreißt
        var lastNl = Array.LastIndexOf(buf, (byte)'\n', Math.Max(0, read - 1));
        var usable = lastNl >= 0 ? lastNl + 1 : (offset + read >= length ? read : 0);
        var text = Encoding.UTF8.GetString(buf, 0, usable);
        if (text.Length > 0 && text[0] == '﻿') text = text[1..];
        return new LogChunkDto(name, text, offset + usable, length, reset);
    }
}
