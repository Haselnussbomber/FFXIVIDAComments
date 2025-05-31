using CommandLine;
using ExdExport;
using Lumina;
using Lumina.Data;
using Lumina.Excel;
using Lumina.Excel.Sheets;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;

var options = Parser.Default.ParseArguments<Options>(args).Value;

if (string.IsNullOrWhiteSpace(options.Path))
    throw new Exception("Path to sqpack directory is empty.");

if (options.Languages == null || options.Languages.Length == 0)
    throw new Exception("No languages selected.");

Console.WriteLine($"Path: {options.Path}");
Console.WriteLine($"Languages: {string.Join(", ", options.Languages)}");

var gameData = new GameData(options.Path, new()
{
    PanicOnSheetChecksumMismatch = false,
    CacheFileResources = false,
});

if (!Directory.Exists("out"))
    Directory.CreateDirectory("out");

// export sheets
foreach (var selectedLangStr in options.Languages!)
{
    foreach (var (lang, langStr) in LanguageUtil.LanguageMap)
    {
        if (langStr == selectedLangStr)
        {
            WriteRows<Addon>(lang, langStr, (row) => (row.RowId, row.Text.ToString()));
            WriteRows<Lumina.Excel.Sheets.Error>(lang, langStr, (row) => (row.RowId, row.Unknown0.ToString()));
            WriteRows<Lobby>(lang, langStr, (row) => (row.RowId, row.Text.ToString()));
            WriteRows<LogMessage>(lang, langStr, (row) => (row.RowId, row.Text.ToString()));
            WriteRows<MainCommand>(lang, langStr, (row) => (row.RowId, row.Name.ToString()));
            WriteRows<Quest>(lang, langStr, (row) => (row.RowId - ushort.MaxValue, row.Name.ToString()));
            WriteRows<Item>(lang, langStr, (row) => row.RowId == 0 ? null : (row.RowId, row.Name.ToString()));
            WriteRows<Status>(lang, langStr, (row) => row.RowId == 0 ? null : (row.RowId, row.Name.ToString()));
            break;
        }
    }
}

// export conditions
ExportConditions("out/Conditions.json");

Console.WriteLine("Done!");

// ---------------------------

void WriteRows<T>(Language lang, string langStr, Func<T, (uint, string)?> getkv) where T : struct, IExcelRow<T>
{
    var sheet = gameData.GetExcelSheet<T>(lang);
    if (sheet == null)
        return;

    var sheetName = typeof(T).GetCustomAttribute<SheetAttribute>()!.Name;

    var outDir = $"out/{langStr}";
    if (!Directory.Exists(outDir))
        Directory.CreateDirectory(outDir);

    using var fileStream = File.Create($"{outDir}/{sheetName}.json");
    using var writer = new Utf8JsonWriter(fileStream, new()
    {
        Indented = true,
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.BasicLatin, UnicodeRanges.Latin1Supplement)
    });

    writer.WriteStartObject();

    var i = 0;
    using var pb = new ProgressBar();

    foreach (var row in sheet)
    {
        pb.Report((double)i / sheet.Count);
        i++;

        var kv = getkv(row);
        if (kv.HasValue)
            writer.WriteString(kv.Value.Item1.ToString(), kv.Value.Item2);
    }

    writer.WriteEndObject(); // end root
    writer.Flush();
}

void ExportConditions(string outPath)
{
    var type = typeof(Dalamud.Game.ClientState.Conditions.ConditionFlag);

    using var fileStream = File.OpenWrite(outPath);
    using var writer = new Utf8JsonWriter(fileStream, new()
    {
        Indented = true,
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.BasicLatin, UnicodeRanges.Latin1Supplement)
    });

    writer.WriteStartObject();

    var i = 0;
    using var pb = new ProgressBar();
    var values = Enum.GetValues(type);
    var processedNames = new HashSet<string>();

    foreach (var value in Enum.GetValues(type))
    {
        pb.Report((double)i / values.Length);
        i++;

        if (value == null)
            continue;

        var name = Enum.GetName(type, value);
        if (name == null || processedNames.Contains(name))
            continue;

        writer.WriteString(((int)value).ToString(), name);
        processedNames.Add(name);
    }

    writer.WriteEndObject(); // end root
    writer.Flush();
}

public record Options
{
    [Option("path", HelpText = "The path to the sqpack directory.", Default = @"C:\Program Files (x86)\SquareEnix\FINAL FANTASY XIV - A Realm Reborn\game\sqpack")]
    public string? Path { get; set; }

    [Option('l', "languages", HelpText = "The languages to export (de, en, fr, ja).", Default = new string[] { "en" }, Separator = ',')]
    public string[]? Languages { get; set; }
}
