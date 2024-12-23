﻿using CommandLine;
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
            break;
        }
    }
}

// export root.exl
gameData.GetFile("exd/root.exl")?.SaveFileRaw("out/root.exl");

// export config options
ExportEnum<FFXIVClientStructs.FFXIV.Client.UI.Misc.ConfigOption>("out/ConfigOptions.json");

// export inventory types
ExportEnum<FFXIVClientStructs.FFXIV.Client.Game.InventoryType>("out/InventoryTypes.json");

// export conditions
ExportConditions("out/Conditions.json");

Console.WriteLine("Done!");

// ---------------------------

void WriteRows<T>(Language lang, string langStr, Func<T, (uint, string)> getkv) where T : struct, IExcelRow<T>
{
    var sheet = gameData.GetExcelSheet<T>(lang);
    if (sheet == null)
        return;

    var sheetName = typeof(T).GetCustomAttribute<SheetAttribute>()!.Name;

    var outDir = $"out/{langStr}";
    if (!Directory.Exists(outDir))
        Directory.CreateDirectory(outDir);

    var sheetOutPath = $"{outDir}/{sheetName}.json";
    if (File.Exists(sheetOutPath) && new FileInfo(sheetOutPath).Length > 0)
        return;

    using var fileStream = File.OpenWrite(sheetOutPath);
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
        writer.WriteString(kv.Item1.ToString(), kv.Item2);
    }

    writer.WriteEndObject(); // end root
    writer.Flush();
}

void ExportEnum<TE>(string outPath) where TE : Enum
{
    var type = typeof(TE);
    var underlyingType = type.GetEnumUnderlyingType().Name;

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

        switch (underlyingType)
        {
            case nameof(Byte):
                writer.WriteString(((byte)value).ToString(), name);
                break;

            case nameof(SByte):
                writer.WriteString(((sbyte)value).ToString(), name);
                break;

            case nameof(Int16):
                writer.WriteString(((short)value).ToString(), name);
                break;

            case nameof(UInt16):
                writer.WriteString(((ushort)value).ToString(), name);
                break;

            case nameof(Int32):
                writer.WriteString(((int)value).ToString(), name);
                break;

            case nameof(UInt32):
                writer.WriteString(((uint)value).ToString(), name);
                break;
        }

        processedNames.Add(name);
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
