# FFXIV IDA Comments

This script will add comments on various calls in IDA, for example:

- Addon texts on `RaptureTextModule_GetAddonText/FormatAddonText`
- ConfigOption names on `ConfigBase_GetConfigOption`
- InventoryTypes on `InventoryManager_GetInventoryContainer`
- LogMessage texts on `RaptureLogModule_ShowLogMessage`
- MainCommand names on `AgentHUD_IsMainCommandEnabled/SetMainCommandEnabledState`
- Quest names on `QuestManager_IsQuestAccepted/IsQuestComplete1`
- Addon names on `RaptureAtkModule_OpenAddon`

It also gives conditions a proper name (prefixed with `g_Conditions_`) and adds a comment to ExecuteCommand with the used op code.

Obviously, the script needs data. That's where the Exporter comes in. It exports all the text and enum values the script needs as json (in the `out/` directory).

## Instructions

0) Have Dalamud, the game, .NET SDK, IDA, Python etc. installed.
1) Clone this repo or download it as zip.
2) Run `dotnet run Exporter.csproj`
3) Run the `ffxiv_comments.py` script in IDA.

## Command Line Switches

You can add these to `dotnet run Exporter.csproj` to change some settings of the Exporter:

### `--path`

The path to the sqpack directory.  
Default is `C:\Program Files (x86)\Square Enix\FINAL FANTASY XIV - A Realm Reborn\game\sqpack`.

### `-l`, `--languages`

The languages to export (`de`, `en`, `fr`, `ja`). Default is just `en`. It is possible to specify more than one by separating them with a comma.  
You also have to change the line `language = "en"` in the `ffxiv_comments.py`.
