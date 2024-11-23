import os
import codecs
import csv
import json
import re
import ida_funcs
import ida_bytes
import ida_allins
import idaapi
import idautils
import idc

debug = False
dataPath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "out")
language = "en"

text_segment = ida_segment.get_segm_by_name('.text')

def main() -> None:
    exl = read_csv(os.path.join(dataPath, "root.exl"), 1, 0)
    addonRows = read_json(os.path.join(dataPath, language, "Addon.json"))
    lobbyRows = read_json(os.path.join(dataPath, language, "Lobby.json"))
    logmessageRows = read_json(os.path.join(dataPath, language, "LogMessage.json"))
    quests = read_json(os.path.join(dataPath, language, "Quest.json"))
    maincommands = read_json(os.path.join(dataPath, language, "MainCommand.json"))
    configOptions = read_json(os.path.join(dataPath, "ConfigOptions.json"))
    conditions = read_json(os.path.join(dataPath, "Conditions.json"))
    inventoryTypes = read_json(os.path.join(dataPath, "InventoryTypes.json"))
    addonNames = get_addon_names()

    addonSigs = {
        "E8 ?? ?? ?? ?? 8D 14 BF", # AgentInterface_GetAddonTextById
        "E8 ?? ?? ?? ?? 48 8D 4E 40 48 8B D0", # RaptureTextModule_FormatAddonTextApply

        "E9 ?? ?? ?? ?? 80 EA 20",                                                                   # RaptureTextModule_GetAddonText
        "E8 ?? ?? ?? ?? 8D 4D 2B",                                                                # RaptureTextModule_FormatAddonText1<string>
        "E8 ?? ?? ?? ?? 44 8B 4D 20",                                                                # RaptureTextModule_FormatAddonText1<string,int>
        "E8 ?? ?? ?? ?? EB 67 B8",                                                                   # RaptureTextModule_FormatAddonText1<string,int,uint>
        "E8 ?? ?? ?? ?? 49 8B 4D 28 48 8B D0",                                              # RaptureTextModule_FormatAddonText1<string,string>
        "E8 ?? ?? ?? ?? 4C 8B B4 24 ?? ?? ?? ?? 49 8D B7",                                  # RaptureTextModule_FormatAddonText1<string,string,string>
        "E8 ?? ?? ?? ?? 8D 4D 2C",                                                                   # RaptureTextModule_FormatAddonText1<int>
        "E8 ?? ?? ?? ?? 80 7E 4E 00",                                                                # RaptureTextModule_FormatAddonText1<int,int>
        "E8 ?? ?? ?? ?? 8B 7D FF",                                                                # RaptureTextModule_FormatAddonText1<int,int,uint>
        "E8 ?? ?? ?? ?? EB 38 49 8B D2",                                                             # RaptureTextModule_FormatAddonText1<int,int,uint,uint>
        "E8 ?? ?? ?? ?? 8B 5C 24 44 48 8B D0",                                                          # RaptureTextModule_FormatAddonText1<int,string>
        "E8 ?? ?? ?? ?? 4C 8B C5 48 89 44 24",                                                          # RaptureTextModule_FormatAddonText2<string>
        "E8 ?? ?? ?? ?? EB 67 48 8B 7E 10",                                                             # RaptureTextModule_FormatAddonText2<string,int>
        "E8 ?? ?? ?? ?? 48 8B 7C 24 ?? EB 14",                            # RaptureTextModule_FormatAddonText2<string,int,uint>
                                                                                                     # RaptureTextModule_FormatAddonText2<string,int,uint,uint> # unused
        "E8 ?? ?? ?? ?? 48 8B D0 48 8D 4D E0 E8 ?? ?? ?? ?? 49 8B 9D",                               # RaptureTextModule_FormatAddonText2<string,int,uint,uint,uint>
                                                                                                     # RaptureTextModule_FormatAddonText2<string,int,uint,uint,uint,uint> # unused
        "E8 ?? ?? ?? ?? 48 8B 8C 24 ?? ?? ?? ?? 45 33 C9 4C 8B C0 C6 44 24",                                           # RaptureTextModule_FormatAddonText2<string,int,uint,uint,uint,uint,uint>
        "E8 ?? ?? ?? ?? 48 8B D0 48 8B 8F",                                                    # RaptureTextModule_FormatAddonText2<string,string>
                                                                                                     # RaptureTextModule_FormatAddonText2<string,string,string> # unused
        "E8 ?? ?? ?? ?? 48 8B D0 48 8D 4C 24 ?? 41 8B C7",                                           # RaptureTextModule_FormatAddonText2<string,string,uint>
                                                                                                     # RaptureTextModule_FormatAddonText2<string,string,uint,uint> # unused
        "E8 ?? ?? ?? ?? 41 39 76 08",                                     # RaptureTextModule_FormatAddonText2<string,string,uint,uint,uint>
        "E8 ?? ?? ?? ?? 4C 8B 65 80 4C 8B C0", # RaptureTextModule_FormatAddonText2<string,string,string,uint,uint>
        "E8 ?? ?? ?? ?? 41 8D 55 0B",                                                                   # RaptureTextModule_FormatAddonText2<int>
        "E8 ?? ?? ?? ?? EB 51 0F B6 DB",                                                             # RaptureTextModule_FormatAddonText2<int,int>
        "E8 ?? ?? ?? ?? 48 8B D8 EB 38",                                                          # RaptureTextModule_FormatAddonText2<int,int,uint>
        "E8 ?? ?? ?? ?? EB 72 4C 8B 42 30",                                                                # RaptureTextModule_FormatAddonText2<int,int,uint,uint>
        "E8 ?? ?? ?? ?? 8D 4D 64",                                                                   # RaptureTextModule_FormatAddonText2<int,int,uint,uint,uint>
                                                                                                     # RaptureTextModule_FormatAddonText2<int,int,uint,uint,uint,uint> # unused
        "E8 ?? ?? ?? ?? 4C 8B 64 24 ?? 4C 8B 74 24 ?? 48 8B 9C 24",                               # RaptureTextModule_FormatAddonText2<int,int,uint,uint,uint,uint,uint>
        "E8 ?? ?? ?? ?? EB 41 41 8B F7",                                                             # RaptureTextModule_FormatAddonText2<int,string>
        "E8 ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 45 0F B7 C6",                                        # RaptureTextModule_FormatAddonText2<int,int,string>
                                                                                                     # RaptureTextModule_FormatAddonText2<int,string,uint> # unused

        "E8 ?? ?? ?? ?? 48 8B 0C FE"
    }

    for idx, sig in enumerate(addonSigs):
        scan_and_comment(f"FormatAddonText{idx}", sig, addonRows)

    scan_and_comment("GetLobbyText", "E8 ?? ?? ?? ?? 48 8B F0 EB 47", lobbyRows)
    scan_and_comment("RaptureLogModule_ShowLogMessage", "E8 ?? ?? ?? ?? EB AA", logmessageRows)
    scan_and_comment("RaptureLogModule_ShowLogMessage<uint>", "E8 ?? ?? ?? ?? 41 8B 5E 28", logmessageRows)
    scan_and_comment("RaptureLogModule_ShowLogMessage<uint,uint>", "E8 ?? ?? ?? ?? 0F BE 4B 44", logmessageRows)
    scan_and_comment("RaptureLogModule_ShowLogMessage<uint,uint,uint>", "E8 ?? ?? ?? ?? 40 84 ED 0F 84 ?? ?? ?? ?? 83 7F 20 00", logmessageRows)
    scan_and_comment("RaptureLogModule_ShowLogMessage<string>", "E8 ?? ?? ?? ?? EB 68 48 8B 07", logmessageRows)
    scan_and_comment("BattleLog_AddLogMessage", "E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? F3 0F 11 44 24", logmessageRows)
    scan_and_comment("SomeLogMessage", "E8 ?? ?? ?? ?? C6 43 34 03", logmessageRows)
    scan_and_comment("BattleLog_AddActionLogMessage", "E8 ?? ?? ?? ?? F6 46 54 04", logmessageRows)
    scan_and_comment("ConfigBase_GetConfigOption", "E8 ?? ?? ?? ?? 8B 56 54", configOptions)
    scan_and_comment("ExdModule_GetSheetByIndex", "4C 8B 81 ?? ?? ?? ?? 4D 85 C0 74 07 8B C2", exl)
    scan_and_comment("ExdModule_GetRowCountBySheetIndex", "E8 ?? ?? ?? ?? 49 8D 7D 18", exl, True)
    scan_and_comment("ExdModule_GetRowBySheetIndexAndRowIndex", "E8 ?? ?? ?? ?? 48 85 C0 74 1D FF C3", exl, True)
    scan_and_comment("ExdModule_GetRowBySheetIndexAndRowId", "E8 ?? ?? ?? ?? 45 0F B6 F4", exl, True)
    scan_and_comment("ExdModule_GetRowBySheetIndexAndRowIdAndSubRowId", "E8 ?? ?? ?? ?? 48 85 C0 74 2C 48 8B 00", exl, True)
    scan_and_comment("QuestManager_IsQuestAccepted", "45 33 C0 48 8D 41 18", quests)
    scan_and_comment("QuestManager_IsQuestComplete1", "E8 ?? ?? ?? ?? 88 47 19", quests)
    scan_and_comment("AgentHUD_IsMainCommandEnabled", "48 8B 81 ?? ?? ?? ?? 44 8B C2 83 E2 1F", maincommands)
    scan_and_comment("AgentHUD_SetMainCommandEnabledState", "E8 ?? ?? ?? ?? 40 32 FF 45 32 C0", maincommands)
    scan_and_comment("RaptureAtkModule_OpenAddon", "E8 ?? ?? ?? ?? 8B 5F 2C", addonNames)
    scan_and_comment("InventoryManager_GetInventoryContainer", "E8 ?? ?? ?? ?? 88 58 18", inventoryTypes)
    scan_and_comment("SetCondition", "83 FA 68 7D 6D", conditions)

    update_conditions("48 8D 0D ?? ?? ?? ?? 8B D3 E8 ?? ?? ?? ?? 32 C0 48 83 C4 20", conditions)
    update_executecommand("E8 ?? ?? ?? ?? 8D 46 0A")

    print("Done!")

def read_csv(filename, indexColumn, textColumn):
    list = {}
    headerSkipped = False
    with codecs.open(filename, "r", encoding="utf-8", errors="replace") as csvfile:
        reader = csv.reader(csvfile, delimiter=',', quotechar='"')
        for row in reader:
            if not headerSkipped:
                headerSkipped = True
                continue
            list[row[indexColumn]] = row[textColumn]
    return list

def read_json(filename):
    list = {}
    with open(filename, 'r') as f:
        data = json.load(f)
        for key, value in data.items():
            list[key] = value
    return list

def read_enum(filename, name):
    with open(filename, 'r', encoding='utf-8') as file:
        lines = file.readlines()
        pattern = r'^\s*(\w+)\s*=\s*(\d+)'
        list = {}

        start = False
        for line in lines:
            if start == False and f"enum {name}" in line:
                start = True
                continue

            elif start == False:
                continue

            if "}" in line:
                break

            match = re.match(pattern, line)
            if match:
                name, id = match.groups()
                list[str(id)] = name

        return list

def get_addon_names():
    start_ea = idaapi.find_binary(text_segment.start_ea, text_segment.end_ea, "48 8D 3D ?? ?? ?? ?? 4C 8B DA", 16, idaapi.SEARCH_DOWN)
    if start_ea == idaapi.BADADDR:
        print("could not find addon names signature")
        return

    inst = idautils.DecodeInstruction(start_ea)
    if not inst:
        print(f"DecodeInstruction at 0x{start_ea:X} failed")
        return

    if inst.itype != ida_allins.NN_lea:
        print(f"Instruction at 0x{start_ea:X} not a lea")
        return

    if inst.ops[0].type != idc.o_reg:
        print(f"Operand 0 of instruction at 0x{start_ea:X} not a o_reg")
        return

    if inst.ops[1].type != idc.o_mem:
        print(f"Operand 1 of instruction at 0x{start_ea:X} not a o_mem")
        return

    start_ea = inst.ops[1].addr

    end_ea = idaapi.find_binary(text_segment.start_ea, text_segment.end_ea, "4C 8B CF 48 8D 1D ?? ?? ?? ??", 16, idaapi.SEARCH_DOWN)
    if end_ea == idaapi.BADADDR:
        print("could not find addon names signature")
        return

    end_ea += 3

    inst = idautils.DecodeInstruction(end_ea)
    if not inst:
        print(f"DecodeInstruction at 0x{end_ea:X} failed")
        return

    if inst.itype != ida_allins.NN_lea:
        print(f"Instruction at 0x{end_ea:X} not a lea")
        return

    if inst.ops[0].type != idc.o_reg:
        print(f"Operand 0 of instruction at 0x{end_ea:X} not a o_reg")
        return

    if inst.ops[1].type != idc.o_mem:
        print(f"Operand 1 of instruction at 0x{end_ea:X} not a o_mem")
        return

    end_ea = inst.ops[1].addr

    list = {}
    i = 0
    ea = start_ea
    while ida_bytes.get_qword(ea) != 0:
        name_ea = ida_bytes.get_qword(ea)
        size = ida_bytes.get_max_strlit_length(name_ea, ida_nalt.STRTYPE_C)
        name_bytes = ida_bytes.get_strlit_contents(name_ea, size, ida_nalt.STRTYPE_C)
        list[str(i)] = name_bytes.decode("UTF-8")
        ea += 8 * 3
        i += 1
        if ea >= end_ea:
            break

    print(f"Found {i} addon names")
    return list

def scan_and_comment(name, sig, list, renamefunc = False):
    fn_ea = idaapi.find_binary(text_segment.start_ea, text_segment.end_ea, sig, 16, idaapi.SEARCH_DOWN)
    if fn_ea == idaapi.BADADDR:
        print(f"signature failed for {name}")
        return

    inst = idautils.DecodeInstruction(fn_ea)
    if not inst:
        print(f"DecodeInstruction failed for {name}")
        return

    if inst.get_canon_mnem() == 'jmp' or inst.get_canon_mnem() == 'call':
        old_fn_ea = fn_ea
        fn_ea = idc.get_operand_value(fn_ea, 0)
        if debug:
            print(f"resolved call for {name} 0x{old_fn_ea:x} -> 0x{fn_ea:X}")

    if debug:
        print(f"{name} found at 0x{fn_ea:X}")

    for xref in idautils.XrefsTo(fn_ea):
        xref_ea = xref.frm

        if get_segm_name(xref_ea) != ".text":
            continue

        func = ida_funcs.get_func(xref_ea)
        if func is None:
            continue

        func_ea = func.start_ea

        id = None
        addr = xref_ea
        count = 0
        while count < 10: # TODO: this should only process instructions that are part of the call... but i don't know how
            count += 1
            addr = idc.prev_head(addr, func_ea)
            if addr == idaapi.BADADDR:
                break

            inst = idautils.DecodeInstruction(addr)
            if not inst:
                continue

            if inst.get_canon_mnem() == 'jz':
                break

            if inst.get_canon_mnem() == 'mov' and idc.get_operand_type(addr, 0) == idc.o_reg and idc.get_operand_type(addr, 1) == idc.o_imm:
                # TODO: resolve "mov     edx, ebp" where ebp holds the id
                reg_names = ["edx"]
                if name == "BattleLog_AddLogMessage" or name == "BattleLog_AddActionLogMessage":
                    reg_names = ["ecx"]
                if name == "QuestManager_IsQuestComplete1":
                    reg_names = ["edx", "ebx", "esi", "ebp"]
                if name == "QuestManager_IsQuestAccepted":
                    reg_names = ["ebx", "edi", "esi"]

                if idaapi.get_reg_name(idc.get_operand_value(addr, 0), 4) in reg_names:
                    id = idc.get_operand_value(addr, 1)
                    break

        if id is None:
            if debug:
                print(f"[{name}] id not found for xref {xref_ea:X}")
            continue

        id = str(id)

        if not id in list:
            if debug:
                print(f"[{name}] id {id} not found for xref {xref_ea:X}")
            continue

        # set comment to instruction
        idc.set_cmt(xref_ea, f"\"{list[id]}\"", 0)

        if renamefunc:
            existingName = ida_funcs.get_func_name(func_ea)

            if existingName.startswith("sub_"):
                size = ida_funcs.calc_func_size(func)

                if name == "ExdModule_GetRowBySheetIndexAndRowId" and size >= 49 and size <= 53:
                    idaapi.set_name(func_ea, f"Component::Exd::ExdModule_Get{list[id]}ById", 0)

                elif  name == "ExdModule_GetRowBySheetIndexAndRowIndex" and size >= 49 and size <= 53:
                    idaapi.set_name(func_ea, f"Component::Exd::ExdModule_Get{list[id]}ByIndex", 0)

                elif name == "ExdModule_GetRowCountBySheetIndex" and size == 24:
                    idaapi.set_name(func_ea, f"Component::Exd::ExdModule_Get{list[id]}::rowCount", 0)

                elif debug:
                    print(f"[{name}] {func_ea:X} with size {size} not touched")

def update_conditions(sig, list):
    ea = idaapi.find_binary(text_segment.start_ea, text_segment.end_ea, sig, 16, idaapi.SEARCH_DOWN)
    if ea == idaapi.BADADDR:
        print(f"signature failed for Conditions")
        return

    inst = idautils.DecodeInstruction(ea)
    if not inst:
        print(f"DecodeInstruction failed for Conditions")
        return

    if inst.get_canon_mnem() == 'lea':
        old_ea = ea
        ea = idc.get_operand_value(ea, 1)
        if debug:
            print(f"resolved lea for Conditions 0x{old_ea:x} -> 0x{ea:X}")

    if debug:
        print(f"Conditions found at 0x{ea:X}")

    for idstr in list:
        name = list[idstr]
        id = int(idstr)
        if id > 0:
            ida_bytes.create_byte(ea + id, 1)
            idaapi.set_name(ea + id, f"g_Conditions_{name}", 0)

def update_executecommand(sig):
    fn_ea = idaapi.find_binary(text_segment.start_ea, text_segment.end_ea, sig, 16, idaapi.SEARCH_DOWN)
    if fn_ea == idaapi.BADADDR:
        print(f"signature failed for ExecuteCommand")
        return

    inst = idautils.DecodeInstruction(fn_ea)
    if not inst:
        print(f"DecodeInstruction failed for ExecuteCommand")
        return

    if inst.get_canon_mnem() == 'jmp' or inst.get_canon_mnem() == 'call':
        old_fn_ea = fn_ea
        fn_ea = idc.get_operand_value(fn_ea, 0)
        if debug:
            print(f"resolved call for ExecuteCommand 0x{old_fn_ea:x} -> 0x{fn_ea:X}")

    if debug:
        print(f"ExecuteCommand found at 0x{fn_ea:X}")

    for xref in idautils.XrefsTo(fn_ea):
        xref_ea = xref.frm

        if get_segm_name(xref_ea) != ".text":
            continue

        func = ida_funcs.get_func(xref_ea)
        if func is None:
            continue

        func_ea = func.start_ea

        id = None
        addr = xref_ea
        count = 0
        while count < 5:
            count += 1
            addr = idc.prev_head(addr, func_ea)
            if addr == idaapi.BADADDR:
                break

            inst = idautils.DecodeInstruction(addr)
            if not inst:
                continue

            if inst.get_canon_mnem() == 'jz':
                break

            if inst.get_canon_mnem() == 'mov' and idc.get_operand_type(addr, 0) == idc.o_reg and idc.get_operand_type(addr, 1) == idc.o_imm:
                reg_names = ["ecx"]

                if idaapi.get_reg_name(idc.get_operand_value(addr, 0), 4) in reg_names:
                    id = idc.get_operand_value(addr, 1)
                    break

        if id is None:
            if debug:
                print(f"[ExecuteCommand] id not found for xref {xref_ea:X}")
            continue

        # set comment to instruction
        idc.set_cmt(xref_ea, f"{id}", 0)

if __name__ == "__main__":
    main()
