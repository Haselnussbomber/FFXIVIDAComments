import os
import json
import ida_allins
import ida_bytes
import ida_enum
import ida_hexrays
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc
from dataclasses import dataclass
from typing import Optional

# ---- CONFIG ----

debug = False
dataPath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "out")
language = "en"

# ---- /CONFIG ----

text_segment = ida_segment.get_segm_by_name('.text')

def main() -> None:
    addonRows = read_json(os.path.join(dataPath, language, "Addon.json"))
    lobbyRows = read_json(os.path.join(dataPath, language, "Lobby.json"))
    logmessageRows = read_json(os.path.join(dataPath, language, "LogMessage.json"))
    quests = read_json(os.path.join(dataPath, language, "Quest.json"))
    maincommands = read_json(os.path.join(dataPath, language, "MainCommand.json"))
    conditions = read_json(os.path.join(dataPath, "Conditions.json"))
    items = read_json(os.path.join(dataPath, language, "Item.json"))

    addonNames = get_addon_names()

    sheetNames = get_enum_member_names("Component::Exd::SheetsEnum")
    configOptions = get_enum_member_names("Client::UI::Misc::ConfigOption")
    inventoryTypes = get_enum_member_names("Client::Game::InventoryType")
    agents = get_enum_member_names("Client::UI::Agent::AgentId")

    commenters = [
        FunctionCommenter("Client::UI::Agent::AgentInterface.GetAddonTextById", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.GetAddonText", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText1<string>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText1<string,int>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText1<string,int,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText1<string,string>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText1<string,string,string>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText1<int>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText1<int,int>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText1<int,int,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText1<int,int,uint,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText1<int,string>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<string>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<string,int>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<string,int,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<string,int,uint,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<string,int,uint,uint,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<string,int,uint,uint,uint,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<string,int,uint,uint,uint,uint,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<string,string>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<string,string,string>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<string,string,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<string,string,uint,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<string,string,uint,uint,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<string,string,string,uint,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<int>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<int,int>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<int,int,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<int,int,uint,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<int,int,uint,uint,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<int,int,uint,uint,uint,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<int,int,uint,uint,uint,uint,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<int,string>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<int,int,string>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonText2<int,string,uint>", addonRows),
        FunctionCommenter("Client::UI::Misc::RaptureTextModule.FormatAddonTextApply", addonRows),

        FunctionCommenter("Client::UI::Agent::AgentLobby.GetLobbyText", lobbyRows),

        FunctionCommenter("Client::UI::Shell::RaptureShellModule.PrintLogMessage", logmessageRows),
        FunctionCommenter("Client::UI::Misc::RaptureLogModule.ShowLogMessage", logmessageRows),
        FunctionCommenter("Client::UI::Misc::RaptureLogModule.ShowLogMessage<uint>", logmessageRows),
        FunctionCommenter("Client::UI::Misc::RaptureLogModule.ShowLogMessage<uint,uint>", logmessageRows),
        FunctionCommenter("Client::UI::Misc::RaptureLogModule.ShowLogMessage<uint,uint,uint>", logmessageRows),
        FunctionCommenter("Client::UI::Misc::RaptureLogModule.ShowLogMessage<string>", logmessageRows),
        FunctionCommenter("Client::Game::BattleLog.SomeFormatLogMessage", logmessageRows, pattern="E8 ?? ?? ?? ?? C6 43 34 03"),

        FunctionCommenter("Common::Configuration::ConfigBase.GetConfigOption", configOptions, quotes=False),

        FunctionCommenter("Component::Exd::ExdModule.GetSheetByIndex", sheetNames, quotes=False),
        FunctionCommenter("Component::Exd::ExdModule.GetRowBySheetIndexAndRowIndex", sheetNames, quotes=False),
        FunctionCommenter("Component::Exd::ExdModule.GetRowCountBySheetIndex", sheetNames, quotes=False),
        FunctionCommenter("Component::Exd::ExdModule.GetRowBySheetIndexAndRowId", sheetNames, quotes=False),
        FunctionCommenter("Component::Exd::ExdModule.GetRowBySheetIndexAndRowIdAndSubRowId", sheetNames, quotes=False),

        FunctionCommenter("Client::Game::UI::Journal.IsQuestAccepted", quests),
        FunctionCommenter("Client::Game::QuestManager.IsQuestAccepted", quests),
        FunctionCommenter("Client::Game::QuestManager.IsQuestComplete", quests),
        FunctionCommenter("Client::Game::QuestManager.IsQuestComplete1", quests),
        FunctionCommenter("Client::Game::UI::UIState.IsUnlockLinkUnlockedOrQuestCompleted", quests),

        FunctionCommenter("Client::UI::UIModule.ExecuteMainCommand", maincommands),
        FunctionCommenter("Client::UI::UIModule.IsMainCommandUnlocked", maincommands),
        FunctionCommenter("Client::UI::Agent::AgentHUD.IsMainCommandEnabled", maincommands),
        FunctionCommenter("Client::UI::Agent::AgentHUD.SetMainCommandEnabledState", maincommands),
        FunctionCommenter("Client::UI::Agent::AgentHUD.GetMainCommandString", maincommands),

        FunctionCommenter("Client::UI::RaptureAtkModule.GetStaticAddonName", addonNames),
        FunctionCommenter("Client::UI::RaptureAtkModule.OpenAddon", addonNames),

        FunctionCommenter("Client::Game::InventoryManager.GetInventoryContainer", inventoryTypes, quotes=False),

        FunctionCommenter("SetCondition", conditions, quotes=False),

        FunctionCommenter("Client::UI::Agent::AgentInterface.GetAgentByInternalId", agents, quotes=False),
        FunctionCommenter("Client::UI::Agent::AgentModule.GetAgentByInternalId", agents, quotes=False),
        FunctionCommenter("Client::UI::Agent::AgentModule.GetAgentByInternalId_2", agents, quotes=False),
        FunctionCommenter("Client::UI::Agent::AgentModule.HideAgent", agents, quotes=False),
        FunctionCommenter("Client::UI::Agent::AgentModule.HideAgentIfActive", agents, quotes=False),
        FunctionCommenter("Client::UI::Agent::AgentModule.IsAgentActive", agents, quotes=False),

        FunctionCommenter("GetItemName", items, id_param_index=0),
        FunctionCommenter("GetItemIcon", items, id_param_index=0),
        FunctionCommenter("Component::Exd::ExdModule.GetItemRowById", items, id_param_index=0),
        FunctionCommenter("Client::Game::CurrencyManager.GetItemCount", items),
        FunctionCommenter("Client::Game::CurrencyManager.GetItemMaxCount", items),

        FunctionCommenter("ExecuteCommand", {}, id_param_index=0),
    ]

    for commenter in commenters:
        commenter.run()

    update_conditions("48 8D 0D ?? ?? ?? ?? 8B D3 E8 ?? ?? ?? ?? 32 C0 48 83 C4 20", conditions)

    print("Done!")

def read_json(filename):
    list = {}
    with open(filename, 'r') as f:
        data = json.load(f)
        for key, value in data.items():
            list[key] = value
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

def get_enum_member_names(enum_name: str) -> dict:
    def remove_until_first_dot(s):
        return s.split('.', 1)[1] if '.' in s else s

    values = {}

    for enum_idx in range(ida_enum.get_enum_qty()):
        enum = ida_enum.getn_enum(enum_idx)
        if enum_name != ida_enum.get_enum_name(enum):
            continue

        cur_member_value = ida_enum.get_first_enum_member(enum, 0xffffffff)
        last_member_value = ida_enum.get_last_enum_member(enum, 0xffffffff)
        while True:
            cur_member_id = ida_enum.get_enum_member(enum, cur_member_value, -1, 0xffffffff)
            member_value = ida_enum.get_enum_member_value(cur_member_id)

            values[str(member_value)] = remove_until_first_dot(ida_enum.get_enum_member_name(cur_member_id))

            if cur_member_value == last_member_value:
                break

            cur_member_value = ida_enum.get_next_enum_member(enum, cur_member_value, 0xffffffff)

    return values

class CallArgFinder(ida_hexrays.ctree_visitor_t):
    ea: int

    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.calls = []

    def get_arg_value(self, arg):
        """Extracts the value of an argument based on its expression type."""
        if arg.op == ida_hexrays.cot_num: # Constant number, we don't need more than that
            return str(arg.n._value)
        return ""

    def visit_expr(self, expr):
        if expr.op == ida_hexrays.cot_call and expr.ea == self.ea: # Check if it's a function call
            call_info = {
                "ea": expr.ea,
                "callee": str(expr.x), # Get function name or expression
                "args": []
            }

            for arg in expr.a:
                call_info["args"].append(self.get_arg_value(arg))

            self.calls.append(call_info)
        return 0

@dataclass
class FunctionCommenter:
    name: str
    datalist: any
    id_param_index: Optional[int] = 1
    pattern: Optional[str] = False
    renamefunc: Optional[bool] = False
    quotes: Optional[bool] = True

    ea: int = 0

    def __post_init__(self):
        if self.pattern:
            self.ea = idaapi.find_binary(text_segment.start_ea, text_segment.end_ea, self.pattern, 16, idaapi.SEARCH_DOWN)
        else:
            self.ea = idc.get_name_ea(text_segment.start_ea, self.name)

    def get_comment(self, id: int):
        if id in self.datalist:
            if self.quotes:
                return f"\"{self.datalist[id]}\" ({id})"
            else:
                return f"{self.datalist[id]} ({id})"

        return str(id)

    def run(self):
        if self.ea == idaapi.BADADDR:
            print(f"Could not find ea for {self.name}")
            return

        if self.pattern:
            print(f"Processing {self.name} ({self.pattern})")
        else:
            print(f"Processing {self.name}")

        for xref in idautils.XrefsTo(self.ea):
            if idc.get_segm_name(xref.frm) != ".text":
                continue

            cfunc = ida_hexrays.decompile(xref.frm)
            if not cfunc:
                print(f"Failed to decompile {hex(xref.frm)}")
                continue

            visitor = CallArgFinder()
            visitor.ea = xref.frm
            visitor.apply_to(cfunc.body, None)

            for call in visitor.calls:
                if call['ea'] == idaapi.BADADDR:
                    continue

                if debug:
                    print(f"Processing function call @ {hex(call['ea'])} ({self.name})")

                id = 0
                for i, arg in enumerate(call["args"]):
                    if i == self.id_param_index:
                        id = arg
                        break

                if id != 0:
                    idc.set_cmt(call['ea'], self.get_comment(id), 0)

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

if __name__ == "__main__":
    main()
