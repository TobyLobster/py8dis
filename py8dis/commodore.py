"""
Commodore specific functions: commodore.c64(), vic20(), c128(), plus4() and
pet() name and comment a program's use of the Kernal, the hardware and the OS
workspace, as acorn.bbc() does for the BBC Micro.

    import commodore
    start = load_prg("game.prg", "6510")
    commodore.c64()

They name the memory locations with descriptive names by default (e.g.
'vic_border_colour'); names="commodore" uses the names in Commodore's
documentation instead (e.g. 'extcol'). See commodoretables.py.
"""

from commands import *
import classification
import collections
import config
import mainformatter
import session
import textencoding
import utils
from memorymanager import BinaryAddr, RuntimeAddr
from snippets6502 import register_snippet
from snippethelper import vector_pattern, vector_handler, vector_handler_name, comment_vector, half_set_vector_text

from commodoretables import *
import commodoresource

# Helpers shared with acorn.py's OS call hooks
from acornhelpers import xy_addr, enum_lookup

NAMES = ("descriptive", "commodore")


# ************************************************************************************************
# The machines

class Machine:
    """What commodore.py knows about one machine: its memory locations,
    hardware, ROMs and so on (from commodoretables.py)."""

    def __init__(self, name, *, locations, hardware_locations, rom_locations, rom_routines,
                 rom_label_tables, jump_table, inline_string_calls, vectors, colours, colour_registers,
                 control_codes, io_ranges, basic_start, cartridge, basic_rom_addr, regions,
                 basic_tokens=None, call_hooks=None):
        self.name = name
        self.basic_tokens = basic_tokens or basic_v2_tokens   # BASIC's keywords, by token from $80
        self.call_hooks = call_hooks                # {jump table name: hook}, if not the C64's (see _hooks)
        self.locations = locations                  # RAM, the vectors and the 6502's vectors
        self.hardware_locations = hardware_locations
        self.rom_locations = rom_locations          # data in the ROMs (named with rom_labels)
        self.rom_routines = rom_routines
        self.rom_label_tables = rom_label_tables    # [({address: name}, suffix for a clash)], from Commodore's source
        self.jump_table = jump_table
        self.inline_string_calls = inline_string_calls  # calls followed by a string to print (PRIMM)
        self.vectors = vectors                      # VectorLocations, for code that sets them
        self.colours = colours
        self.colour_registers = colour_registers
        self.control_codes = control_codes
        self.io_ranges = io_ranges                  # [(start, end)]: never defined inline
        self.basic_start = basic_start              # where BASIC programs are loaded
        self.cartridge = cartridge                  # (address, style): see is_cartridge(); None if there's no standard header
        self.basic_rom_addr = basic_rom_addr        # (None if basic_rom() isn't supported)
        self.regions = regions                      # [(start, end, name)]

def _kernal_vectors():
    """The Kernal's RAM vectors (&0314-&0333), as Locations"""
    return [Location(v.addr, 2, v.commodore_name, v.name) for v in c64_vectors if v.name is not None and v.addr >= 0x0314]

def c64_machine():
    return Machine("c64",
        locations=c64_ram_locations + _kernal_vectors() + c64_more_ram_locations + c64_cpu_vectors,
        hardware_locations=c64_hardware_locations,
        rom_locations=c64_rom_locations,
        rom_routines=c64_rom_routines,
        rom_label_tables=[(commodoresource.c64_kernal_rom_labels, "_rom"), (commodoresource.c64_basic_rom_labels, "_basic")],
        jump_table=kernal_jump_table,
        inline_string_calls=[],
        vectors=c64_vectors,
        colours=colours,
        colour_registers=c64_colour_registers,
        control_codes=control_codes,
        io_ranges=[(0xd000, 0xe000)],
        basic_start=0x0801,
        cartridge=(0x8000, "CBM80"),
        basic_rom_addr=0xa000,
        regions=[
            (0x0000, 0x0002, "6510 I/O port"),
            (0x0200, 0x0300, "OS workspace"),
            (0x0300, 0x0334, "Vectors"),
            (0x0334, 0x0400, "Tape buffer"),
            (0x0400, 0x0800, "Screen memory"),
            (0x0800, 0xa000, "BASIC program area"),
            (0xa000, 0xc000, "BASIC ROM"),
            (0xc000, 0xd000, "Upper RAM"),
            (0xd000, 0xd400, "VIC-II"),
            (0xd400, 0xd800, "SID"),
            (0xd800, 0xdc00, "Colour RAM"),
            (0xdc00, 0xdd00, "CIA 1"),
            (0xdd00, 0xde00, "CIA 2"),
            (0xde00, 0xdf00, "I/O 1"),
            (0xdf00, 0xe000, "I/O 2"),
            (0xe000, 0xff81, "Kernal ROM"),
            # The 6502's NMI, reset and IRQ vectors follow (a region named by
            # the CPU)
            (0xff81, 0xfffa, "Kernal entry points"),
        ])

VIC20_EXPANSIONS = ("none", "3k", "8k")

def vic20_machine(expansion="none"):
    """The VIC-20, with no RAM expansion, 3K (in block 0, &0400-&0fff), or 8K
    or more (from block 1, &2000)"""
    expanded_8k = (expansion == "8k")
    basic_start = {"none": 0x1001, "3k": 0x0401, "8k": 0x1201}[expansion]
    screen = 0x1000 if expanded_8k else 0x1e00
    colour_ram = 0x9400 if expanded_8k else 0x9600
    if expansion == "8k":
        ram_regions = [(0x0400, 0x1000, "3K expansion RAM"), (0x1000, 0x1200, "Screen memory"), (0x1200, 0x8000, "BASIC program area")]
    elif expansion == "3k":
        ram_regions = [(0x0400, 0x1e00, "BASIC program area"), (0x1e00, 0x2000, "Screen memory"), (0x2000, 0x8000, "Expansion RAM")]
    else:
        ram_regions = [(0x0400, 0x1000, "3K expansion RAM"), (0x1000, 0x1e00, "BASIC program area"), (0x1e00, 0x2000, "Screen memory"), (0x2000, 0x8000, "Expansion RAM")]
    return Machine("vic20",
        locations=vic20_ram_locations + _kernal_vectors() + c64_more_ram_locations[:1] + vic20_screen_locations(expanded_8k) + c64_cpu_vectors,
        hardware_locations=vic20_hardware_locations,
        rom_locations=vic20_rom_locations,
        rom_routines=vic20_rom_routines,
        rom_label_tables=[(commodoresource.vic20_kernal_rom_labels, "_rom"), (commodoresource.vic20_basic_rom_labels, "_basic")],
        # (The VIC-20 doesn't have the first three entries)
        jump_table=[call for call in kernal_jump_table if call.addr >= 0xff8a],
        inline_string_calls=[],
        vectors=c64_vectors,
        colours=vic20_colours,
        colour_registers=vic20_colour_registers,
        control_codes=vic20_control_codes,
        io_ranges=[(0x9000, 0x9800 if colour_ram == 0x9600 else 0x9600)],
        basic_start=basic_start,
        cartridge=(0xa000, "A0CBM"),
        basic_rom_addr=0xc000,
        regions=[
            (0x0200, 0x0300, "OS workspace"),
            (0x0300, 0x0334, "Vectors"),
            (0x0334, 0x0400, "Tape buffer"),
        ] + ram_regions + [
            (0x8000, 0x9000, "Character ROM"),
            (0x9000, 0x9010, "VIC"),
            (0x9110, 0x9120, "VIA 1"),
            (0x9120, 0x9130, "VIA 2"),
            (colour_ram, colour_ram + 0x200, "Colour RAM"),
            (0x9800, 0x9c00, "I/O 2"),
            (0x9c00, 0xa000, "I/O 3"),
            (0xa000, 0xc000, "Cartridge ROM"),
            (0xc000, 0xe000, "BASIC ROM"),
            (0xe000, 0xff8a, "Kernal ROM"),
            (0xff8a, 0xfffa, "Kernal entry points"),
        ])

def c128_machine():
    """The C128 in C128 mode (in C64 mode, it's a C64), as it is with the
    usual bank 15: the ROMs, and the I/O at &d000"""
    jump_table = sorted(c128_jump_table_additions + kernal_jump_table, key=lambda call: call.addr)
    return Machine("c128",
        locations=c128_workspace_locations + c64_cpu_vectors,
        hardware_locations=c128_hardware_locations,
        rom_locations=[],
        rom_routines=c128_rom_routines,
        rom_label_tables=[(commodoresource.c128_kernal_rom_labels, "_rom"), (commodoresource.c128_editor_rom_labels, "_editor"),
                          (commodoresource.c128_monitor_rom_labels, "_monitor"), (commodoresource.c128_basic_rom_labels, "_basic")],
        jump_table=jump_table,
        inline_string_calls=[0xff7d],
        vectors=c128_vectors,
        colours=colours,
        colour_registers=c128_colour_registers,
        control_codes=control_codes,
        io_ranges=[(0xd000, 0xe000), (0xff00, 0xff05)],
        basic_start=0x1c01,
        cartridge=(0x8000, "CBM"),
        basic_rom_addr=0x4000,
        regions=[
            (0x0200, 0x0400, "OS workspace"),
            (0x0400, 0x0800, "Screen memory"),
            (0x0800, 0x0a00, "BASIC stack"),
            (0x0a00, 0x0b00, "OS workspace"),
            (0x0b00, 0x0c00, "Tape buffer"),
            (0x0c00, 0x0e00, "RS-232 buffers"),
            (0x0e00, 0x1000, "Sprite definitions"),
            (0x1000, 0x1100, "Function keys"),
            (0x1100, 0x1c00, "BASIC workspace"),
            (0x1c00, 0x4000, "BASIC program area"),
            (0x4000, 0xb000, "BASIC ROM"),
            (0xb000, 0xc000, "Monitor ROM"),
            (0xc000, 0xd000, "Screen editor ROM"),
            (0xd000, 0xd400, "VIC-II"),
            (0xd400, 0xd500, "SID"),
            (0xd500, 0xd600, "MMU"),
            (0xd600, 0xd700, "VDC"),
            (0xd800, 0xdc00, "Colour RAM"),
            (0xdc00, 0xdd00, "CIA 1"),
            (0xdd00, 0xde00, "CIA 2"),
            (0xde00, 0xdf00, "I/O 1"),
            (0xdf00, 0xe000, "I/O 2"),
            (0xe000, 0xff00, "Kernal ROM"),
            (0xff00, 0xff05, "MMU"),
            (0xff05, 0xff47, "Kernal ROM"),
            (0xff47, 0xfffa, "Kernal entry points"),
        ])

def plus4_machine():
    """The Plus/4 (or C16, or C116)"""
    jump_table = sorted(plus4_jump_table_additions + kernal_jump_table, key=lambda call: call.addr)
    return Machine("plus4",
        locations=plus4_workspace_locations + plus4_screen_locations + c64_cpu_vectors,
        hardware_locations=plus4_hardware_locations,
        rom_locations=[],
        rom_routines=plus4_rom_routines,
        rom_label_tables=[(commodoresource.plus4_kernal_rom_labels, "_rom"), (commodoresource.plus4_basic_rom_labels, "_basic")],
        jump_table=jump_table,
        inline_string_calls=[0xff4f],
        vectors=plus4_vectors,
        # (The TED's colours include their luminance, so they're not named)
        colours={},
        colour_registers=[],
        control_codes=control_codes,
        io_ranges=[(0xfd00, 0xff40)],
        basic_start=0x1001,
        cartridge=(0x8000, "CBM"),
        basic_rom_addr=0x8000,
        regions=[
            (0x0200, 0x0300, "OS workspace"),
            (0x0300, 0x0333, "Vectors"),
            (0x0333, 0x03f3, "Tape buffer"),
            (0x03f3, 0x0800, "OS workspace"),
            (0x0800, 0x0c00, "Colour RAM"),
            (0x0c00, 0x1000, "Screen memory"),
            (0x1000, 0x8000, "BASIC program area"),
            (0x8000, 0xc000, "BASIC ROM"),
            (0xc000, 0xfd00, "Kernal ROM"),
            (0xfd00, 0xff00, "I/O"),
            (0xff00, 0xff40, "TED"),
            (0xff40, 0xfffa, "Kernal entry points"),
        ])

PET_BASIC_VERSIONS = (1, 2, 4)
PET_COLUMNS = (40, 80)

def pet_machine(basic=4, columns=40):
    """The PET (or CBM 3000, 4000 or 8000), with BASIC 1, 2 or 4, and a 40 or
    80 column screen (80 columns only with BASIC 4)"""
    workspace = pet_workspace_locations[(basic, columns)]
    if basic == 1:
        os_regions = [(0x0200, 0x027a, "OS workspace"), (0x027a, 0x033a, "Tape buffer 1"), (0x033a, 0x03fa, "Tape buffer 2")]
    elif basic == 2:
        os_regions = [(0x0200, 0x027a, "OS workspace"), (0x027a, 0x033a, "Tape buffer 1"), (0x033a, 0x03fa, "Tape buffer 2"),
                      (0x03fa, 0x0400, "OS workspace")]
    else:
        os_regions = [(0x0200, 0x027a, "OS workspace"), (0x027a, 0x033a, "Tape buffer 1"), (0x033a, 0x0353, "DOS workspace"),
                      (0x0353, 0x03fa, "Tape buffer 2"), (0x03fa, 0x0400, "OS workspace")]
    basic_rom_start = 0xb000 if basic == 4 else 0xc000
    screen_end = 0x8000 + (40 if columns == 40 else 80) * 25
    return Machine("pet",
        locations=workspace + pet_screen_locations(columns) + c64_cpu_vectors,
        hardware_locations=pet_hardware_locations + (pet_crtc_locations if columns == 80 else []),
        rom_locations=[],
        rom_routines=pet_rom_routines(basic),
        rom_label_tables=[(getattr(commodoresource, "pet%d_kernal_rom_labels" % basic), "_rom"),
                          (getattr(commodoresource, "pet%d_basic_rom_labels" % basic), "_basic")],
        jump_table=pet_jump_table,
        inline_string_calls=[],
        vectors=pet_vectors(workspace),
        colours={},
        colour_registers=[],
        control_codes=pet_80_column_control_codes if columns == 80 else pet_control_codes,
        io_ranges=[(0xe800, 0xe900)],
        basic_start=0x0401,
        cartridge=None,
        basic_rom_addr=None,
        basic_tokens={1: basic_v1_tokens, 2: basic_v2_tokens, 4: basic_v4_tokens}[basic],
        # (Its LOAD and SAVE aren't the C64's, so only CHROUT has a hook of
        # its own)
        call_hooks={"chrout": chrout_hook},
        regions=os_regions + [
            (0x0400, 0x8000, "BASIC program area"),
            (0x8000, screen_end, "Screen memory"),
            (0x9000, basic_rom_start, "Expansion ROM"),
            (basic_rom_start, 0xe000, "BASIC ROM"),
            (0xe000, 0xe800, "Screen editor ROM"),
            (0xe810, 0xe814, "PIA 1"),
            (0xe820, 0xe824, "PIA 2"),
            (0xe840, 0xe850, "VIA"),
        ] + ([(0xe880, 0xe882, "CRTC")] if columns == 80 else []) + [
            (0xf000, 0xffc0, "Kernal ROM"),
            (0xffc0, 0xfffa, "Kernal entry points"),
        ])

def _machine():
    """The machine chosen for this session (by c64(), vic20(), c128(),
    plus4() or pet()), or the C64 if none has been"""
    return session.current().extras.get("commodore.machine") or c64_machine()


# ************************************************************************************************
# The names

def _name(location, names):
    """A Location's name in the given style"""
    if names == "commodore" and location.commodore_name is not None:
        return location.commodore_name
    return location.name

# The mnemonics of the 65C02 and the 6502's undocumented opcodes (in each
# assembler's spelling), which assemblers take as instructions, so they can't
# be labels
_OTHER_MNEMONICS = set("""
    bra phx phy plx ply stp stz trb tsb wai
    ahx alr anc ane arr asr axs dcm dcp hlt ins isb isc jam kil lae las lax
    lxa rla rra sax sbx sha shs shx shy slo sre sxa sya tas xaa""".split()) | {
    "%s%d" % (op, bit) for op in ("bbr", "bbs", "rmb", "smb") for bit in range(8)}

def location_names(machine, names="descriptive", rom_labels=True):
    """The names c64() etc. give memory locations, as a list of
    (address, name, base address or None): one for each byte of each
    location (e.g. 'tape_buffer+1', with the base address of 'tape_buffer'),
    the ROM routines, and (with rom_labels) the labels in Commodore's source
    for the Kernal and BASIC ROMs. Not the Kernal's jump table, which are
    subroutines.

    A label in Commodore's source with the same name as a Kernal call or
    another location gets '_rom' added (e.g. PLOT, the routine at &e50a that
    the jump table's plot at &fff0 jumps to on the C64, is 'plot_rom'), and a
    label in BASIC's source with the same name as one of those gets '_basic'
    added (e.g. 'stop_basic'), and similarly for the C128's screen editor
    ('_editor') and monitor ('_monitor'). So does a label that's another
    65xx CPU's mnemonic, which an assembler would take as an instruction (e.g.
    the C128's and Plus/4's BASIC have STP and STZ, 'stp_basic' and
    'stz_basic'). A location with the same name as a Kernal call gets '_ram'
    added (e.g. the C128's 'jsrfar' routine in RAM is 'jsrfar_ram', with
    names="commodore")."""
    result = []
    jump_table_names = {call.name for call in machine.jump_table}
    def add(location):
        name = _name(location, names)
        if name in jump_table_names:
            name += "_ram"
        if "+" in name:
            # (An offset from another location's name, e.g. 'vicreg+1')
            result.append((location.addr, name, location.addr - int(name.split("+")[1])))
            return
        result.append((location.addr, name, None))
        for i in range(1, location.size):
            result.append((location.addr + i, "%s+%d" % (name, i), location.addr))

    for location in machine.locations + machine.hardware_locations:
        add(location)

    if rom_labels:
        for location in machine.rom_locations:
            add(location)
        named = {addr for addr, _, _ in result} | {call.addr for call in machine.jump_table}
        for routine in machine.rom_routines:
            name = routine.name
            if names == "commodore" and routine.commodore_name is not None:
                name = routine.commodore_name
            result.append((routine.addr, name, None))
            named.add(routine.addr)

        used = {name for _, name, _ in result} | {call.name for call in machine.jump_table}
        for rom_labels_table, suffix in machine.rom_label_tables:
            for addr in sorted(rom_labels_table):
                if addr in named:
                    continue
                name = rom_labels_table[addr]
                if name in used or name in _OTHER_MNEMONICS:
                    name += suffix
                assert name not in used, name
                used.add(name)
                result.append((addr, name, None))
    return result

def c64_location_names(names="descriptive", rom_labels=True):
    """The names c64() gives memory locations (see location_names())"""
    return location_names(c64_machine(), names, rom_labels)


# ************************************************************************************************
# Comments on Kernal calls

def _known_value(state, reg):
    """The value of the register before the call, if it's set by an
    immediate load on every path (else None)"""
    binary_addr = state.pessimistic[reg].get_previous_load_imm_operand()
    if binary_addr is None:
        return None
    return memory_binary[binary_addr]

def _hex2(n):
    return config.get_assembler().hex2(n)

def _hex4(n):
    return config.get_assembler().hex4(n)

def _comment_registers(runtime_addr, state, subroutine, entry=True, exit=True):
    """Comment where the registers are set before the call, and used after
    it, from the subroutine's on_entry and on_exit (as the 6502's default
    subroutine hook does)."""
    if subroutine.runtime_addr == runtime_addr:
        return
    if entry and subroutine.on_entry:
        for reg in ('a', 'x', 'y'):
            reg_addr = state.optimistic[reg].previous_adjust
            text = subroutine.on_entry.get(reg)
            if reg_addr is not None and text:
                disassembly.comment_binary(reg_addr, reg.upper() + "=" + text, align=Align.INLINE, word_wrap=False, auto_generated=True)
    if exit and subroutine.on_exit:
        for reg in ('a', 'x', 'y'):
            text = subroutine.on_exit.get(reg)
            next_use = state.next_use[reg]
            if next_use is not None and text:
                disassembly.comment(movemanager.b2r(next_use), reg.upper() + "=" + text, align=Align.INLINE, auto_generated=True)

def _comment_call(runtime_addr, subroutine, text):
    if subroutine.runtime_addr != runtime_addr:
        disassembly.comment(runtime_addr, text, align=Align.INLINE, word_wrap=False, auto_generated=True)

def _char_description(c):
    """A description of a PETSCII character, e.g. "'a'" or "$93 (clear
    screen)" """
    char = textencoding.PETSCII.char(c)
    if char is not None:
        return "'%s'" % char
    control_codes = _machine().control_codes
    if c in control_codes:
        return "%s (%s)" % (_hex2(c), control_codes[c])
    return _hex2(c)

def default_hook(runtime_addr, state, subroutine):
    _comment_registers(runtime_addr, state, subroutine)
    if subroutine.title:
        _comment_call(runtime_addr, subroutine, subroutine.title)

def chrout_hook(runtime_addr, state, subroutine):
    _comment_registers(runtime_addr, state, subroutine)
    a = _known_value(state, 'a')
    if a is None:
        _comment_call(runtime_addr, subroutine, subroutine.title)
    else:
        _comment_call(runtime_addr, subroutine, "Output " + _char_description(a))
        # A character is written as one where it's loaded (e.g. "lda #'a'",
        # if the assembler can: see Assembler.encoded_char_literal())
        operand_addr = state.pessimistic['a'].get_previous_load_imm_operand()
        format_hint = session.current().disassembly.format_hint
        if (textencoding.current().char(a) is not None and operand_addr not in format_hint
                and operand_addr not in session.current().classifications.expressions):
            format_hint[operand_addr] = mainformatter.char_formatter

def setlfs_hook(runtime_addr, state, subroutine):
    _comment_registers(runtime_addr, state, subroutine)
    # Name the device number where X is set
    enum_lookup(state.optimistic['x'].get_previous_load_imm_operand(), device_numbers)

    a, x, y = (_known_value(state, reg) for reg in "axy")
    if a is None or x is None or y is None:
        _comment_call(runtime_addr, subroutine, subroutine.title)
        return
    device = device_descriptions.get(x, "device %d" % x)
    if x in device_descriptions:
        device = "device %d (%s)" % (x, device)
    secondary = "no secondary address" if y == 255 else "secondary address %d" % y
    _comment_call(runtime_addr, subroutine, "Set logical file %d to %s, %s" % (a, device, secondary))

def _name_data(runtime_addr, name):
    """Label the address, if it has no name yet, with the name (or name_2
    etc. if that's taken)"""
    labels = session.current().labels.labels
    if runtime_addr in labels and labels[runtime_addr].explicit_names:
        return
    counts = session.current().extras.setdefault("commodore.data_names", {})
    count = counts.get(name, 0) + 1
    counts[name] = count
    label(runtime_addr, name if count == 1 else "%s_%d" % (name, count))

def _loaded_and_unclassified(runtime_addr, length):
    """Whether there's data loaded for the length bytes at the runtime
    address, none of it classified yet"""
    for i in range(length):
        addr = runtime_addr + i
        if addr > 0xffff:
            return False
        binary_addr, _ = movemanager.r2b(RuntimeAddr(addr))
        if binary_addr is None or not memorymanager.is_data_loaded_at_binary_addr(binary_addr):
            return False
        if classification.is_classified(binary_addr):
            return False
    return True

def setnam_hook(runtime_addr, state, subroutine):
    _comment_registers(runtime_addr, state, subroutine)
    length = _known_value(state, 'a')
    filename_addr = xy_addr(state.pessimistic['x'].get_previous_load_imm_operand(), state.pessimistic['y'].get_previous_load_imm_operand())
    if length == 0:
        _comment_call(runtime_addr, subroutine, "Set no filename")
        return
    if length is None or filename_addr is None:
        _comment_call(runtime_addr, subroutine, subroutine.title)
        return

    # The filename is a PETSCII string of A bytes
    if _loaded_and_unclassified(filename_addr, length):
        _name_data(filename_addr, "filename")
        string(filename_addr, length, encoding="petscii")
    text = ""
    for i in range(length):
        binary_addr, _ = movemanager.r2b(RuntimeAddr(filename_addr + i))
        c = None if binary_addr is None else memory_binary[binary_addr]
        char = None if c is None else textencoding.PETSCII.char(c)
        if char is None or char == '"':
            text = None
            break
        text += char
    if text is None:
        _comment_call(runtime_addr, subroutine, "Set the filename (%d bytes)" % length)
    else:
        _comment_call(runtime_addr, subroutine, 'Set the filename to "%s"' % text)

def load_hook(runtime_addr, state, subroutine):
    a = _known_value(state, 'a')
    # (X/Y are the load address only for a load with secondary address 0, so
    # they're not commented on)
    _comment_registers(runtime_addr, state, subroutine, entry=False)
    if a is not None:
        disassembly.comment_binary(state.pessimistic['a'].get_previous_load_imm_operand(), "A=" + subroutine.on_entry['a'], align=Align.INLINE, word_wrap=False, auto_generated=True)
    if a == 0:
        _comment_call(runtime_addr, subroutine, "Load a file")
    elif a == 1:
        _comment_call(runtime_addr, subroutine, "Verify a file")
    else:
        _comment_call(runtime_addr, subroutine, subroutine.title)

def save_hook(runtime_addr, state, subroutine):
    _comment_registers(runtime_addr, state, subroutine)
    # A is the zero page address of the pointer to the start address: name it
    a_addr = state.pessimistic['a'].get_previous_load_imm_operand()
    if a_addr is not None:
        auto_expr(movemanager.b2r(a_addr), get_label(memory_binary[a_addr], a_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE))
    end_addr = xy_addr(state.pessimistic['x'].get_previous_load_imm_operand(), state.pessimistic['y'].get_previous_load_imm_operand())
    _comment_call(runtime_addr, subroutine, subroutine.title)

def _carry_hook(read_text, set_text):
    """A hook for a call that reads something into X/Y with carry set, and
    sets it from X/Y with carry clear (e.g. PLOT): the texts can use {x} and
    {y}, the values of X and Y if they're known."""
    def hook(runtime_addr, state, subroutine):
        carry = state.pessimistic['c']
        if carry is True:
            _comment_registers(runtime_addr, state, subroutine, entry=False, exit=False)
            # The results are in X and Y, as on_entry describes them
            for reg in ('x', 'y'):
                next_use = state.next_use[reg]
                if next_use is not None and subroutine.on_entry.get(reg):
                    disassembly.comment(movemanager.b2r(next_use), reg.upper() + "=" + subroutine.on_entry[reg], align=Align.INLINE, auto_generated=True)
            _comment_call(runtime_addr, subroutine, read_text)
        elif carry is False:
            _comment_registers(runtime_addr, state, subroutine, exit=False)
            x, y = _known_value(state, 'x'), _known_value(state, 'y')
            _comment_call(runtime_addr, subroutine, set_text.format(x="X" if x is None else x, y="Y" if y is None else y))
        else:
            _comment_registers(runtime_addr, state, subroutine, exit=False)
            _comment_call(runtime_addr, subroutine, subroutine.title)
    return hook

plot_hook   = _carry_hook("Read the cursor position into X (row) and Y (column)", "Move the cursor to row {x}, column {y}")
memtop_hook = _carry_hook("Read the top of memory into X/Y", "Set the top of memory to X/Y")
membot_hook = _carry_hook("Read the bottom of memory into X/Y", "Set the bottom of memory to X/Y")
vector_hook = _carry_hook("Copy the Kernal vectors to the list at X/Y", "Set the Kernal vectors from the list at X/Y")

def setmsg_hook(runtime_addr, state, subroutine):
    _comment_registers(runtime_addr, state, subroutine)
    a = _known_value(state, 'a')
    if a is None:
        _comment_call(runtime_addr, subroutine, subroutine.title)
        return
    shown = [kind for bit, kind in ((0x80, "control"), (0x40, "error")) if a & bit]
    if not shown:
        text = "Turn off Kernal messages"
    else:
        text = "Show only Kernal %s messages" % " and ".join(shown) if len(shown) == 1 else "Show Kernal control and error messages"
    _comment_call(runtime_addr, subroutine, text)

def strout_hook(runtime_addr, state, subroutine):
    """BASIC's STROUT: print the zero-terminated string at A/Y"""
    _comment_registers(runtime_addr, state, subroutine)
    string_addr = xy_addr(state.pessimistic['a'].get_previous_load_imm_operand(), state.pessimistic['y'].get_previous_load_imm_operand())
    if string_addr is not None and _loaded_and_unclassified(string_addr, 1):
        stringz(string_addr, encoding="petscii")
    _comment_call(runtime_addr, subroutine, subroutine.title)

_hooks = {
    "chrout": chrout_hook,
    "setlfs": setlfs_hook,
    "setnam": setnam_hook,
    "load":   load_hook,
    "save":   save_hook,
    "plot":   plot_hook,
    "memtop": memtop_hook,
    "membot": membot_hook,
    "vector": vector_hook,
    "setmsg": setmsg_hook,
}


# ************************************************************************************************
# Snippets

def _vector_names(names):
    """{address: (name, description, handler name)} for the vectors a
    program can set"""
    result = {}
    for vector in _machine().vectors:
        name = None
        if vector.name is not None:
            name = vector.commodore_name if names == "commodore" else vector.name
        result[vector.addr] = (name, vector.description, vector.handler)
    return result

def pre_trace_writing_to_vector(p):
    """A program setting one of the vectors (e.g. the IRQ vector), an effect
    pattern (see snippethelper.vector_pattern()): before tracing, label the
    handler (e.g. 'irq_handler', then 'irq_handler_2' etc) and trace it."""
    _, description, handler = _vector_names(session.current().extras["commodore.names"])[p.binding('vector')]

    def new_name():
        # The first handler for a vector is e.g. 'irq_handler', the next
        # 'irq_handler_2'
        counts = session.current().extras.setdefault("commodore.vector_handler_count", {})
        count = counts.get(handler, 0) + 1
        counts[handler] = count
        return handler if count == 1 else "%s_%d" % (handler, count)

    vector_handler(p, new_name)

def post_trace_writing_to_vector(p):
    """A program setting one of the vectors: after tracing, comment it (e.g.
    'Set the IRQ vector to irq_handler', or for one with only one byte set to
    a known value, 'Set the low byte of the IRQ vector to $31'), and write
    the handler's address as its name's low and high bytes."""
    _, description, handler = _vector_names(session.current().extras["commodore.names"])[p.binding('vector')]
    if p.matched('lo') and p.matched('hi'):
        text = "Set the {0} to {1}".format(description, vector_handler_name(p.value('lo_value') + 256 * p.value('hi_value')))
    else:
        text = half_set_vector_text(p, "the " + description, _hex2)
    comment_vector(p, text)

# ************************************************************************************************
# The C128's MMU

def c128_memory(configuration, addr):
    """What the C128 has at addr with the given MMU configuration (the value
    of its configuration register, at &ff00, e.g. c128_bank_configurations[0]
    for bank 0): 'MMU' (&ff00-&ff04, in every configuration), 'I/O',
    'character ROM', 'BASIC ROM', 'Kernal ROM' (which includes the screen
    editor), 'internal ROM', 'external ROM' (the function ROMs), or 'RAM 0' to
    'RAM 3' (RAM 2 and 3 are RAM 0 and 1 on a C128 with 128K). &0000-&03ff is
    always RAM 0, since the Kernal makes it common RAM."""
    if 0xff00 <= addr < 0xff05:
        return "MMU"
    ram = "RAM %d" % (configuration >> 6)
    if addr < 0x0400:
        return "RAM 0"
    if addr < 0x4000:
        return ram
    if addr < 0x8000:
        return ram if configuration & 0x02 else "BASIC ROM"
    if addr < 0xc000:
        return ("BASIC ROM", "internal ROM", "external ROM", ram)[(configuration >> 2) & 3]
    high = ("Kernal ROM", "internal ROM", "external ROM", ram)[(configuration >> 4) & 3]
    if 0xd000 <= addr < 0xe000:
        if not configuration & 0x01:
            return "I/O"
        return ram if high == ram else "character ROM"
    return high

def c128_configuration_description(configuration):
    """A description of an MMU configuration, e.g. 'bank 15 (RAM 0, BASIC
    ROM, Kernal ROM, I/O)', or for one that isn't one of the Kernal's banks,
    e.g. 'RAM 0, I/O'."""
    def at(addr):
        return c128_memory(configuration, addr)
    ram = "RAM %d" % (configuration >> 6)
    parts = []
    low, mid, high = at(0x4000), at(0x8000), at(0xc000)
    if low == "BASIC ROM" and mid == "BASIC ROM":
        parts.append("BASIC ROM")
    elif low == "BASIC ROM":
        parts.append("BASIC ROM at $4000-$7fff")
    elif mid == "BASIC ROM":
        parts.append("BASIC ROM at $8000-$bfff")
    for rom in ("internal ROM", "external ROM"):
        name = rom.replace("ROM", "function ROM")
        if mid == rom and high == rom:
            parts.append(name + " at $8000-$ffff")
        elif mid == rom:
            parts.append(name + " at $8000-$bfff")
        elif high == rom:
            parts.append(name + " at $c000-$ffff")
    if high == "Kernal ROM":
        parts.append("Kernal ROM")
    if at(0xd000) in ("I/O", "character ROM"):
        parts.append(at(0xd000))
    text = ram + (", " + ", ".join(parts) if parts else " only")
    if configuration in c128_bank_configurations:
        return "bank {0} ({1})".format(c128_bank_configurations.index(configuration), text)
    return text

# The MMU's configuration register (at &ff00 and &d500), and its load
# configuration registers (&ff01-&ff04: writing to one sets the configuration
# to the preconfiguration register at &d501-&d504)
_MMU_CONFIGURATION_REGISTERS = (0xff00, 0xd500)
_MMU_LOAD_CONFIGURATION_REGISTERS = range(0xff01, 0xff05)

def _c128_mmu_writes():
    """[(binary location, configuration or None)] for each instruction that
    sets the MMU configuration: the value stored to &ff00 or &d500 (if it's
    known), or None for a store to one of the load configuration registers
    (&ff01-&ff04), or of an unknown value. ([(binary location, register
    address, configuration or None)])"""
    cpu = session.current().cpu
    result = []
    for run in cpu.straight_runs():
        for write in cpu.memory_writes(run):
            if write.read_modify_write or write.target is None:
                continue
            register = write.target
            if register in _MMU_CONFIGURATION_REGISTERS or register in _MMU_LOAD_CONFIGURATION_REGISTERS:
                configuration = write.value if register in _MMU_CONFIGURATION_REGISTERS else None
                move_id = session.current().moves.move_id_for_binary_addr[write.binary_addr]
                result.append((memorymanager.BinaryLocation(BinaryAddr(write.binary_addr), move_id), register, configuration))
    return result

def _c128_comment_mmu_writes(writes):
    """Comment each instruction that sets the MMU configuration, e.g. 'Set
    the MMU to bank 0 (RAM 0 only)'."""
    for binary_loc, register, configuration in writes:
        if register in _MMU_LOAD_CONFIGURATION_REGISTERS:
            text = "Set the MMU to preconfiguration {0} (as set at ${1:04x})".format("ABCD"[register - 0xff01], 0xd501 + register - 0xff01)
        elif configuration is not None:
            text = "Set the MMU to " + c128_configuration_description(configuration)
        else:
            continue
        disassembly.comment_binary(binary_loc, text, align=Align.INLINE, auto_generated=True)

def _c128_switched_ranges(writes):
    """[(binary start, binary end, configuration)] for the code after each
    instruction that sets the MMU's configuration to a known value (see
    _c128_mmu_writes()): from the next instruction, for as long as the code
    runs straight on from it. That stops at the end of a block (e.g. RTS or
    JMP), at an instruction that other code jumps or branches to (or an entry
    point), since that might come from code with another configuration, and
    at the next instruction that sets the configuration. (A JSR is taken to
    return with the configuration it was called with.)"""
    memory_binary = session.current().memory.binary
    labels = session.current().labels.labels
    explicit_entry_points = session.current().cpu.explicit_entry_points
    write_addrs = {binary_loc.binary_addr for binary_loc, _, _ in writes}
    result = []
    for binary_loc, register, configuration in writes:
        if configuration is None:
            continue
        c = classification.get_classification(binary_loc.binary_addr)
        start = binary_loc.binary_addr + c.length()
        end = start
        while end < 0x10000 and memory_binary[end] is not None and end not in write_addrs:
            c = classification.get_classification(end)
            if c is None or c is classification.INSIDE_A_CLASSIFICATION or not c.is_code(end):
                break
            label = labels.get(movemanager.b2r(BinaryAddr(end)))
            if end > start and ((label is not None and label.references) or end in explicit_entry_points):
                break
            end += c.length()
            if c.is_block_end():
                break
        if end > start:
            result.append((start, end, configuration))
    return result

def _c128_configuration_at(binary_addr, ranges):
    """The MMU configuration the code at binary_addr runs with, from the
    ranges [(binary start, binary end, configuration)] (the first that
    covers it), or None if it's not known (so it's taken to be bank 15)."""
    for start, end, configuration in ranges:
        if start <= binary_addr < end:
            return configuration
    return None

# The heading for the names of addresses in another configuration than bank
# 15 in the "Memory locations" list (since their memory regions are bank
# 15's)
C128_OTHER_BANKS_HEADING = "Other banks"

def _c128_name_by_configuration(ranges):
    """Where code that runs with another MMU configuration (in the ranges,
    see _c128_configuration_at()) uses an address that's something else in
    that configuration than in bank 15 (e.g. RAM rather than I/O or a ROM),
    give the address a plain name there (e.g. 'ld020'), as a local label,
    rather than its name in bank 15 (e.g. 'vic_border_colour'). Only names
    commodore.py gives are replaced, not the control file's."""
    if not ranges:
        return
    machine = _machine()
    optional_labels = session.current().disassembly.optional_labels
    # The names c128() gives that can be replaced: the ROM routines' and
    # the Kernal's jump table's (whose calls aren't commented there either,
    # see _unless_mapped_out())
    routine_names = collections.defaultdict(set)
    for routine in machine.rom_routines:
        routine_names[routine.addr].update({routine.name, routine.commodore_name})
    for call in machine.jump_table:
        routine_names[call.addr].add(call.name)
    bank_15 = c128_bank_configurations[15]
    for runtime_addr, label in sorted(session.current().labels.labels.items()):
        if runtime_addr not in optional_labels and runtime_addr not in routine_names:
            continue
        given = {name.text for names in label.explicit_names.values() for name in names}
        if not given <= routine_names.get(runtime_addr, set()):
            continue
        for reference in label.references:
            configuration = _c128_configuration_at(reference.binary_addr, ranges)
            if configuration is None or c128_memory(configuration, runtime_addr) == c128_memory(bank_15, runtime_addr):
                continue
            c = classification.get_classification(reference.binary_addr)
            length = c.length() if c is not None and c is not classification.INSIDE_A_CLASSIFICATION else 1
            disassembly.add_local_label(RuntimeAddr(runtime_addr), utils.force_case("l%04x" % runtime_addr),
                                        reference.binary_addr, reference.binary_addr + length, heading=C128_OTHER_BANKS_HEADING)

def _mapped_out(binary_addr, runtime_addr):
    """Whether the code at binary_addr runs with a C128 MMU configuration in
    which runtime_addr is something else than in bank 15 (e.g. RAM rather
    than the Kernal ROM or I/O), so a call to a ROM routine there, or a store
    to an I/O register, isn't one. (Always False for the other machines.)
    During tracing, only c128_bank()'s configurations are known; once the
    code has been traced, those the code sets too (see
    _c128_mmu_analysis())."""
    if _machine().name != "c128":
        return False
    extras = session.current().extras
    ranges = extras.get("commodore.c128_ranges")
    if ranges is None:
        ranges = extras.get("commodore.c128_banks", [])
    configuration = _c128_configuration_at(binary_addr, ranges)
    return configuration is not None and c128_memory(configuration, runtime_addr) != c128_memory(c128_bank_configurations[15], runtime_addr)

def _unless_mapped_out(hook):
    """A subroutine hook for a ROM routine, that does nothing for a call
    from code that runs with the ROM mapped out (see _mapped_out())."""
    def wrapper(runtime_addr, state, subroutine):
        binary_addr, _ = movemanager.r2b(runtime_addr)
        if binary_addr is not None and _mapped_out(binary_addr, subroutine.runtime_addr):
            return
        hook(runtime_addr, state, subroutine)
    return wrapper

def _inline_string_hook(target, caller):
    """The hook for a call that prints the string after it (PRIMM): tracing
    continues after the string, unless the call is from code that runs with
    the Kernal ROM mapped out (see _mapped_out())."""
    binary_addr, _ = movemanager.r2b(caller)
    if binary_addr is not None and _mapped_out(binary_addr, target):
        return caller + 3
    return stringz_hook(target, caller)

def _c128_mmu_analysis():
    """The C128's MMU: comment the code that sets its configuration, and name
    the addresses code uses according to the configuration it runs with:
    after the code sets it (see _c128_switched_ranges()), or as
    c128_bank() says. (Run once the code has been traced, as one of the CPU's
    code analysis functions.)"""
    writes = _c128_mmu_writes()
    _c128_comment_mmu_writes(writes)
    # (The configuration the code sets comes first, since it changes the one
    # c128_bank() gives)
    ranges = _c128_switched_ranges(writes) + list(session.current().extras.get("commodore.c128_banks", []))
    session.current().extras["commodore.c128_ranges"] = ranges
    _c128_name_by_configuration(ranges)

def c128_bank(start, end, bank=None, *, configuration=None):
    """Say that the code from start to end (runtime addresses, end exclusive)
    runs with the C128's MMU set to the given bank (0-15, as the Kernal
    numbers them, see c128_bank_configurations), or configuration (the value
    of its configuration register, at &ff00), rather than the usual bank 15.
    An address it uses that's something else there (e.g. in bank 0, RAM
    rather than I/O or a ROM) isn't given its name in bank 15: e.g. 'lda
    $d020' is 'lda ld020', not 'lda vic_border_colour'. (Only the names
    c128() gives; and &0000-&03ff is RAM 0 in every bank.) A call to a ROM
    routine that's mapped out isn't commented as one, and a call to PRIMM
    isn't followed by a string (see _mapped_out()). Call it after
    c128()."""
    command = "c128_bank"
    if _machine().name != "c128":
        utils.die("commodore.c128_bank(): call commodore.c128() first")
    if (bank is None) == (configuration is None):
        utils.die("commodore.c128_bank(): give a bank or a configuration (but not both)")
    if bank is not None:
        if not utils.is_integer_type(bank) or not 0 <= bank < 16:
            utils.die("commodore.c128_bank(): the bank must be 0-15, not {0!r}".format(bank))
        configuration = c128_bank_configurations[bank]
    elif not utils.is_integer_type(configuration) or not 0 <= configuration < 0x100:
        utils.die("commodore.c128_bank(): the configuration must be 0-255, not {0!r}".format(configuration))
    for addr in (start, end):
        if not utils.is_integer_type(addr) or not 0 <= addr <= 0x10000:
            utils.die("commodore.c128_bank(): the addresses must be between 0 and &10000, not {0!r}".format(addr))
    if not start < end:
        utils.die("commodore.c128_bank(): the start ({0}) must be before the end ({1})".format(_hex4(start), _hex4(end)))
    binary_start = movemanager.r2b_checked(start).binary_addr
    binary_end = movemanager.r2b_checked(end - 1).binary_addr + 1
    session.current().extras.setdefault("commodore.c128_banks", []).append((binary_start, binary_end, configuration))


def _far_call(p):
    """For a match of the JSRFAR/JMPFAR effect pattern: (bank, target address,
    whether it's JMPFAR, whether the target is traced). The target is traced
    if it's in the program, i.e. loaded, and RAM 0 in that bank (RAM 2 is
    RAM 0 on a C128 with 128K)."""
    bank = p.value('bank')
    target = p.value('lo') + 256*p.value('hi')
    is_jump = p.memory_binary[p.get_binary_address('call')] == 0x4c
    traced = _is_loaded(target) and bank < 16 and c128_memory(c128_bank_configurations[bank], target) in ("RAM 0", "RAM 2")
    return bank, target, is_jump, traced

def pre_trace_far_call(p):
    """A C128 program setting up JSRFAR or JMPFAR's bank and address at
    &02-&04 with known values, then calling it (an effect pattern): before
    tracing, if the address is in the program (see _far_call()), name it
    (e.g. 'far_call_target') and trace it."""
    bank, target, is_jump, traced = _far_call(p)
    if not traced:
        return
    if vector_handler_name(target) is None:
        # e.g. 'far_call_target', then 'far_call_target_2'
        base_name = "far_jump_target" if is_jump else "far_call_target"
        counts = session.current().extras.setdefault("commodore.far_call_count", {})
        count = counts.get(base_name, 0) + 1
        counts[base_name] = count
        label(target, base_name if count == 1 else "%s_%d" % (base_name, count))
    p.entry(target)

def post_trace_far_call(p):
    """After tracing: comment the set-up of a JSRFAR or JMPFAR (e.g. 'Call
    far_call_target in bank 0'), and use the target's name in it."""
    bank, target, is_jump, traced = _far_call(p)
    start, end = p.extent()
    if traced:
        target_text = vector_handler_name(target)
        for line, maker in (('store_lo', make_lo), ('store_hi', make_hi)):
            operand = p.store(line).value_operand
            if operand is not None:
                classification.add_expression(operand, maker(target_text), force=False)
    else:
        target_text = "$%04x" % target

    labels = session.current().labels.labels
    runtime_addr = movemanager.b2r(start.binary_addr)
    if not (runtime_addr in labels and labels[runtime_addr].explicit_names.get(start.move_id)):
        p.blank_once(start)
    disassembly.comment_binary(start, "{0} {1} in bank {2}".format("Jump to" if is_jump else "Call", target_text, bank),
                               indent=1, align=Align.AFTER_LABEL, auto_generated=True)
    p.blank_once(end)

def register_snippets():
    """Register commodore's snippets with the current session (once per
    session)"""
    extras = session.current().extras
    if extras.get("commodore.snippets_registered"):
        return
    extras["commodore.snippets_registered"] = True

    # On the C128, a call to JSRFAR or JMPFAR with its bank and address set at
    # &02-&04, e.g. 'lda #0 : sta $02 : lda #>target : sta $03 : lda #<target
    # : sta $04 : jsr jsrfar' (an effect pattern, so in any order, with any
    # registers and other instructions between)
    if any(call.name == "jsrfar" for call in _machine().jump_table):
        register_snippet(pre_trace_far_call, post_trace_far_call, """
store_bank
    [$02] = bank
store_hi
    [$03] = hi
store_lo
    [$04] = lo
call
    jsr $ff6e | jmp $ff71
""")

    # Code setting one of the vectors, in any order, with any registers (an
    # effect pattern)
    register_snippet(pre_trace_writing_to_vector, post_trace_writing_to_vector, vector_pattern(vector.addr for vector in _machine().vectors))

# ************************************************************************************************
# The VIC-II's interrupts (C64 and C128)

_VIC_CONTROL_1 = 0xd011
_VIC_RASTER_LINE = 0xd012
_VIC_INTERRUPT_STATUS = 0xd019
_VIC_INTERRUPT_ENABLE = 0xd01a
_VIC_REGISTERS = (_VIC_CONTROL_1, _VIC_RASTER_LINE, _VIC_INTERRUPT_STATUS, _VIC_INTERRUPT_ENABLE)

# The VIC-II's interrupts, by bit (of &d019 and &d01a)
_VIC_INTERRUPTS = ("raster", "sprite-background collision", "sprite-sprite collision", "light pen")

def _vic_interrupts_text(value):
    """e.g. 'raster interrupt', 'raster and light pen interrupts'"""
    names = [name for bit, name in enumerate(_VIC_INTERRUPTS) if value & (1 << bit)]
    if len(names) == 1:
        return names[0] + " interrupt"
    return ", ".join(names[:-1]) + " and " + names[-1] + " interrupts"

def _vic_interrupt_analysis():
    """Comment the code that sets up the VIC-II's interrupts: a store of a
    known value to its raster line register (&d012), e.g. 'Raster interrupt
    at line 100', with bit 8 from a store to &d011 that runs with it, if it's
    known; to its interrupt enable register (&d01a), e.g. 'Enable only the
    VIC-II's raster interrupt'; and to its interrupt status register (&d019),
    e.g. 'Acknowledge the VIC-II's raster interrupt', as does a
    read-modify-write instruction (e.g. 'asl $d019'). (Not where a C128's
    MMU maps the I/O out: see _mapped_out(). Run once the code has been
    traced, as one of the CPU's code analysis functions.)"""
    cpu = session.current().cpu
    memory_binary = session.current().memory.binary

    def comment(binary_addr, text):
        move_id = session.current().moves.move_id_for_binary_addr[binary_addr]
        disassembly.comment_binary(memorymanager.BinaryLocation(BinaryAddr(binary_addr), move_id), text, align=Align.INLINE, auto_generated=True)

    for run in cpu.straight_runs():
        # The writes to the VIC-II's interrupt registers in the run
        accesses = [write for write in cpu.memory_writes(run)
                    if write.target in _VIC_REGISTERS and not _mapped_out(write.binary_addr, write.target)]
        if not accesses:
            continue

        # Bit 8 of the raster line: bit 7 of what's stored to &d011, if
        # that's known, or set by an 'and #n' or 'ora #n' just before
        high_bits = set()
        for write in accesses:
            if write.target != _VIC_CONTROL_1 or write.read_modify_write:
                continue
            value = write.value
            index = run.index(write.binary_addr)
            previous = run[index - 1] if index > 0 else None
            if value is not None:
                high_bits.add(value >> 7)
            elif previous is not None and memory_binary[previous] == 0x29 and not memory_binary[previous + 1] & 0x80:   # and #n
                high_bits.add(0)
            elif previous is not None and memory_binary[previous] == 0x09 and memory_binary[previous + 1] & 0x80:       # ora #n
                high_bits.add(1)
            else:
                high_bits.add(None)
        high_bit = high_bits.pop() if len(high_bits) == 1 else None

        for write in accesses:
            binary_addr, register, value = write.binary_addr, write.target, write.value
            if write.read_modify_write:
                if register == _VIC_INTERRUPT_STATUS:
                    comment(binary_addr, "Acknowledge the VIC-II's interrupts")
                continue
            if value is None:
                continue
            if register == _VIC_RASTER_LINE:
                if high_bit is None:
                    text = "Raster interrupt at line {0} (or {1}, if bit 7 of {2} is set)".format(value, value + 256, _hex4(_VIC_CONTROL_1))
                else:
                    text = "Raster interrupt at line {0}".format(value + 256 * high_bit)
                comment(binary_addr, text)
            elif register == _VIC_INTERRUPT_ENABLE:
                if value & 0x0f == 0:
                    text = "Disable the VIC-II's interrupts"
                elif value & 0x0f == 0x0f:
                    text = "Enable all the VIC-II's interrupts"
                else:
                    text = "Enable only the VIC-II's " + _vic_interrupts_text(value)
                comment(binary_addr, text)
            elif register == _VIC_INTERRUPT_STATUS:
                if value & 0x0f == 0x0f:
                    comment(binary_addr, "Acknowledge the VIC-II's interrupts")
                elif value & 0x0f:
                    comment(binary_addr, "Acknowledge the VIC-II's " + _vic_interrupts_text(value))

# ************************************************************************************************
# BASIC programs

def _basic_line_text(data):
    """A tokenised BASIC line's text as LIST shows it (in the C64's upper
    case/graphics character set), with other codes as e.g. {$93}"""
    result = ""
    in_quotes = False
    in_rem = False
    for c in data:
        if c == ord('"'):
            in_quotes = not in_quotes
        if c >= 0x80 and not in_quotes and not in_rem:
            if c == BASIC_TOKEN_PI:
                result += "{pi}"
            elif c - 0x80 < len(_machine().basic_tokens):
                result += _machine().basic_tokens[c - 0x80]
                in_rem = (c == BASIC_TOKEN_REM)
            else:
                result += "{%s}" % _hex2(c)
            continue
        char = textencoding.PETSCII.char(c)
        if char is not None:
            result += char.upper()
        else:
            result += "{%s}" % _hex2(c)
    return result

def _basic_lines(runtime_addr):
    """The lines of the BASIC program at the address, as a list of (address,
    link, line number, text bytes), followed by the address of the two zero
    bytes that end it; or None if there isn't a valid BASIC program there."""
    def u8(addr):
        if addr > 0xffff:
            return None
        binary_addr, _ = movemanager.r2b(RuntimeAddr(addr))
        if binary_addr is None or not memorymanager.is_data_loaded_at_binary_addr(binary_addr):
            return None
        return memory_binary[binary_addr]
    def u16(addr):
        low, high = u8(addr), u8(addr + 1)
        return None if low is None or high is None else low + 256*high

    lines = []
    addr = runtime_addr
    while True:
        link = u16(addr)
        if link is None:
            return None
        if link == 0:
            return lines, addr
        number = u16(addr + 2)
        # The link is to the address after the line's zero byte
        if number is None or number > 63999 or link <= addr + 4 or len(lines) >= 1000:
            return None
        text = []
        for a in range(addr + 4, link - 1):
            c = u8(a)
            if c is None or c == 0:
                return None
            text.append(c)
        if u8(link - 1) != 0:
            return None
        lines.append((addr, link, number, text))
        addr = link

def basic_program(runtime_addr=None):
    """Classify the tokenised BASIC program at the address (by default where
    BASIC programs start: &0801 on the C64, and on the VIC-20 &1001, or &0401
    or &1201 with a RAM expansion), e.g. the one-line 'SYS' program at the start
    of most machine code programs. Each line is labelled (e.g.
    'basic_line_10'), its link to the next line and its line number are
    words, and its text is bytes for the tokens and PETSCII strings, listed
    in a comment, e.g. '; 10 SYS2061'. An address SYS calls in the loaded
    data is an entry point, named 'sys_entry' unless it already has a name
    (so to give it another, name it before calling this, or c64()).

    Returns the address after the program, or None (classifying nothing) if
    there isn't a valid BASIC program there."""
    if runtime_addr is None:
        runtime_addr = _machine().basic_start
    found = _basic_lines(runtime_addr)
    if found is None:
        return None
    lines, end = found
    names = {}
    def line_name(number):
        name = "basic_line_%d" % number
        names[name] = names.get(name, 0) + 1
        return name if names[name] == 1 else "%s_%d" % (name, names[name])
    line_names = [line_name(number) for _, _, number, _ in lines] + ["basic_end"]

    for i, (addr, link, number, text) in enumerate(lines):
        label(addr, line_names[i])
        auto_comment(addr, "%d %s" % (number, _basic_line_text(text)))
        word(addr)
        expr(addr, line_names[i + 1])
        word(addr + 2)
        decimal(addr + 2)
        # The text: runs of characters as strings, the rest (tokens and
        # other codes) as bytes
        a = addr + 4
        in_quotes = False
        in_rem = False
        run_start = None
        def end_run(run_end):
            if run_start is not None:
                string(run_start, run_end - run_start, encoding="petscii")
        for c in text:
            if c == ord('"'):
                in_quotes = not in_quotes
            is_char = textencoding.PETSCII.char(c) is not None and (c < 0x80 or in_quotes or in_rem)
            if is_char:
                if run_start is None:
                    run_start = a
            else:
                end_run(a)
                run_start = None
                byte(a)
                if c == BASIC_TOKEN_REM and not in_quotes:
                    in_rem = True
            a += 1
        end_run(a)
        byte(a)     # (the zero at the end of the line)

        # SYS to an address in the loaded data
        if BASIC_TOKEN_SYS in text:
            digits = bytes(text[text.index(BASIC_TOKEN_SYS) + 1:]).decode("latin-1").lstrip(" (")
            number_text = ""
            for d in digits:
                if not d.isdigit():
                    break
                number_text += d
            if number_text and int(number_text) <= 0xffff and _is_loaded(int(number_text)):
                sys_addr = int(number_text)
                entry(sys_addr)
                if not _has_name(sys_addr):
                    label(sys_addr, "sys_entry")

    label(end, "basic_end")
    word(end)
    return end + 2

def _is_loaded(runtime_addr):
    """Whether there's data loaded at the runtime address"""
    binary_addr, _ = movemanager.r2b(RuntimeAddr(runtime_addr))
    return binary_addr is not None and memorymanager.is_data_loaded_at_binary_addr(binary_addr)


# ************************************************************************************************
# ROMs and cartridges

def is_cartridge():
    """For a cartridge: name its header, and trace its code.

    On the C64 a cartridge is at &8000, and on the VIC-20 at &a000, starting
    with the addresses of its cold and warm start code, then a signature in
    PETSCII ('CBM80' on the C64, 'A0CBM' on the VIC-20). On the C128 and the
    Plus/4 a function ROM is at &8000 (or &c000 for the C128's internal
    one), starting with its cold and warm start code (usually JMPs), then an
    ID byte (1 to start it automatically) and 'CBM' in ASCII. (The PET's
    expansion ROMs have no standard header.)"""
    if _machine().cartridge is None:
        utils.die("commodore.is_cartridge(): the PET's expansion ROMs have no standard header")
    addr, signature = _machine().cartridge
    if signature == "CBM":
        label(addr, "cartridge_cold_start")
        entry(addr)
        label(addr + 3, "cartridge_warm_start")
        entry(addr + 3)
        label(addr + 6, "cartridge_id")
        byte(addr + 6)
        label(addr + 7, "cartridge_signature")
        string(addr + 7, 3, encoding="ascii")
    else:
        label(addr, "cartridge_cold_start_vector")
        code_ptr(addr, label_name=None if _has_name(memorymanager.get_u16_runtime(RuntimeAddr(addr))) else "cartridge_cold_start")
        label(addr + 2, "cartridge_warm_start_vector")
        code_ptr(addr + 2, label_name=None if _has_name(memorymanager.get_u16_runtime(RuntimeAddr(addr + 2))) else "cartridge_warm_start")
        label(addr + 4, "cartridge_signature")
        string(addr + 4, len(signature), encoding="petscii")
    auto_comment(addr, "Cartridge header")

def _has_name(runtime_addr):
    labels = session.current().labels.labels
    return runtime_addr in labels and bool(labels[runtime_addr].explicit_names)

def kernal_rom():
    """For a disassembly of a Kernal ROM (loaded at &e000, or &c000 on the
    C128 and Plus/4): trace the code from the Kernal's jump table (each entry
    named, e.g. 'chrout') and the 6502's NMI, reset and IRQ vectors."""
    for call in _machine().jump_table:
        if _is_loaded(call.addr):
            entry(call.addr, call.name)
    for addr, name in ((0xfffa, "nmi_entry"), (0xfffc, "reset_entry"), (0xfffe, "irq_entry")):
        target = memorymanager.get_u16_runtime(RuntimeAddr(addr))
        has_name = _has_name(target) or target in session.current().disassembly.optional_labels
        code_ptr(addr, label_name=None if has_name else name)

def basic_rom():
    """For a disassembly of a BASIC ROM (loaded at &a000 on the C64, &c000 on
    the VIC-20, &4000 on the C128 and &8000 on the Plus/4): trace the code
    from its cold and warm start vectors (or JMPs), and name its signature."""
    machine = _machine()
    base = machine.basic_rom_addr
    if base is None:
        utils.die("commodore.basic_rom(): the PET's BASIC ROM has no vectors to trace from (use entry())")
    if machine.cartridge[1] == "CBM":
        # JMPs to the cold and warm start code (and on the C128 the IRQ
        # code), then on the Plus/4 an ID byte and 'CBM'
        for offset, name in ((0, "basic_cold_start"), (3, "basic_warm_start"), (6, "basic_irq")):
            if memory[RuntimeAddr(base + offset)] == 0x4c:
                label(base + offset, name)
                entry(base + offset)
        if memory[RuntimeAddr(base + 6)] != 0x4c:
            label(base + 6, "basic_id")
            byte(base + 6)
            label(base + 7, "basic_signature")
            string(base + 7, 3, encoding="ascii")
        return
    for offset, name in ((0, "basic_cold_start"), (2, "basic_warm_start")):
        target = memorymanager.get_u16_runtime(RuntimeAddr(base + offset))
        label(base + offset, name + "_vector")
        code_ptr(base + offset, label_name=None if _has_name(target) else name)
    label(base + 4, "basic_signature")
    string(base + 4, encoding="petscii")


# ************************************************************************************************
# The machines' set up

def _set_up(command, machine, names, rom_labels):
    """What c64(), vic20(), c128(), plus4() and pet() do, for the machine"""
    if names not in NAMES:
        utils.die("commodore.{0}(): names must be one of {1}, not {2!r}".format(command, ", ".join(repr(n) for n in NAMES), names))
    extras = session.current().extras
    if extras.get("commodore.machine") is not None:
        utils.die("commodore.{0}(): this session's machine has already been chosen".format(command))
    extras["commodore.machine"] = machine
    extras["commodore.names"] = names

    config.set_text_encoding("petscii")
    register_snippets()
    for start, end, name in machine.regions:
        memory_region(start, end, name)

    for addr, name, base in location_names(machine, names, rom_labels):
        optional_label(addr, name, base, definable_inline=not any(start <= addr < end for start, end in machine.io_ranges))

    for call in machine.jump_table:
        hooks = _hooks if machine.call_hooks is None else machine.call_hooks
        subroutine(call.addr, call.name, call.title, None, call.on_entry, call.on_exit, hook=_unless_mapped_out(hooks.get(call.name, default_hook)), is_entry_point=False)
    # A call that prints the string after it (PRIMM) continues after the
    # string
    for addr in machine.inline_string_calls:
        cpu = session.current().cpu
        if cpu is None:
            utils.die("commodore.{0}(): call load() first".format(command))
        cpu.subroutine_hooks[RuntimeAddr(addr)] = _inline_string_hook
    if rom_labels:
        for routine in machine.rom_routines:
            name = routine.name
            if names == "commodore" and routine.commodore_name is not None:
                name = routine.commodore_name
            subroutine(routine.addr, name, routine.title, None, routine.on_entry, routine.on_exit,
                       hook=_unless_mapped_out(strout_hook if routine.commodore_name == "strout" else default_hook), is_entry_point=False)

    # Colours stored in the colour registers
    for addr in machine.colour_registers:
        for reg in "axy":
            session.current().trace.substitute_constant_list.append(cpu6502.SubConst("st%s $%04x" % (reg, addr), reg, machine.colours, True,
                                                                                     condition=lambda binary_addr, addr=addr: not _mapped_out(binary_addr, addr)))

    # The C128's MMU (see _c128_mmu_analysis()), before the calls are
    # commented and the colours substituted, since they depend on it (see
    # _mapped_out())
    if machine.name == "c128":
        code_analysis_fns = session.current().cpu.code_analysis_fns
        code_analysis_fns.insert(code_analysis_fns.index(session.current().cpu.substitute_constants), _c128_mmu_analysis)
    # The VIC-II's interrupts (see _vic_interrupt_analysis())
    if machine.name in ("c64", "c128"):
        session.current().cpu.code_analysis_fns.append(_vic_interrupt_analysis)

    if _is_loaded(machine.basic_start):
        basic_program(machine.basic_start)

def c64(names="descriptive", rom_labels=True):
    """Name and comment a C64 program's use of the Kernal, the hardware and
    the memory locations used by the OS and BASIC:

    - memory regions, for the list of memory locations at the top;
    - names for the memory locations (only output if used): zero page, the
      OS and BASIC workspace, the vectors, the screen, the VIC-II, the SID,
      the CIAs and the colour RAM; with names="commodore", Commodore's names
      (e.g. 'extcol' rather than 'vic_border_colour');
    - the Kernal's jump table, e.g. 'chrout', with comments where it's
      called (e.g. 'Output $93 (clear screen)'), and where the registers are
      set for it and used after it;
    - with rom_labels (the default), names for the routines in the C64's
      ROMs that programs call (e.g. 'kernal_irq_handler' at &ea31), and the
      labels in Commodore's source for the Kernal and BASIC ROMs. (Use
      rom_labels=False for a program that replaces the ROMs.)
    - names for the colours stored in the VIC-II's colour registers (e.g.
      'colour_black');
    - code that sets a vector (e.g. the IRQ vector at &0314) to an address in
      the program: the address is traced and named (e.g. 'irq_handler');
    - a BASIC program loaded at &0801 (see basic_program());
    - PETSCII as the text encoding (see config.set_text_encoding()).
    """
    _set_up("c64", c64_machine(), names, rom_labels)

def vic20(expansion=None, names="descriptive", rom_labels=True):
    """As c64(), for the VIC-20: its Kernal and BASIC are the C64's, with
    its own hardware (the VIC, two VIAs and the colour RAM) and memory map.

    expansion is the RAM expansion: "none", "3k" (in block 0, &0400-&0fff)
    or "8k" (8K or more, from &2000). It decides where BASIC programs start
    (&1001, &0401 or &1201), and where the screen and its colour RAM are
    (&1e00 and &9600, or with 8K or more, &1000 and &9400). By default (None)
    it's worked out from where the program is loaded: "3k" if there's data at
    &0401, else "none" if there's data at &1001, else "8k" if there's data at
    &1201, else "none"."""
    if expansion is None:
        if _is_loaded(0x0401):
            expansion = "3k"
        elif _is_loaded(0x1001):
            expansion = "none"
        elif _is_loaded(0x1201):
            expansion = "8k"
        else:
            expansion = "none"
    if expansion not in VIC20_EXPANSIONS:
        utils.die("commodore.vic20(): expansion must be one of {0} (or None), not {1!r}".format(", ".join(repr(e) for e in VIC20_EXPANSIONS), expansion))
    _set_up("vic20", vic20_machine(expansion), names, rom_labels)

def c128(names="descriptive", rom_labels=True):
    """As c64(), for the C128 in C128 mode, with the usual bank 15 (the ROMs
    and the I/O at &d000): its workspace, the MMU, the VDC, the VIC-II's and
    the C64's other hardware, its jump table (the C64's and 19 more, e.g.
    JSRFAR and PRIMM, whose string is skipped when tracing), its ROM routines
    and the labels in Commodore's source for its BASIC, monitor, screen
    editor and Kernal, and a BASIC program at &1c01.

    Its workspace has Commodore's names from its source, with descriptive
    names for the most used ones, and those that are the C64's (see
    commodoretables.py); the rest have Commodore's names either way. (A C128
    program in C64 mode is a C64 program: use c64().)"""
    _set_up("c128", c128_machine(), names, rom_labels)

def plus4(names="descriptive", rom_labels=True):
    """As c64(), for the Plus/4 (and the C16 and C116, which have the same
    ROMs): its workspace, the TED (video, sound, timers and the ROM switch at
    &ff3e/&ff3f), the ACIA, the 6529 ports, its jump table (the C64's and
    PRINT, PRIMM and the monitor), its ROM routines and the labels in
    Commodore's source for its BASIC and Kernal, and a BASIC program at
    &1001. Its workspace's names are as for c128()."""
    _set_up("plus4", plus4_machine(), names, rom_labels)

def pet(basic=4, columns=40, names="descriptive", rom_labels=True):
    """As c64(), for the PET (and the CBM 3000, 4000 and 8000 series), with
    BASIC 1 (the original 1977 ROMs), 2 or 4, and a 40 or 80 column screen
    (columns=80, BASIC 4's 8000 series, with a CRTC at &e880): its workspace
    (which depends on the BASIC version), the PIAs, the VIA, the screen at
    &8000, its jump table at &ffc0 (where only CHROUT has a hook: its LOAD,
    SAVE, VERIFY and SYS are BASIC's commands, not the C64's calls), its ROM
    routines and the labels in Commodore's source for its BASIC and Kernal
    (not BASIC 4's screen editor, which is different for each model), and a
    BASIC program at &0401, listed with that version's keywords (BASIC 4's
    disk commands too). The PET has no colours. Its workspace's names are as
    for c128()."""
    if basic not in PET_BASIC_VERSIONS:
        utils.die("commodore.pet(): basic must be 1, 2 or 4, not {0!r}".format(basic))
    if columns not in PET_COLUMNS:
        utils.die("commodore.pet(): columns must be 40 or 80, not {0!r}".format(columns))
    if columns == 80 and basic != 4:
        utils.die("commodore.pet(): only BASIC 4 PETs have 80 columns")
    _set_up("pet", pet_machine(basic, columns), names, rom_labels)
