"""
Commodore machines

Commodore specific functions: commodore.c64(), vic20(), c128(), plus4() and
pet() name and comment a program's use of the Kernal, the hardware and the OS
workspace, as acorn.bbc() does for the BBC Micro; drive1541() does the same
for code that runs in the 1541 disk drive. A control file calls one after
loading the program:

    import commodore
    start = load_prg("game.prg", "6510")
    commodore.c64()

They name the memory locations with descriptive names by default (e.g.
'vic_border_colour'); names="commodore" uses the names in Commodore's
documentation instead (e.g. 'EXTCOL'). Commodore's own names are in
capitals unless config.set_upper_case_os_calls(False) (see
official_name()). docs/machines/commodore.md describes it all for users.

The main pieces, in the order they come in this file:

- Machine, and c64_machine() etc.: what's known about each machine (its
  memory locations, hardware, ROM routines, Kernal jump table, vectors,
  colours and memory regions), from the tables in commodoretables.py and
  the labels from Commodore's source in commodoresource.py.
- location_names(): the names the set-up gives the memory locations, as
  optional labels (which are only output if they're used).
- The subroutine hooks for the Kernal's calls (chrout_hook() etc.), which
  comment each call and where its registers are set.
- Snippets: effect patterns (see effectpattern.py and snippethelper.py) for
  code that sets a vector, calls JSRFAR or JMPFAR on the C128, or writes a
  job to the 1541's job queue.
- Memory configurations: the C128's MMU and the C64's port at $01 (see
  Banking). Once the code has been traced, the configuration is followed
  through it (_flow_ranges()), and an address that's something else in
  the configuration the code runs with gets a plain name there
  (_name_by_configuration()). c128_bank() and c64_configuration() give the
  configuration for code where it isn't known from the code.
- drive1541_code(): code for the 1541 in another machine's program.
- The 1541's job results and VIAs, and the VIC-II's interrupts: comments
  made once the code has been traced.
- basic_program(): the BASIC program at the start of most programs.
- is_cartridge(), kernal_rom(), basic_rom() and dos_rom(): for
  disassembling cartridges and ROMs.
- _set_up(), and c64() etc., which put it all together.

Much of the work is done after tracing, by functions added to the CPU's
code analysis functions (cpu.code_analysis_fns, see cpu.py), since it
needs to know which bytes are code and what's known about the registers.
What the set-up chose, and what's found along the way, is kept in the
session's extras (see session.py), under keys starting 'commodore.'.
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

# The styles of name for the memory locations (the names argument of c64()
# etc.)
NAMES = ("descriptive", "commodore")


# ************************************************************************************************
# The machines

class Machine:
    """What commodore.py knows about one machine: its memory locations,
    hardware, ROMs and so on (from commodoretables.py and
    commodoresource.py). c64_machine() etc. make one, and _set_up() gives
    the session its names, hooks and memory regions; _machine() is the
    session's.

    'name' is the machine's short name ("c64", "vic20", "c128", "plus4",
    "pet" or "1541"), which the code checks for what's particular to a
    machine. The other attributes are described where they're set."""

    def __init__(self, name, *, locations, hardware_locations, rom_locations, rom_routines,
                 rom_label_tables, jump_table, inline_string_calls, vectors, colours, colour_registers,
                 control_codes, io_ranges, basic_start, cartridge, basic_rom_addr, regions,
                 basic_tokens=None, basic_prefixed_tokens=None, call_hooks=None):
        self.name = name
        self.basic_tokens = basic_tokens or basic_v2_tokens   # BASIC's keywords, by token from $80 (None for a prefix)
        self.basic_prefixed_tokens = basic_prefixed_tokens or {}  # {prefix: {second byte: keyword}}, for two-byte tokens
        self.call_hooks = call_hooks                # {jump table name: hook}, if not the C64's (see _hooks)
        self.locations = locations                  # RAM, the vectors and the 6502's vectors
        self.hardware_locations = hardware_locations    # the I/O registers, the colour RAM etc.
        self.rom_locations = rom_locations          # data in the ROMs (named with rom_labels)
        self.rom_routines = rom_routines            # RomRoutines: the ROM routines programs call (named with rom_labels)
        self.rom_label_tables = rom_label_tables    # [({address: name}, suffix for a clash)], from Commodore's source
        self.jump_table = jump_table                # KernalCalls, in address order
        self.inline_string_calls = inline_string_calls  # calls followed by a string to print (PRIMM)
        self.vectors = vectors                      # VectorLocations, for code that sets them
        self.colours = colours                      # {colour number: constant name}
        self.colour_registers = colour_registers    # the addresses where a colour stored is named
        self.control_codes = control_codes          # {PETSCII code: description}, for CHROUT's comments
        self.io_ranges = io_ranges                  # [(start, end)]: memory mapped I/O (see io_range()), never defined inline
        self.basic_start = basic_start              # where BASIC programs are loaded (None if there's no BASIC)
        self.cartridge = cartridge                  # (address, style): see is_cartridge(); None if there's no standard header
        self.basic_rom_addr = basic_rom_addr        # where the BASIC ROM starts (None if basic_rom() isn't supported)
        self.regions = regions                      # [(start, end, name)]: the memory regions (see memory_region())

def _kernal_vectors():
    """The Kernal's RAM vectors ($0314-$0333), as Locations, for the C64's
    and VIC-20's list of locations"""
    return [Location(v.addr, 2, v.commodore_name, v.name) for v in c64_vectors if v.name is not None and v.addr >= 0x0314]

def c64_machine():
    """The Commodore 64, with its usual memory configuration ($37: BASIC,
    the Kernal and the I/O)"""
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

# The VIC-20's RAM expansions (the expansion argument of vic20())
VIC20_EXPANSIONS = ("none", "3k", "8k")

def vic20_machine(expansion="none"):
    """The VIC-20, with no RAM expansion ("none"), 3K ("3k", in block 0,
    $0400-$0fff), or 8K or more ("8k", from block 1, $2000). The expansion
    moves the start of BASIC programs, the screen and the colour RAM (see
    vic20())."""
    expanded_8k = (expansion == "8k")
    basic_start = {"none": 0x1001, "3k": 0x0401, "8k": 0x1201}[expansion]
    colour_ram = 0x9400 if expanded_8k else 0x9600
    # The RAM's regions: BASIC's program area is after the screen with 8K or
    # more, and before it otherwise. (The regions of RAM an expansion would
    # add are named whether it's there or not.)
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
        # (The VIC and the VIAs, up to the end of the colour RAM)
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
    usual bank 15: the ROMs, and the I/O at $d000. Its jump table is the
    C64's and its own additions; its MMU's registers at $ff00-$ff04 are I/O
    too."""
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
        basic_tokens=basic_v7_tokens,
        basic_prefixed_tokens=basic_v7_prefixed_tokens,
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
    """The Plus/4 (or C16, or C116, which have the same ROMs), with its
    usual memory map: the ROMs, and the I/O and the TED at $fd00-$ff3f. Its
    jump table is the C64's and its own additions."""
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
        basic_tokens=basic_v35_tokens,
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

# The PET's BASIC versions and screen widths (the basic and columns arguments
# of pet())
PET_BASIC_VERSIONS = (1, 2, 4)
PET_COLUMNS = (40, 80)

def pet_machine(basic=4, columns=40):
    """The PET (or CBM 3000, 4000 or 8000), with BASIC 1, 2 or 4, and a 40 or
    80 column screen (80 columns only with BASIC 4). The BASIC version
    decides the workspace, the ROM routines' addresses and labels, and
    BASIC's keywords; 80 columns adds the CRTC and the 80-column editor's
    workspace and control codes."""
    workspace = pet_workspace_locations[(basic, columns)]
    # The OS workspace and tape buffers in $0200-$03ff (with BASIC 4, the
    # DOS's workspace is at the start of what's the second tape buffer with
    # BASIC 1 and 2)
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

# The 1541's DOS ROMs (the rom argument of drive1541())
DRIVE1541_ROMS = ("1541", "1541-ii")

def drive1541_machine(rom="1541", buffers=range(5)):
    """The 1541 disk drive, with the 1541's DOS ROM (325302-01 and
    901229-05), or the 1541-II's (251968-03, also in the 1541C), and names
    for the buffers given (the numbers 0-4 of those to name: not those the
    program is loaded in, whose code has labels of its own). It has no
    Kernal, BASIC or cartridges."""
    return Machine("1541",
        locations=drive1541_workspace_locations + [drive1541_buffer_locations[n] for n in buffers] + c64_cpu_vectors,
        hardware_locations=drive1541_hardware_locations,
        rom_locations=[],
        rom_routines=drive1541_rom_routines(rom),
        rom_label_tables=[(getattr(commodoresource, "drive%s_rom_labels" % rom.replace("-", "")), "_rom")],
        jump_table=[],
        inline_string_calls=[],
        vectors=drive1541_vectors,
        colours={},
        colour_registers=[],
        control_codes={},
        io_ranges=[(0x1800, 0x1810), (0x1c00, 0x1c10)],
        basic_start=None,
        cartridge=None,
        basic_rom_addr=None,
        call_hooks={},
        regions=[
            (0x0200, 0x0300, "DOS workspace"),
        ] + [(0x0300 + 0x100 * n, 0x0400 + 0x100 * n, "Buffer %d" % n) for n in range(5)] + [
            (0x1800, 0x1810, "VIA 1 (serial bus)"),
            (0x1c00, 0x1c10, "VIA 2 (disk controller)"),
            (0xc000, 0xffe6, "DOS ROM"),
            (0xffe6, 0xfffa, "DOS ROM vectors"),
        ])

def _machine():
    """The Machine chosen for this session (by c64(), vic20(), c128(),
    plus4(), pet() or drive1541()), or the C64 if none has been (e.g. for
    a hook or command used without one: a new Machine each time)"""
    return session.current().extras.get("commodore.machine") or c64_machine()


# ************************************************************************************************
# The names

def official_name(name):
    """Commodore's own name for something (e.g. 'chrout', or with
    names="commodore", 'txttab'), in capitals (CHROUT, TXTTAB) unless
    config.set_upper_case_os_calls(False). py8dis's descriptive names (e.g.
    'tape_buffer') are left as they are."""
    return name.upper() if config.get_upper_case_os_calls() else name

def _name(location, names):
    """A Location's name in the given style ("descriptive" or "commodore"),
    and whether it's Commodore's own (which official_name() gives in
    capitals). A location with no Commodore name has its descriptive name
    in either style, and in the descriptive style a location whose
    descriptive name is Commodore's (e.g. much of the C128's workspace) is
    Commodore's own."""
    if names == "commodore" and location.commodore_name is not None:
        return location.commodore_name, True
    return location.name, location.name == location.commodore_name

# The mnemonics of the 65C02 and the 6502's undocumented opcodes (in each
# assembler's spelling), which assemblers take as instructions, so they can't
# be labels
_OTHER_MNEMONICS = set("""
    bra phx phy plx ply stp stz trb tsb wai
    ahx alr anc ane arr asr axs dcm dcp hlt ins isb isc jam kil lae las lax
    lxa rla rra sax sbx sha shs shx shy slo sre sxa sya tas xaa""".split()) | {
    "%s%d" % (op, bit) for op in ("bbr", "bbs", "rmb", "smb") for bit in range(8)}

def location_names(machine, names="descriptive", rom_labels=True):
    """The names c64() etc. give the machine's memory locations, as a list of
    (address, name, base address or None): one for each byte of each
    location and hardware register (e.g. 'tape_buffer+1', with the base
    address of 'tape_buffer'), and with rom_labels, the data in the ROMs,
    the ROM routines and the labels in Commodore's source for the ROMs (the
    Kernal and BASIC, the C128's screen editor and monitor, and the 1541's
    DOS). Not the Kernal's jump table, which _set_up() gives as subroutines.
    'names' is the style, "descriptive" or "commodore" (see _name()).

    A label in Commodore's source with the same name as a Kernal call or
    another location gets '_rom' added (e.g. PLOT, the routine at $e50a that
    the jump table's PLOT at $fff0 jumps to on the C64, is 'PLOT_ROM'), and a
    label in BASIC's source with the same name as one of those gets '_basic'
    added (e.g. 'STOP_BASIC'), and similarly for the C128's screen editor
    ('_editor') and monitor ('_monitor'). So does a label that's another
    65xx CPU's mnemonic, which an assembler would take as an instruction (e.g.
    the C128's and Plus/4's BASIC have STP and STZ, 'STP_BASIC' and
    'STZ_BASIC'). A location with the same name as a Kernal call gets '_ram'
    added (e.g. the C128's 'jsrfar' routine in RAM is 'JSRFAR_RAM', with
    names="commodore"). An address that already has a name (a location, a
    ROM routine or a Kernal call) gets no label from the source.

    Commodore's own names (the Kernal calls, the labels from its source, and
    with names="commodore" the locations and routines, or in the
    descriptive style a location that has no other name) are given by
    official_name(), so in capitals unless
    config.set_upper_case_os_calls(False), with what's added, e.g.
    'PLOT_ROM'. (Names are compared in lower case, so none differ only in
    case.)"""
    result = []
    jump_table_names = {call.name for call in machine.jump_table}
    def add(location):
        """Add a name for each byte of the location (with '_ram' added if
        it's a Kernal call's name)."""
        name, official = _name(location, names)
        if name in jump_table_names:
            name += "_ram"
        if official:
            name = official_name(name)
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
        # The addresses with names already, which the source's labels don't
        # replace
        named = {addr for addr, _, _ in result} | {call.addr for call in machine.jump_table}
        for routine in machine.rom_routines:
            result.append((routine.addr, _routine_name(routine, names), None))
            named.add(routine.addr)

        # The labels from Commodore's source, each table in turn, with its
        # suffix added to a name that's already used (or is a mnemonic)
        used = {name.lower() for _, name, _ in result} | {call.name for call in machine.jump_table}
        for rom_labels_table, suffix in machine.rom_label_tables:
            for addr in sorted(rom_labels_table):
                if addr in named:
                    continue
                name = rom_labels_table[addr]
                if name in used or name in _OTHER_MNEMONICS:
                    name += suffix
                assert name not in used, name
                used.add(name)
                result.append((addr, official_name(name), None))
    return result

def _routine_name(routine, names):
    """A RomRoutine's name in the given style (see location_names()): with
    names="commodore", Commodore's (by official_name()), if it has one;
    otherwise the descriptive name."""
    if names == "commodore" and routine.commodore_name is not None:
        return official_name(routine.commodore_name)
    return routine.name

def c64_location_names(names="descriptive", rom_labels=True):
    """The names c64() gives memory locations (see location_names())"""
    return location_names(c64_machine(), names, rom_labels)


# ************************************************************************************************
# Comments on Kernal calls
#
# These are subroutine hooks (see subroutine()), called after tracing for
# each call to a Kernal call or ROM routine (and for the code at its own
# address, if it's in the program), with the CPU's state before the call
# instruction and the subroutine's details (its title, on_entry and
# on_exit). They comment the call, e.g. 'Output $93 (clear screen)', and
# where its registers are set and used, e.g. 'A=logical file number'.

def _known_value(state, reg):
    """The value of the register reg ('a', 'x' or 'y') before the call, if
    it's known for certain (the pessimistic state) to have been set by an
    immediate load (e.g. 'lda #n'), else None"""
    binary_addr = state.pessimistic[reg].get_previous_load_imm_operand()
    if binary_addr is None:
        return None
    return memory_binary[binary_addr]

def _hex2(n):
    """A byte in hex, as the assembler writes it, e.g. $1f."""
    return config.get_assembler().hex2(n)

def _hex4(n):
    """A 16-bit number in hex, as the assembler writes it, e.g. $d011."""
    return config.get_assembler().hex4(n)

def _comment_registers(runtime_addr, state, subroutine, entry=True, exit=True):
    """Comment where the registers are set before the call at runtime_addr,
    and used after it, from the subroutine's on_entry and on_exit (as the
    6502's default subroutine hook does), e.g. 'A=logical file number' on
    the 'lda #15' before it. With entry=False or exit=False, those
    comments are left out (for a hook that makes its own). Nothing is
    commented for the subroutine's own code (runtime_addr being the
    subroutine's address)."""
    if subroutine.runtime_addr == runtime_addr:
        return
    if entry and subroutine.on_entry:
        # (On the instruction that last loaded or changed the register)
        for reg in ('a', 'x', 'y'):
            reg_addr = state.optimistic[reg].previous_adjust
            text = subroutine.on_entry.get(reg)
            if reg_addr is not None and text:
                disassembly.comment_binary(reg_addr, reg.upper() + "=" + text, align=Align.INLINE, word_wrap=False, auto_generated=True)
    if exit and subroutine.on_exit:
        # (On the instruction after the call that next uses the register)
        for reg in ('a', 'x', 'y'):
            text = subroutine.on_exit.get(reg)
            next_use = state.next_use[reg]
            if next_use is not None and text:
                disassembly.comment(movemanager.b2r(next_use), reg.upper() + "=" + text, align=Align.INLINE, auto_generated=True)

def _comment_call(runtime_addr, subroutine, text):
    """Comment the call at runtime_addr with the text, inline (but not the
    subroutine's own code)."""
    if subroutine.runtime_addr != runtime_addr:
        disassembly.comment(runtime_addr, text, align=Align.INLINE, word_wrap=False, auto_generated=True)

def _char_description(c):
    """A description of a PETSCII character, e.g. "'a'", or for a control
    code the machine's CHROUT acts on, "$93 (clear screen)", or else just
    its code, e.g. "$80" """
    char = textencoding.PETSCII.char(c)
    if char is not None:
        return "'%s'" % char
    control_codes = _machine().control_codes
    if c in control_codes:
        return "%s (%s)" % (_hex2(c), control_codes[c])
    return _hex2(c)

def default_hook(runtime_addr, state, subroutine):
    """The hook for a Kernal call or ROM routine with no hook of its own (see
    _hooks): comment the registers, and the call with its title."""
    _comment_registers(runtime_addr, state, subroutine)
    if subroutine.title:
        _comment_call(runtime_addr, subroutine, subroutine.title)

def chrout_hook(runtime_addr, state, subroutine):
    """CHROUT's hook: if A is known, comment the call with the character
    output (e.g. "Output 'a'" or 'Output $93 (clear screen)'), and write a
    printable character as one where it's loaded."""
    _comment_registers(runtime_addr, state, subroutine)
    a = _known_value(state, 'a')
    if a is None:
        _comment_call(runtime_addr, subroutine, subroutine.title)
    else:
        _comment_call(runtime_addr, subroutine, "Output " + _char_description(a))
        # A character is written as one where it's loaded (e.g. "lda #'a'",
        # if the assembler can: see Assembler.encoded_char_literal()), unless
        # the operand is already formatted or has an expression
        operand_addr = state.pessimistic['a'].get_previous_load_imm_operand()
        format_hint = session.current().disassembly.format_hint
        if (textencoding.current().char(a) is not None and operand_addr not in format_hint
                and operand_addr not in session.current().classifications.expressions):
            format_hint[operand_addr] = mainformatter.char_formatter

def setlfs_hook(runtime_addr, state, subroutine):
    """SETLFS's hook: name the device number where X is loaded (e.g. 'ldx
    #device_disk_8'), and if A, X and Y are all known, comment the call
    with them, e.g. 'Set logical file 15 to device 8 (disk drive),
    secondary address 15'."""
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
    # (A secondary address of 255 means none)
    secondary = "no secondary address" if y == 255 else "secondary address %d" % y
    _comment_call(runtime_addr, subroutine, "Set logical file %d to %s, %s" % (a, device, secondary))

def _name_data(runtime_addr, name):
    """Label the address with the name, if it has no explicit name yet: the
    first address given a name has it, the next name_2 and so on (e.g.
    'filename', 'filename_2'), counted for the session."""
    labels = session.current().labels.labels
    if runtime_addr in labels and labels[runtime_addr].explicit_names:
        return
    counts = session.current().extras.setdefault("commodore.data_names", {})
    count = counts.get(name, 0) + 1
    counts[name] = count
    label(runtime_addr, name if count == 1 else "%s_%d" % (name, count))

def _loaded_and_unclassified(runtime_addr, length):
    """Whether there's data loaded for the length bytes at the runtime
    address, none of it classified yet (so it can be marked as a string
    without clashing with code or other data)"""
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
    """SETNAM's hook: the filename is the A bytes at X/Y. Where X and Y are
    loaded, write them as the low and high bytes of the filename's label
    (see xy_addr()). If its length and address are known, mark the filename
    as a PETSCII string, labelled 'filename' (if it's loaded and isn't
    classified yet), and comment the call with it, e.g. 'Set the filename
    to "i0"'."""
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
    # The filename's text, for the comment, if it's all printable PETSCII
    # characters other than '"' (else the comment gives its length)
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
    """LOAD's hook: if A is known, comment the call as 'Load a file' (A=0)
    or 'Verify a file' (A=1), and A where it's loaded. X and Y aren't
    commented where they're set, only where they're used after the
    call."""
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
    """SAVE's hook: where A is loaded, write it as the name of the zero page
    pointer to the start address; and where X and Y are loaded, as the low
    and high bytes of the end address's label (see xy_addr())."""
    _comment_registers(runtime_addr, state, subroutine)
    # A is the zero page address of the pointer to the start address: name it
    a_addr = state.pessimistic['a'].get_previous_load_imm_operand()
    if a_addr is not None:
        auto_expr(movemanager.b2r(a_addr), get_label(memory_binary[a_addr], a_addr, binary_addr_type=BinaryAddrType.BINARY_ADDR_IS_AT_LABEL_USAGE))
    # (xy_addr() writes the expressions; the address itself isn't used)
    xy_addr(state.pessimistic['x'].get_previous_load_imm_operand(), state.pessimistic['y'].get_previous_load_imm_operand())
    _comment_call(runtime_addr, subroutine, subroutine.title)

def _carry_hook(read_text, set_text):
    """A hook for a call that reads something into X/Y with carry set, and
    sets it from X/Y with carry clear (e.g. PLOT). The call is commented
    with read_text or set_text, depending on the carry flag, if it's known
    (else with the call's title); set_text can use {x} and {y}, the values
    of X and Y if they're known (else 'X' and 'Y'). When it reads, X and Y
    are commented where they're next used, rather than where they're set."""
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

# The hooks for PLOT, MEMTOP, MEMBOT and VECTOR, which read or set with the
# carry flag
plot_hook   = _carry_hook("Read the cursor position into X (row) and Y (column)", "Move the cursor to row {x}, column {y}")
memtop_hook = _carry_hook("Read the top of memory into X/Y", "Set the top of memory to X/Y")
membot_hook = _carry_hook("Read the bottom of memory into X/Y", "Set the bottom of memory to X/Y")
vector_hook = _carry_hook("Copy the Kernal vectors to the list at X/Y", "Set the Kernal vectors from the list at X/Y")

def setmsg_hook(runtime_addr, state, subroutine):
    """SETMSG's hook: if A is known, comment the call with the Kernal
    messages it shows, e.g. 'Show only Kernal error messages'."""
    _comment_registers(runtime_addr, state, subroutine)
    a = _known_value(state, 'a')
    if a is None:
        _comment_call(runtime_addr, subroutine, subroutine.title)
        return
    # (Bit 7 shows the control messages, e.g. 'SEARCHING FOR', and bit 6 the
    # error messages, e.g. 'I/O ERROR #4')
    shown = [kind for bit, kind in ((0x80, "control"), (0x40, "error")) if a & bit]
    if not shown:
        text = "Turn off Kernal messages"
    else:
        text = "Show only Kernal %s messages" % " and ".join(shown) if len(shown) == 1 else "Show Kernal control and error messages"
    _comment_call(runtime_addr, subroutine, text)

def strout_hook(runtime_addr, state, subroutine):
    """The hook for BASIC's STROUT, which prints the zero-terminated string
    at A/Y: where A and Y are loaded, write them as the low and high bytes
    of the string's label (see xy_addr()), and mark the string as a
    zero-terminated PETSCII string, if it's loaded and isn't classified
    yet."""
    _comment_registers(runtime_addr, state, subroutine)
    string_addr = xy_addr(state.pessimistic['a'].get_previous_load_imm_operand(), state.pessimistic['y'].get_previous_load_imm_operand())
    if string_addr is not None and _loaded_and_unclassified(string_addr, 1):
        stringz(string_addr, encoding="petscii")
    _comment_call(runtime_addr, subroutine, subroutine.title)

# The hooks for the Kernal calls that have one of their own, by name (the
# others have default_hook()). A machine's call_hooks replaces this (e.g. the
# PET's, whose LOAD and SAVE aren't these).
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
    program can set on the machine, with the vector's name in the given
    style (None for the 6502's own vectors, which have none here)"""
    result = {}
    for vector in _machine().vectors:
        name = None
        if vector.name is not None:
            name = official_name(vector.commodore_name) if names == "commodore" else vector.name
        result[vector.addr] = (name, vector.description, vector.handler)
    return result

def pre_trace_writing_to_vector(p):
    """A program setting one of the vectors (e.g. the IRQ vector), an effect
    pattern (see snippethelper.vector_pattern()): before tracing, label the
    handler (e.g. 'irq_handler', then 'irq_handler_2' etc), unless it has a
    name already, and trace it."""
    _, description, handler = _vector_names(session.current().extras["commodore.names"])[p.binding('vector')]

    def new_name():
        """A name for a new handler: the first for a vector is e.g.
        'irq_handler', the next 'irq_handler_2' (counted for the session)."""
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
    of its configuration register, at $ff00, e.g. c128_bank_configurations[0]
    for bank 0): 'MMU' ($ff00-$ff04, in every configuration), 'I/O',
    'character ROM', 'BASIC ROM', 'Kernal ROM' (which includes the screen
    editor), 'internal ROM', 'external ROM' (the function ROMs), or 'RAM 0' to
    'RAM 3' (RAM 2 and 3 are RAM 0 and 1 on a C128 with 128K). $0000-$03ff is
    always RAM 0, since the Kernal makes it common RAM."""
    # The configuration register's bits: 0 is $d000-$dfff (0 for I/O, 1 for
    # what bits 4-5 choose, with the character ROM for the Kernal's); 1 is $4000-$7fff (0 for BASIC's ROM, 1 for RAM); 2-3 are
    # $8000-$bfff, and 4-5 $c000-$ffff (0 for BASIC's ROM or the Kernal's, 1
    # for the internal function ROM, 2 for the external one, 3 for RAM); and
    # 6-7 are the RAM bank
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
        # (Bit 0 set: what bits 4-5 choose, but the character ROM rather
        # than the Kernal's)
        if not configuration & 0x01:
            return "I/O"
        return "character ROM" if high == "Kernal ROM" else high
    return high

def c128_configuration_description(configuration):
    """A description of an MMU configuration, e.g. 'bank 15 (RAM 0, BASIC
    ROM, Kernal ROM, I/O)', or for one that isn't one of the Kernal's banks,
    e.g. 'RAM 0, I/O'."""
    def at(addr):
        return c128_memory(configuration, addr)
    ram = "RAM %d" % (configuration >> 6)
    # The ROMs, in address order, then the I/O or character ROM
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

# The MMU's configuration register (at $ff00 and $d500), and its load
# configuration registers ($ff01-$ff04: writing to one sets the configuration
# to the preconfiguration register at $d501-$d504)
_MMU_CONFIGURATION_REGISTERS = (0xff00, 0xd500)
_MMU_LOAD_CONFIGURATION_REGISTERS = range(0xff01, 0xff05)

def _c128_mmu_writes():
    """The C128's Banking.writes (see _banking()): [(binary location,
    register address, configuration or None)] for each instruction that
    sets the MMU configuration, once the code has been traced. The
    configuration is the value stored to $ff00 or $d500, if it's known; or
    None for a store of an unknown value, or to one of the load
    configuration registers ($ff01-$ff04), whose preconfiguration isn't
    known. (Read-modify-write instructions, e.g. INC $ff00, and stores to
    addresses that aren't known, e.g. indexed ones, are left out.)"""
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

def _c128_comment_mmu_writes(writes, known):
    """The C128's Banking.comment: comment each instruction in writes (see
    _c128_mmu_writes()) that sets the MMU configuration to a known value,
    e.g. 'Set the MMU to bank 0 (RAM 0 only)', or a preconfiguration, e.g.
    'Set the MMU to preconfiguration A (as set at $d501)'. ('known', the
    configuration each instruction runs with, isn't needed here.)"""
    for binary_loc, register, configuration in writes:
        if register in _MMU_LOAD_CONFIGURATION_REGISTERS:
            text = "Set the MMU to preconfiguration {0} (as set at ${1:04x})".format("ABCD"[register - 0xff01], 0xd501 + register - 0xff01)
        elif configuration is not None:
            text = "Set the MMU to " + c128_configuration_description(configuration)
        else:
            continue
        disassembly.comment_binary(binary_loc, text, align=Align.INLINE, auto_generated=True)

# ************************************************************************************************
# The C64's memory configuration: the 6510's port at $01

# The usual value of the port: the BASIC and Kernal ROMs, and the I/O
C64_USUAL_CONFIGURATION = 0x37

# The heading for the names of addresses in another configuration than the
# usual one in the "Memory locations" list (since their memory regions are
# the usual configuration's)
C64_OTHER_CONFIGURATIONS_HEADING = "Other memory configurations"

def c64_memory(configuration, addr):
    """What the C64 has at addr with the 6510's port at $01 set to the given
    configuration (its bits 0-2: LORAM, HIRAM and CHAREN): 'BASIC ROM'
    ($a000-$bfff), 'Kernal ROM' ($e000-$ffff), 'I/O' or 'character ROM'
    ($d000-$dfff), or 'RAM'. (Without a cartridge, which changes these.)"""
    mode = configuration & 7
    if 0xa000 <= addr < 0xc000:
        return "BASIC ROM" if mode & 3 == 3 else "RAM"
    if 0xd000 <= addr < 0xe000:
        if mode & 3 == 0:
            return "RAM"
        return "I/O" if mode & 4 else "character ROM"
    if addr >= 0xe000:
        return "Kernal ROM" if mode & 2 else "RAM"
    return "RAM"

def c64_configuration_description(configuration):
    """A description of a C64 memory configuration (the value of the 6510's
    port at $01), e.g. 'RAM, I/O' ($35), 'RAM only' ($34), or for the usual
    one ($37), 'the usual one (RAM, BASIC ROM, Kernal ROM, I/O)'."""
    parts = [part for part in (c64_memory(configuration, 0xa000), c64_memory(configuration, 0xe000), c64_memory(configuration, 0xd000)) if part != "RAM"]
    text = "RAM" + (", " + ", ".join(parts) if parts else " only")
    if configuration & 7 == C64_USUAL_CONFIGURATION & 7:
        text = "the usual one (" + text + ")"
    return text

# The 6510's port (its data register), and the opcodes that read-modify-write
# it in zero page or absolute: INC and DEC (with the change each makes)
C64_PORT = 0x01
_INC_DEC = {0xe6: 1, 0xee: 1, 0xc6: -1, 0xce: -1}
# STA zp and STA addr, and the bytes of 'lda $01' (zero page and absolute)
_STA = (0x85, 0x8d)
_LDA_PORT = ((0xa5, 0x01), (0xad, 0x01, 0x00))
_ACCUMULATOR_LOGIC = {0x29: lambda a, n: a & n, 0x09: lambda a, n: a | n, 0x49: lambda a, n: a ^ n}     # AND, ORA, EOR #n

def _c64_port_writes():
    """The C64's Banking.writes (see _banking()): [(binary location, $01,
    value)] for each instruction that writes the 6510's port at $01, once
    the code has been traced. The value is the value stored, if it's known;
    else a function of the port's value before it, giving the value after,
    for INC and DEC, and for a store of A after 'lda $01' and immediate
    ANDs, ORAs and EORs (e.g. 'lda $01 : and #$f8 : ora #$05 : sta $01');
    else None (e.g. for 'lsr $01', or a store of a value that isn't
    known)."""
    cpu = session.current().cpu
    memory_binary = session.current().memory.binary
    result = []
    for run in cpu.straight_runs():
        for write in cpu.memory_writes(run):
            if write.target != C64_PORT:
                continue
            binary_addr = write.binary_addr
            opcode = memory_binary[binary_addr]
            value = None
            if write.read_modify_write:
                if opcode in _INC_DEC:
                    value = lambda before, step=_INC_DEC[opcode]: (before + step) & 0xff
            elif write.value is not None:
                value = write.value
            elif opcode in _STA:
                value = _c64_port_logic(run, run.index(binary_addr))
            move_id = session.current().moves.move_id_for_binary_addr[binary_addr]
            result.append((memorymanager.BinaryLocation(BinaryAddr(binary_addr), move_id), C64_PORT, value))
    return result

def _c64_port_logic(run, index):
    """For a store of A to $01 at run[index] (run is a straight run of code,
    see Cpu6502.straight_runs()): if A is the port's value with immediate
    ANDs, ORAs or EORs ('lda $01', then e.g. 'and #$f8 : ora #$05'), a
    function of the port's value before it, giving the value stored; else
    None."""
    memory_binary = session.current().memory.binary
    # Work back from the store, collecting the ANDs, ORAs and EORs (in the
    # order they run), until the 'lda $01'; any other instruction first means
    # A isn't known this way
    steps = []
    for binary_addr in reversed(run[:index]):
        opcode = memory_binary[binary_addr]
        if opcode in _ACCUMULATOR_LOGIC:
            steps.insert(0, (_ACCUMULATOR_LOGIC[opcode], memory_binary[binary_addr + 1]))
            continue
        if any(tuple(memory_binary[binary_addr:binary_addr + len(lda)]) == lda for lda in _LDA_PORT):
            def value(before, steps=steps):
                for operation, n in steps:
                    before = operation(before, n)
                return before & 0xff
            return value
        return None
    return None

def _c64_comment_port_writes(writes, known):
    """The C64's Banking.comment: comment each instruction in writes (see
    _c64_port_writes()) that sets the C64's memory configuration to a known
    value, e.g. 'Set the memory configuration to RAM, I/O ($35)': a value
    stored, or for INC, DEC etc., the configuration after it, where the one
    before it is known ('known' is {binary address: configuration} for the
    instructions that run with a known one, see _flow_ranges())."""
    for binary_loc, _, value in writes:
        if callable(value):
            before = known.get(binary_loc.binary_addr)
            value = value(before) if before is not None else None
        if value is None:
            continue
        disassembly.comment_binary(binary_loc, "Set the memory configuration to {0} (${1:02x})".format(c64_configuration_description(value), value),
                                   align=Align.INLINE, auto_generated=True)

def c64_configuration(start, end, configuration):
    """Say that the code from start to end (runtime addresses, end exclusive)
    runs with the C64's memory configuration (the value of the 6510's port at
    $01) set to the given one, e.g. $35 for RAM and the I/O (with BASIC and
    the Kernal switched out), rather than the usual $37: e.g. a routine
    whose caller switches the ROMs out. An address it uses that's something
    else there (e.g. RAM rather than a ROM or the I/O) isn't given its usual
    name, and a call to a ROM routine that's switched out isn't commented as
    one (see c64_memory()). (The configuration the code sets with $01 is
    followed by itself: see c64().) Call it after c64().

    The range is recorded, as binary addresses, in the session's extras
    (see _flow_ranges(), which uses it). It stops with an error if c64()
    hasn't been called, or for a bad configuration or range."""
    if _machine().name != "c64":
        utils.die("commodore.c64_configuration(): call commodore.c64() first")
    if not utils.is_integer_type(configuration) or not 0 <= configuration < 0x100:
        utils.die("commodore.c64_configuration(): the configuration must be 0-255, not {0!r}".format(configuration))
    binary_start, binary_end = _checked_range("c64_configuration", start, end)
    session.current().extras.setdefault("commodore.c64_configurations", []).append((binary_start, binary_end, configuration))

def _checked_range(command, start, end):
    """The binary start and end of the runtime addresses start to end (end
    exclusive), for c128_bank() or c64_configuration() (named by command,
    for the errors). Stops with an error unless both are integers from 0 to
    $10000 and start is before end, or if start or end - 1 isn't an
    unambiguous runtime address (see movemanager.r2b_checked())."""
    for addr in (start, end):
        if not utils.is_integer_type(addr) or not 0 <= addr <= 0x10000:
            utils.die("commodore.{0}(): the addresses must be between 0 and $10000, not {1!r}".format(command, addr))
    if not start < end:
        utils.die("commodore.{0}(): the start ({1}) must be before the end ({2})".format(command, _hex4(start), _hex4(end)))
    binary_start = movemanager.r2b_checked(start).binary_addr
    binary_end = movemanager.r2b_checked(end - 1).binary_addr + 1
    return binary_start, binary_end

# ************************************************************************************************
# Memory configurations: the C128's MMU, and the C64's port at $01

# How a machine's memory configuration is set and what it maps (see
# _banking()), so that the same code can follow the C128's MMU and the C64's
# port at $01:
# - 'writes' is a function giving the code that sets it (see
#   _c128_mmu_writes() and _c64_port_writes());
# - 'memory' is a function giving what's at an address in a configuration
#   (c128_memory() or c64_memory());
# - 'usual' is the configuration the names are for (the C128's bank 15, or
#   the C64's $37);
# - 'comment' is a function that comments the code that sets it;
# - 'heading' is the heading for the names in other configurations, in the
#   "Memory locations" list;
# - 'fixed_key' is the key in the session's extras for the ranges the control
#   file gives (with c128_bank() or c64_configuration()), as [(binary start,
#   binary end, configuration)];
# - 'far_targets_key' is the key for the code that starts with a
#   configuration of its own, as {binary address: configuration} (the C128's
#   JSRFAR and JMPFAR targets; the C64 has none).
Banking = collections.namedtuple("Banking", ["writes", "memory", "usual", "comment", "heading", "fixed_key", "far_targets_key"])

def _banking():
    """The Banking for the session's machine (the C128 or the C64), or None
    if it has none"""
    name = _machine().name
    if name == "c128":
        return Banking(_c128_mmu_writes, c128_memory, c128_bank_configurations[15], _c128_comment_mmu_writes,
                       C128_OTHER_BANKS_HEADING, "commodore.c128_banks", "commodore.c128_far_targets")
    if name == "c64":
        return Banking(_c64_port_writes, c64_memory, C64_USUAL_CONFIGURATION, _c64_comment_port_writes,
                       C64_OTHER_CONFIGURATIONS_HEADING, "commodore.c64_configurations", "commodore.c64_far_targets")
    return None

# The 6502's opcodes that end a block of code (RTS, RTI, BRK, JMP (ind)),
# and its conditional branches
_BLOCK_END_OPCODES = (0x60, 0x40, 0x00, 0x6c)
_BRANCH_OPCODES = (0x10, 0x30, 0x50, 0x70, 0x90, 0xb0, 0xd0, 0xf0)

def _flow_ranges(writes, banking):
    """Follow the memory configuration (the C128's MMU configuration, or the
    C64's port at $01, as 'banking' says, see _banking()) through the code
    as it runs, once it's been traced. Returns (ranges, known): ranges is
    [(binary start, binary end, configuration)] for the runs of
    instructions that run with a known configuration, and known is {binary
    address: configuration} for each instruction that does.

    'writes' is banking.writes()'s list of the instructions that set the
    configuration (see _c128_mmu_writes()). A write's value is a
    configuration, None if it isn't known, or a function of the
    configuration before it (e.g. for INC $01), which is only known where
    that is.

    The configuration is followed from an instruction that sets it to a
    known value to the next instruction, the target of a branch or JMP, and
    a subroutine called with JSR, up to the next instruction that sets it.
    The return from a JSR comes back with the configuration the call was
    made with, unless the subroutine always returns with one it sets itself,
    or returns with different ones (see summary()); after a call that
    prints the string after it (PRIMM),
    the code after the string has it. A call to code that isn't traced
    (e.g. a ROM routine) is taken to leave the configuration as it was.

    Where code can be reached with different configurations, or from an
    entry point, code with nothing before it, or code the program refers to
    another way (e.g. a vector it sets), its configuration isn't known (so
    it's taken to be the usual one, e.g. the C128's bank 15). Code in a
    c128_bank() or c64_configuration() range has the range's configuration
    where it's reached from outside the range (or where it isn't reached at
    all), and follows the code within it; a JSRFAR or JMPFAR target (see
    pre_trace_far_call()) starts with its bank's."""
    cpu = session.current().cpu
    memory_binary = session.current().memory.binary
    labels = session.current().labels.labels
    moves = session.current().moves.move_id_for_binary_addr
    # (The configuration of code that can be reached with different ones, or
    # where it isn't known)
    UNKNOWN = object()

    # The code's instructions, and how control flows from each
    instructions = []
    for range_start, range_end in memorymanager.loaded_ranges():
        binary_addr = range_start
        while binary_addr < range_end:
            c = classification.get_classification(binary_addr)
            if c is None or c is classification.INSIDE_A_CLASSIFICATION:
                binary_addr += 1
                continue
            if c.is_code(binary_addr):
                instructions.append((binary_addr, c.length()))
            binary_addr += c.length()
    is_instruction = {binary_addr for binary_addr, _ in instructions}

    def code_at(runtime_addr, move_id):
        """The binary addresses of the instructions at a jump's, branch's or
        call's target, preferring the given move (the instruction's): none
        if the target isn't traced code."""
        binary_addr = cpu.get_target_binary_addr_preferring_given_move_id(RuntimeAddr(runtime_addr), move_id) if runtime_addr < 0x10000 else []
        return [b for b in binary_addr if b in is_instruction]

    # Each instruction's successors: [(binary address, the JSR's target if
    # it's the return from a call (or 'call' for the call itself), else
    # None)]
    successors = {}
    predecessors = collections.defaultdict(set)
    for binary_addr, length in instructions:
        opcode = memory_binary[binary_addr]
        nexts = []
        if opcode in _BLOCK_END_OPCODES:
            pass
        elif opcode == 0x4c:
            # JMP addr
            nexts = [(n, None) for n in code_at(memory_binary[binary_addr + 1] + 256 * memory_binary[binary_addr + 2], moves[binary_addr])]
        elif opcode == 0x20:
            # JSR: the call, and the return (with the target, so the return
            # can use the subroutine's summary(); None if it isn't traced)
            targets = code_at(memory_binary[binary_addr + 1] + 256 * memory_binary[binary_addr + 2], moves[binary_addr])
            after = binary_addr + length
            c = classification.get_classification(after) if after < 0x10000 else None
            if after not in is_instruction and isinstance(c, classification.String) and after + c.length() in is_instruction:
                # (The call prints the string after it, e.g. PRIMM, and
                # returns after the string)
                after += c.length()
            if after in is_instruction and not classification.get_classification(binary_addr).is_block_end():
                nexts.append((after, targets[0] if targets else None))
            nexts += [(n, "call") for n in targets]
        else:
            # The next instruction, and a branch's target (its offset is
            # signed, from the instruction after it)
            if binary_addr + length in is_instruction and not classification.get_classification(binary_addr).is_block_end():
                nexts.append((binary_addr + length, None))
            if opcode in _BRANCH_OPCODES:
                offset = memory_binary[binary_addr + 1]
                runtime = movemanager.b2r(BinaryAddr(binary_addr)) + 2 + (offset - 256 if offset >= 128 else offset)
                nexts += [(n, None) for n in code_at(runtime & 0xffff, moves[binary_addr])]
        successors[binary_addr] = nexts
        for n, _ in nexts:
            predecessors[n].add(binary_addr)

    # Where the configuration isn't known on entry: the entry points, code
    # with no other code before it, and code the program refers to other
    # than by branching, jumping or calling to it (e.g. a vector it sets)
    seeds = {}
    for binary_addr, _ in instructions:
        label = labels.get(movemanager.b2r(BinaryAddr(binary_addr)))
        referred = label is not None and any(ref.binary_addr not in predecessors[binary_addr] for ref in label.references)
        if binary_addr in cpu.explicit_entry_points or not predecessors[binary_addr] or referred:
            seeds[binary_addr] = UNKNOWN
    # A JSRFAR or JMPFAR target (see pre_trace_far_call()) starts with its
    # bank's configuration, even if it's one of the above (e.g. code with
    # nothing before it)
    for binary_addr, configuration in session.current().extras.get(banking.far_targets_key, {}).items():
        if binary_addr in is_instruction:
            seeds[binary_addr] = configuration if seeds.get(binary_addr, configuration) is UNKNOWN or binary_addr not in seeds else seeds[binary_addr]

    # The ranges the control file gives (c128_bank() or c64_configuration())
    banks = list(session.current().extras.get(banking.fixed_key, []))
    def bank_range(binary_addr):
        """The c128_bank() or c64_configuration() range (binary start,
        binary end, configuration) that binary_addr is in (the first given,
        if there's more than one), or None"""
        for r in banks:
            if r[0] <= binary_addr < r[1]:
                return r
        return None

    # {binary address: what the instruction sets the configuration to}
    write_values = {binary_loc.binary_addr: configuration for binary_loc, _, configuration in writes}

    # Work out the configuration each instruction runs with (its 'in'),
    # merging what reaches it: a known configuration if every way in agrees
    # (None is nothing yet)
    def merge(a, b):
        if a is None:
            return b
        return a if a == b else UNKNOWN

    # A subroutine's effect on the configuration (see summary()): CALLER if
    # it returns with the one it was called with
    CALLER = object()
    summaries = {}
    in_progress = set()

    def propagate(seeds, follow_calls):
        """{binary address: the configuration it runs with} for the code
        reached from the seeds ({binary address: configuration}), following
        calls into subroutines (and using the c128_bank() and
        c64_configuration() ranges) if follow_calls. (Without, it's for
        summary(), which only counts the configurations the subroutine sets
        itself: a call within it returns with its summary(), and the
        subroutine isn't followed into.)

        This is a work list: an instruction whose 'in' changes is looked at
        again, until nothing changes."""
        def bank_range_used(binary_addr):
            return bank_range(binary_addr) if follow_calls else None
        configuration_in = {}
        work = collections.deque()
        for binary_addr, value in seeds.items():
            if bank_range_used(binary_addr) is not None:
                # (The c128_bank() or c64_configuration() range says what it
                # runs with)
                value = bank_range_used(binary_addr)[2]
            configuration_in[binary_addr] = merge(configuration_in.get(binary_addr), value)
            work.append(binary_addr)
        while work:
            binary_addr = work.popleft()
            # The configuration after the instruction: its 'in', unless it
            # sets it
            value = configuration_in[binary_addr]
            if binary_addr in write_values:
                written = write_values[binary_addr]
                if callable(written):
                    # (e.g. INC $01: only known if the value before it is)
                    value = written(value) if utils.is_integer_type(value) else UNKNOWN
                else:
                    value = written if written is not None else UNKNOWN
            for n, call in successors[binary_addr]:
                if call == "call" and not follow_calls:
                    continue
                out = value
                if call is not None and call != "call":
                    # The return from a subroutine: with the configuration it
                    # was called with, unless it sets its own
                    effect = summary(call)
                    out = value if effect is CALLER else effect
                r = bank_range_used(n)
                # (Code in a c128_bank() or c64_configuration() range runs
                # with its configuration when it's reached from outside the
                # range)
                new = merge(configuration_in.get(n), r[2] if r is not None and r is not bank_range_used(binary_addr) else out)
                if new is not configuration_in.get(n) and new != configuration_in.get(n):
                    configuration_in[n] = new
                    work.append(n)
        return configuration_in

    def summary(target):
        """What the subroutine at target (a binary address) does to the
        configuration: CALLER if every RTS it reaches has the one it was
        called with (or it reaches none), a configuration if they all have
        that one (e.g. 'lda #$3f : sta $ff00 : rts'), else UNKNOWN. Worked
        out once for each subroutine; a recursive call, while it's being
        worked out, is taken to be CALLER."""
        if target in summaries:
            return summaries[target]
        if target in in_progress:
            return CALLER
        in_progress.add(target)
        result = None
        for binary_addr, value in propagate({target: CALLER}, follow_calls=False).items():
            if memory_binary[binary_addr] == 0x60:
                result = merge(result, value)
        in_progress.discard(target)
        summaries[target] = CALLER if result is None else result
        return summaries[target]

    configuration_in = propagate(seeds, follow_calls=True)
    known = {binary_addr: value for binary_addr, value in configuration_in.items() if utils.is_integer_type(value)}

    # The ranges: each run of consecutive instructions with the same known
    # configuration (code in a range the control file gives, but not
    # reached, has the range's)
    result = []
    for binary_addr, length in instructions:
        value = configuration_in.get(binary_addr)
        if value is None and bank_range(binary_addr) is not None:
            value = bank_range(binary_addr)[2]
        if value is None or value is UNKNOWN or value is CALLER:
            continue
        if result and result[-1][1] == binary_addr and result[-1][2] == value:
            result[-1] = (result[-1][0], binary_addr + length, value)
        else:
            result.append((binary_addr, binary_addr + length, value))
    return result, known

def _c128_configuration_at(binary_addr, ranges):
    """The memory configuration the code at binary_addr runs with (the
    C128's MMU configuration, or the C64's port at $01: this is used for
    both), from the ranges [(binary start, binary end, configuration)] (the
    first that covers it), or None if it's not known (so it's taken to be
    the usual one, e.g. the C128's bank 15)."""
    for start, end, configuration in ranges:
        if start <= binary_addr < end:
            return configuration
    return None

# The heading for the names of addresses in another configuration than bank
# 15 in the "Memory locations" list (since their memory regions are bank
# 15's)
C128_OTHER_BANKS_HEADING = "Other banks"

def _name_by_configuration(ranges, banking):
    """Where code that runs with another memory configuration (in the
    ranges, see _c128_configuration_at()) uses an address that's something
    else in that configuration than in the usual one (e.g. the C128's bank
    15, or the C64's $37: RAM rather than I/O or a ROM, as banking.memory
    says), give the address a plain name there (e.g. 'ld020'), as a local
    label for that instruction, rather than its usual name (e.g.
    'vic_border_colour'). These names are listed under banking.heading in
    the "Memory locations" list. Only names commodore.py gives are
    replaced (the optional labels, and the names of the ROM routines and
    Kernal calls), not the control file's."""
    if not ranges:
        return
    machine = _machine()
    optional_labels = session.current().disassembly.optional_labels
    # The names c128() etc. give that can be replaced: the ROM routines' and
    # the Kernal's jump table's (whose calls aren't commented there either,
    # see _unless_mapped_out())
    routine_names = collections.defaultdict(set)
    for routine in machine.rom_routines:
        routine_names[routine.addr].update({routine.name, _routine_name(routine, "commodore")})
    for call in machine.jump_table:
        routine_names[call.addr].add(official_name(call.name))
    usual = banking.usual
    for runtime_addr, label in sorted(session.current().labels.labels.items()):
        if runtime_addr not in optional_labels and runtime_addr not in routine_names:
            continue
        # (Any other explicit name is the control file's, so it's kept)
        given = {name.text for names in label.explicit_names.values() for name in names}
        if not given <= routine_names.get(runtime_addr, set()):
            continue
        # Each use of the address from code that runs with a configuration
        # in which it's something else
        for reference in label.references:
            configuration = _c128_configuration_at(reference.binary_addr, ranges)
            if configuration is None or banking.memory(configuration, runtime_addr) == banking.memory(usual, runtime_addr):
                continue
            c = classification.get_classification(reference.binary_addr)
            length = c.length() if c is not None and c is not classification.INSIDE_A_CLASSIFICATION else 1
            disassembly.add_local_label(RuntimeAddr(runtime_addr), utils.force_case("l%04x" % runtime_addr),
                                        reference.binary_addr, reference.binary_addr + length, heading=banking.heading)

# ************************************************************************************************
# Drive code in another machine's program (see drive1541_code())

# Each piece of drive code drive1541_code() is given: where it is in the
# binary, how long it is, where it runs in the drive, its move ID and the
# drive's ROM ("1541" or "1541-ii"). They're kept in the session's extras,
# as "commodore.drive_code".
DriveCode = collections.namedtuple("DriveCode", ["binary_start", "length", "runtime_start", "move_id", "rom"])

# The heading for the drive's names in the "Memory locations" list
DRIVE_CODE_HEADING = "1541 drive"

def _drive_code_at(binary_addr):
    """The DriveCode that binary_addr (a binary address) is in, or None"""
    for drive_code in session.current().extras.get("commodore.drive_code", []):
        if drive_code.binary_start <= binary_addr < drive_code.binary_start + drive_code.length:
            return drive_code
    return None

def _drive_code_names():
    """Where drive code (see drive1541_code()) uses an address outside the
    drive code itself, it gets the 1541's name (e.g. 'job_queue', rather
    than the machine's name for the address), with '_drive' added to a name
    that's also the machine's or the control file's (see
    disassembly.add_range_optional_labels()). Calls from it to the DOS
    ROM's routines are commented with their titles. (Run once the code has
    been traced, as one of the CPU's code analysis functions.)"""
    drive_codes = session.current().extras.get("commodore.drive_code", [])
    if not drive_codes:
        return
    labels = session.current().labels.labels
    memory_binary = session.current().memory.binary
    names_style = session.current().extras.get("commodore.names", "descriptive")
    rom_labels = session.current().extras.get("commodore.rom_labels", True)

    # The names used elsewhere: the machine's, and the control file's
    # (In lower case: see location_names())
    used = {name.lower() for _, name, _ in location_names(_machine(), names_style, rom_labels)}
    used |= {call.name for call in _machine().jump_table}
    for label_ in labels.values():
        for names in label_.explicit_names.values():
            used |= {name.text.lower() for name in names}

    for drive_code in drive_codes:
        start, end = drive_code.binary_start, drive_code.binary_start + drive_code.length
        # (A buffer the drive code is in isn't named: one with drive code in
        # any of its bytes)
        buffers = [n for n in range(5) if not any(_drive_loaded(addr)[0] for addr in range(0x0300 + 0x100 * n, 0x0400 + 0x100 * n))]
        machine = drive1541_machine(drive_code.rom, buffers)
        # The 1541's names, except for the addresses in drive code. (A name
        # with a base address, e.g. 'buffer_2+1', is made from its base's
        # name where it's used, so only the base names need '_drive'.)
        names = {}
        for addr, name, base in location_names(machine, names_style, rom_labels):
            if addr in names or _drive_loaded(addr)[0]:
                continue
            if base is None:
                if name.lower() in used:
                    name += "_DRIVE" if name.isupper() else "_drive"
                if not name.isupper():
                    # (Commodore's names are as official_name() gives them)
                    name = utils.force_case(name)
            names[addr] = (name, base)
        disassembly.add_range_optional_labels(start, end, names, DRIVE_CODE_HEADING)

        # Calls to the DOS ROM's routines (JSRs and JMPs from the drive code)
        titles = {routine.addr: routine.title for routine in machine.rom_routines}
        for runtime_addr, title in titles.items():
            label_ = labels.get(runtime_addr)
            if label_ is None:
                continue
            for reference in label_.references:
                if start <= reference.binary_addr < end and memory_binary[reference.binary_addr] in (0x20, 0x4c):
                    disassembly.comment_binary(memorymanager.BinaryLocation(BinaryAddr(reference.binary_addr), drive_code.move_id), title,
                                               align=Align.INLINE, auto_generated=True)

def drive1541_code(runtime_addr, binary_addr, length, rom="1541"):
    """Code for the 1541 disk drive in another machine's program (e.g. a C64
    fast loader's drive code, which it sends to the drive with M-W and runs
    with M-E or a job): length bytes at binary_addr, that run at runtime_addr
    in the drive. Call it after c64() etc.

    The bytes are moved to runtime_addr (see move(); the move ID is
    returned), and traced from there. Where the drive code uses an address
    outside itself, it gets the 1541's name (as drive1541() gives, e.g.
    'job_queue' or 'via2_disk_control', under the heading '1541 drive', with
    '_drive' added to a name that's also the machine's), rather than the
    machine's name for that address. Calls from it to the DOS ROM's routines
    are commented, and not taken to be calls to the machine's ROM (whose
    hooks don't run there). Its jobs are commented, and a JUMP or EXECUTE
    job's code is traced if it's in drive code too (see drive1541()). rom is
    as for drive1541().

    The first call adds _drive_code_names() and _drive1541_analysis() to
    the CPU's code analysis functions, and registers the job queue's effect
    patterns. Stops with an error if there's no machine yet, or it's the
    1541's own disassembly."""
    if _machine().name == "1541":
        utils.die("commodore.drive1541_code(): this is already the 1541's disassembly (drive1541())")
    if session.current().extras.get("commodore.machine") is None:
        utils.die("commodore.drive1541_code(): call c64() etc. first")
    if rom not in DRIVE1541_ROMS:
        utils.die("commodore.drive1541_code(): rom must be one of {0}, not {1!r}".format(", ".join(repr(r) for r in DRIVE1541_ROMS), rom))
    move_id = move(runtime_addr, binary_addr, length)
    extras = session.current().extras
    drive_codes = extras.setdefault("commodore.drive_code", [])
    drive_codes.append(DriveCode(binary_addr, length, runtime_addr, move_id, rom))
    if len(drive_codes) == 1:
        session.current().cpu.code_analysis_fns.append(_drive_code_names)
        session.current().cpu.code_analysis_fns.append(_drive1541_analysis)
        _register_job_patterns()
    with move_id:
        entry(runtime_addr)
    return move_id

def _mapped_out(binary_addr, runtime_addr):
    """Whether the code at binary_addr runs with a memory configuration (the
    C128's MMU, or the C64's port at $01, see _banking()) in which
    runtime_addr is something else than usual (e.g. RAM rather than the
    Kernal ROM or I/O), so a call to a ROM routine there, or a store to an
    I/O register, isn't one. (Always False for the other machines.) During
    tracing, only c128_bank()'s and c64_configuration()'s configurations
    are known; once the code has been traced, those the code sets too (see
    _banking_analysis()).

    It's always True for drive code (see drive1541_code()), which runs in
    the drive, so the machine's ROM routines and I/O aren't there."""
    if _drive_code_at(binary_addr) is not None:
        # (Drive code, see drive1541_code(), runs in the drive)
        return True
    banking = _banking()
    if banking is None:
        return False
    extras = session.current().extras
    # (The ranges _banking_analysis() found, once it's run; until then, the
    # control file's)
    ranges = extras.get("commodore.banking_ranges")
    if ranges is None:
        ranges = extras.get(banking.fixed_key, [])
    configuration = _c128_configuration_at(binary_addr, ranges)
    return configuration is not None and banking.memory(configuration, runtime_addr) != banking.memory(banking.usual, runtime_addr)

def _unless_mapped_out(hook):
    """A subroutine hook for a ROM routine or Kernal call that runs hook,
    except for a call from code that runs with the ROM mapped out, or from
    drive code (see _mapped_out()), where it does nothing."""
    def wrapper(runtime_addr, state, subroutine):
        binary_addr, _ = movemanager.r2b(runtime_addr)
        if binary_addr is not None and _mapped_out(binary_addr, subroutine.runtime_addr):
            return
        hook(runtime_addr, state, subroutine)
    return wrapper

def _inline_string_hook(target, caller):
    """The tracing hook (see Cpu.subroutine_hooks) for a call that prints
    the string after it (PRIMM): it marks the zero-terminated string after
    the JSR at caller, and returns the address after it, where tracing
    continues. For a call from code that runs with the Kernal ROM mapped
    out (see _mapped_out()), it's an ordinary call, and tracing continues
    after the JSR."""
    binary_addr, _ = movemanager.r2b(caller)
    if binary_addr is not None and _mapped_out(binary_addr, target):
        return caller + 3
    return stringz_hook(target, caller)

def _banking_analysis():
    """The C128's MMU, or the C64's port at $01 (see _banking()): comment the
    code that sets the memory configuration, and name the addresses code
    uses according to the configuration it runs with: after the code sets it
    (see _flow_ranges()), or as c128_bank() or c64_configuration() says.
    (Run once the code has been traced, as one of the CPU's code analysis
    functions, before the calls are commented and the colours substituted.)
    The ranges are kept in the session's extras, as
    "commodore.banking_ranges", for _mapped_out()."""
    banking = _banking()
    writes = banking.writes()
    ranges, known = _flow_ranges(writes, banking)
    banking.comment(writes, known)
    # (The configuration the code sets comes first, since it changes the one
    # c128_bank() or c64_configuration() gives)
    ranges += list(session.current().extras.get(banking.fixed_key, []))
    session.current().extras["commodore.banking_ranges"] = ranges
    _name_by_configuration(ranges, banking)

def c128_bank(start, end, bank=None, *, configuration=None):
    """Say that the code from start to end (runtime addresses, end exclusive)
    runs with the C128's MMU set to the given bank (0-15, as the Kernal
    numbers them, see c128_bank_configurations), or configuration (the value
    of its configuration register, at $ff00), rather than the usual bank 15.
    An address it uses that's something else there (e.g. in bank 0, RAM
    rather than I/O or a ROM) isn't given its name in bank 15: e.g. 'lda
    $d020' is 'lda ld020', not 'lda vic_border_colour'. (Only the names
    c128() gives; and $0000-$03ff is RAM 0 in every bank.) A call to a ROM
    routine that's mapped out isn't commented as one, and a call to PRIMM
    isn't followed by a string (see _mapped_out()). Call it after
    c128().

    The range is recorded, as binary addresses, in the session's extras
    (see _flow_ranges(), which uses it). It stops with an error if c128()
    hasn't been called, if it isn't given either a bank or a configuration
    (or is given both), or for a bad bank, configuration or range."""
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
    binary_start, binary_end = _checked_range(command, start, end)
    session.current().extras.setdefault("commodore.c128_banks", []).append((binary_start, binary_end, configuration))


def _far_call(p):
    """For a match of the JSRFAR/JMPFAR effect pattern (see
    register_snippets()): (bank, target address, whether it's JMPFAR,
    whether the target is traced). The target is traced if it's in the
    program, i.e. loaded, and RAM 0 in that bank (RAM 2 is RAM 0 on a C128
    with 128K), with the bank one of the Kernal's 16."""
    bank = p.value('bank')
    target = p.value('lo') + 256*p.value('hi')
    is_jump = p.memory_binary[p.get_binary_address('call')] == 0x4c
    traced = _is_loaded(target) and bank < 16 and c128_memory(c128_bank_configurations[bank], target) in ("RAM 0", "RAM 2")
    return bank, target, is_jump, traced

def pre_trace_far_call(p):
    """A C128 program setting up JSRFAR or JMPFAR's bank and address at
    $02-$04 with known values, then calling it (an effect pattern): before
    tracing, if the address is in the program (see _far_call()), name it
    (e.g. 'far_call_target', unless it has a name already) and trace it,
    and record that it runs with its bank's configuration (see
    _flow_ranges())."""
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
    # (The target runs with its bank's configuration, see _flow_ranges())
    binary_addr, _ = movemanager.r2b(RuntimeAddr(target))
    if binary_addr is not None:
        session.current().extras.setdefault("commodore.c128_far_targets", {})[binary_addr] = c128_bank_configurations[bank]

def post_trace_far_call(p):
    """After tracing: comment the set-up of a JSRFAR or JMPFAR (e.g. 'Call
    far_call_target in bank 0'), before it and set off by blank lines, and
    if the target is traced, write the address's loads as its name's low
    and high bytes (unless they're written another way already)."""
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

    # (A blank line before it, unless it starts at a label with a name)
    labels = session.current().labels.labels
    runtime_addr = movemanager.b2r(start.binary_addr)
    if not (runtime_addr in labels and labels[runtime_addr].explicit_names.get(start.move_id)):
        p.blank_once(start)
    disassembly.comment_binary(start, "{0} {1} in bank {2}".format("Jump to" if is_jump else "Call", target_text, bank),
                               indent=1, align=Align.AFTER_LABEL, auto_generated=True)
    p.blank_once(end)

# ************************************************************************************************
# The 1541's job queue

def _drive1541_job(p):
    """For a match of a job pattern (see _register_job_patterns()): (job
    number, job code name, track, sector), the track and sector None if
    they're not known, or None if the value stored isn't a job code, or the
    code isn't the 1541's (in a disassembly for another machine, only the
    drive code given by drive1541_code() is). The job number is the job
    queue's address that's written ($00-$04)."""
    code = p.value('code')
    if code not in drive1541_job_codes:
        return None
    if _machine().name != "1541" and _drive_code_at(p.extent()[0].binary_addr) is None:
        return None
    return p.binding('job'), drive1541_job_codes[code], p.value('track'), p.value('sector')

def _drive_loaded(runtime_addr):
    """Whether there's code for the 1541 at runtime_addr (one of its
    addresses): in the 1541's own disassembly, if data is loaded there; in
    another machine's, if drive code (see drive1541_code()) is there. Returns
    (whether it is, its move ID)."""
    if _machine().name == "1541":
        return _is_loaded(runtime_addr), None
    for drive_code in session.current().extras.get("commodore.drive_code", []):
        if drive_code.runtime_start <= runtime_addr < drive_code.runtime_start + drive_code.length:
            return True, drive_code.move_id
    return False, None

def pre_trace_drive1541_job(p):
    """Code writing a job code to the 1541's job queue (an effect pattern):
    before tracing, for a job that runs the code in its buffer (JUMP or
    EXECUTE), label and trace that code (e.g. 'job_3_code', unless it has a
    name already), if it's loaded."""
    job = _drive1541_job(p)
    if job is None:
        return
    n, name, _, _ = job
    # (Job n's buffer is at $0300 + $100 * n)
    code = 0x0300 + 0x100 * n
    loaded, move_id = _drive_loaded(code)
    if name in ("job_jump", "job_execute") and loaded:
        if vector_handler_name(code) is None:
            label(code, "job_%d_code" % n, move_id)
        p.entry(code)

def post_trace_drive1541_job(p):
    """After tracing: comment the job (e.g. 'Job 0: read track 18, sector 1
    into buffer 0 ($0300)'), before the code that sets it up and set off by
    blank lines, and name its job code as a constant where it's loaded
    (e.g. 'lda #job_read')."""
    job = _drive1541_job(p)
    if job is None:
        return
    n, name, track, sector = job
    code = 0x0300 + 0x100 * n
    buffer = "buffer {0} (${1:04x})".format(n, code)
    if name in ("job_jump", "job_execute") and vector_handler_name(code) is not None:
        buffer = "buffer {0} ({1})".format(n, vector_handler_name(code))
    if track is not None and sector is not None:
        block = "track {0}, sector {1}".format(track, sector)
    else:
        block = "the job's track and sector"
    on_track = "track {0}".format(track) if track is not None else "the job's track"
    text = {
        "job_read":    "read {0} into {1}".format(block, buffer),
        "job_write":   "write {0} to {1}".format(buffer, block),
        "job_verify":  "verify {0} against {1}".format(buffer, block),
        "job_seek":    "find a header on {0}".format(on_track),
        "job_bump":    "move the head to track 1 (bump)",
        "job_jump":    "run the code in {0}".format(buffer),
        "job_execute": "move the head to {0}, then run the code in {1}".format(on_track, buffer),
    }[name]
    operand = p.value_operand('store')
    if operand is not None:
        disassembly.add_constant(p.value('code'), name, format=Format.HEX)
        classification.add_expression(operand, name, force=False)
    start, end = p.extent()
    labels = session.current().labels.labels
    runtime_addr = movemanager.b2r(start.binary_addr)
    if not (runtime_addr in labels and labels[runtime_addr].explicit_names.get(start.move_id)):
        p.blank_once(start)
    disassembly.comment_binary(start, "Job {0}: {1}".format(n, text), indent=1, align=Align.AFTER_LABEL, auto_generated=True)
    p.blank_once(end)

def _register_job_patterns():
    """Register the effect patterns for jobs written to the 1541's job queue
    (see register_snippets()): one for each of the five jobs, n, matching a
    store to its place in the queue ($00 + n, the 'store' line), with the
    optional stores of its track and sector ($06 + 2n and $07 + 2n) before
    it. (The DOS's workspace has room for a sixth, at $05 with its track and
    sector at $10-$11, but the 1541 has no buffer 5, so they're unused.) (Called by register_snippets() for the 1541, and by
    drive1541_code() for drive code in another machine's program.)"""
    for n in range(5):
        register_snippet(pre_trace_drive1541_job, post_trace_drive1541_job, """
track
?   [${0:02x}] = track
sector
?   [${1:02x}] = sector
store
    [job = ${2:02x}] = code
""".format(6 + 2 * n, 7 + 2 * n, n))

# ************************************************************************************************
# The 1541's job results and VIAs

_DRIVE1541_END_JOB = 0xf969     # ERRR, which ends a job with the result in A

def _drive1541_in_scope(binary_addr):
    """Whether the code at binary_addr is the 1541's: any code in its own
    disassembly (drive1541()), or drive code in another machine's (see
    drive1541_code())."""
    return _machine().name == "1541" or _drive_code_at(binary_addr) is not None

def _a_set_by(run, k):
    """The binary address of the instruction before run[k] in the straight
    run of code that last changed A (one that does more than read it), or
    None"""
    for binary_addr in reversed(run[:k]):
        if classification.get_classification(binary_addr).reg_changes['a'] not in "-U":
            return binary_addr
    return None

def _via_bits_text(register, set_mask, clear_mask):
    """What setting and clearing the bits of a 1541 VIA port does, e.g.
    'Turn the LED on', or None if none of them are outputs it knows.
    register is the port's address ($1800 or $1c00, see
    drive1541_via_bits), and set_mask and clear_mask the bits that are
    known to be set and cleared. A two-bit field of VIA 2's port B (the
    stepper motor's phase, or the bit rate) is described only if both its
    bits are known."""
    phrases = []
    for bit, (_, output) in sorted(drive1541_via_bits[register].items()):
        if output is not None:
            if set_mask & (1 << bit):
                phrases.append(output[0])
            elif clear_mask & (1 << bit):
                phrases.append(output[1])
    if register == 0x1c00:
        # Two-bit fields: the head stepper's phase (bits 0-1), and the bit
        # rate (bits 5-6: 3 for tracks 1-17, 2 for 18-24, 1 for 25-30, 0 for
        # 31 on)
        mask = 3
        if (set_mask | clear_mask) & mask == mask:
            phrases.append("set the stepper motor's phase to {0}".format(set_mask & mask))
        mask = 3 << 5
        if (set_mask | clear_mask) & mask == mask:
            rate = (set_mask & mask) >> 5
            phrases.append("set the bit rate to {0} (for tracks {1})".format(rate, ("31-35", "25-30", "18-24", "1-17")[rate]))
    if not phrases:
        return None
    text = ", ".join(phrases)
    return text[0].upper() + text[1:]

def _drive1541_analysis():
    """The 1541's job results and VIAs, in its code (see _drive1541_in_scope()):
    name the job result compared with after reading the job queue (e.g. 'cmp
    #job_ok'), or given to ERRR to end a job (e.g. 'lda #job_ok : jmp
    end_job'); comment what a store to a VIA port does (e.g. 'Turn the LED
    on', after 'lda $1c00 : ora #$08'), and a test of one of its bits (e.g.
    'Test CLOCK IN', for 'lda $1800 : and #$04'). (Run once the code has been
    traced, as one of the CPU's code analysis functions.)"""
    cpu = session.current().cpu
    memory_binary = session.current().memory.binary
    moves = session.current().moves.move_id_for_binary_addr

    def comment(binary_addr, text):
        disassembly.comment_binary(memorymanager.BinaryLocation(BinaryAddr(binary_addr), moves[binary_addr]), text,
                                   align=Align.INLINE, auto_generated=True)

    def name_result(operand_addr):
        """Name the job result at the operand as a constant (e.g. 'job_ok'),
        commented with the error the DOS reports for it."""
        value = memory_binary[operand_addr]
        if value in drive1541_job_results:
            name, description = drive1541_job_results[value]
            disassembly.add_constant(value, name, description)
            classification.add_expression(operand_addr, name, force=False)

    def absolute(binary_addr):
        """The 16-bit operand of the instruction at binary_addr."""
        return memory_binary[binary_addr + 1] + 256 * memory_binary[binary_addr + 2]

    for run in cpu.straight_runs():
        for k, binary_addr in enumerate(run):
            if not _drive1541_in_scope(binary_addr):
                continue
            opcode = memory_binary[binary_addr]
            if opcode == 0xc9:
                # 'cmp #n' after reading the job queue: A was last set by
                # 'lda zp', 'lda zp,x', 'lda addr' or 'lda addr,x' of $00-$04
                source = _a_set_by(run, k)
                if source is not None and ((memory_binary[source] in (0xa5, 0xb5) and memory_binary[source + 1] <= 4) or
                                           (memory_binary[source] in (0xad, 0xbd) and absolute(source) <= 4)):
                    name_result(binary_addr + 1)
            elif opcode in (0x20, 0x4c) and absolute(binary_addr) == _DRIVE1541_END_JOB:
                # 'lda #n : jmp end_job' (or JSR)
                source = _a_set_by(run, k)
                if source is not None and memory_binary[source] == 0xa9:
                    name_result(source + 1)
            elif opcode in (0x8d, 0x8e, 0x8c) and absolute(binary_addr) in drive1541_via_bits:
                # STA, STX or STY addr to a VIA port: work out which bits are
                # known to be set and cleared
                register = absolute(binary_addr)
                set_mask = clear_mask = 0
                # 'lda register', then 'ora #n' and 'and #n', then 'sta register'
                i = k - 1
                while opcode == 0x8d and i >= 0 and memory_binary[run[i]] in (0x09, 0x29):
                    i -= 1
                if opcode == 0x8d and i >= 0 and i < k - 1 and memory_binary[run[i]] == 0xad and absolute(run[i]) == register:
                    for j in range(i + 1, k):
                        n = memory_binary[run[j] + 1]
                        if memory_binary[run[j]] == 0x09:
                            set_mask |= n
                            clear_mask &= ~n
                        else:
                            clear_mask |= ~n & 0xff
                            set_mask &= n
                elif k > 0:
                    # A known value (of the register stored, from the state
                    # after the instruction before the store)
                    value = cpu.cpu_states[run[k - 1]].pessimistic["axy"[(0x8d, 0x8e, 0x8c).index(opcode)]].value
                    if value is None:
                        continue
                    set_mask, clear_mask = value, ~value & 0xff
                else:
                    continue
                text = _via_bits_text(register, set_mask, clear_mask)
                if text is not None:
                    comment(binary_addr, text)
            elif opcode == 0x29 and k > 0 and memory_binary[run[k - 1]] == 0xad and absolute(run[k - 1]) in drive1541_via_bits:
                # 'lda register : and #n', testing bits (only if every bit
                # tested is one it knows)
                bits = drive1541_via_bits[absolute(run[k - 1])]
                n = memory_binary[binary_addr + 1]
                names = [bits[bit][0] for bit in range(8) if n & (1 << bit) and bit in bits]
                if names and all(n & (1 << bit) == 0 or bit in bits for bit in range(8)):
                    comment(binary_addr, "Test " + " and ".join(names))
            elif opcode == 0x2c and absolute(binary_addr) in drive1541_via_bits and 7 in drive1541_via_bits[absolute(binary_addr)]:
                # 'bit register' (N is bit 7)
                comment(binary_addr, "Test " + drive1541_via_bits[absolute(binary_addr)][7][0])

def register_snippets():
    """Register commodore's snippets with the current session (once per
    session; _set_up() calls it): the effect patterns for the machine's
    JSRFAR and JMPFAR calls (if it has them), the 1541's jobs (for the
    1541) and the vectors a program can set."""
    extras = session.current().extras
    if extras.get("commodore.snippets_registered"):
        return
    extras["commodore.snippets_registered"] = True

    # On the C128, a call to JSRFAR or JMPFAR with its bank and address set at
    # $02-$04, e.g. 'lda #0 : sta $02 : lda #>target : sta $03 : lda #<target
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

    # In the 1541, code writing a job code to the job queue ($00-$04, one for
    # each buffer), with the job's track and sector ($06-$0f) if they're set
    # too (an effect pattern for each job)
    if _machine().name == "1541":
        _register_job_patterns()

    # Code setting one of the vectors, in any order, with any registers (an
    # effect pattern)
    register_snippet(pre_trace_writing_to_vector, post_trace_writing_to_vector, vector_pattern(vector.addr for vector in _machine().vectors))

# ************************************************************************************************
# The VIC-II's interrupts (C64 and C128)

# The VIC-II's registers for its interrupts: its control register 1 (whose
# bit 7 is bit 8 of the raster line), the raster line to interrupt at, and
# its interrupt status and enable registers
_VIC_CONTROL_1 = 0xd011
_VIC_RASTER_LINE = 0xd012
_VIC_INTERRUPT_STATUS = 0xd019
_VIC_INTERRUPT_ENABLE = 0xd01a
_VIC_REGISTERS = (_VIC_CONTROL_1, _VIC_RASTER_LINE, _VIC_INTERRUPT_STATUS, _VIC_INTERRUPT_ENABLE)

# The VIC-II's interrupts, by bit (of $d019 and $d01a)
_VIC_INTERRUPTS = ("raster", "sprite-background collision", "sprite-sprite collision", "light pen")

def _vic_interrupts_text(value):
    """The VIC-II's interrupts whose bits are set in value (bits 0-3, at
    least one of them), e.g. 'raster interrupt', 'raster and light pen
    interrupts'"""
    names = [name for bit, name in enumerate(_VIC_INTERRUPTS) if value & (1 << bit)]
    if len(names) == 1:
        return names[0] + " interrupt"
    return ", ".join(names[:-1]) + " and " + names[-1] + " interrupts"

def _vic_interrupt_analysis():
    """Comment the code that sets up the VIC-II's interrupts: a store of a
    known value to its raster line register ($d012), e.g. 'Raster interrupt
    at line 100', with bit 8 from a store to $d011 in the same straight run
    of code, if it's known; to its interrupt enable register ($d01a), e.g.
    'Enable only the VIC-II's raster interrupt'; and to its interrupt status
    register ($d019), e.g. 'Acknowledge the VIC-II's raster interrupt', as
    does a read-modify-write instruction (e.g. 'asl $d019'). (Not where the
    C128's MMU or the C64's port at $01 maps the I/O out: see
    _mapped_out(). Run once the code has been traced, as one of the CPU's
    code analysis functions, for the C64 and C128.)"""
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

        # Bit 8 of the raster line: bit 7 of what's stored to $d011, if
        # that's known, or set by an 'and #n' or 'ora #n' just before (and
        # only if every store to $d011 in the run agrees)
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

        # Comment each write (bits 0-3 of the enable and status registers
        # are the interrupts)
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
    """A tokenised BASIC line's text (data, its bytes) as LIST shows it (in
    the C64's upper case/graphics character set), with the machine's BASIC
    keywords for the tokens (except in quotes or after REM), including the
    C128's two-byte ones ($ce or $fe, then a second byte), {pi} for pi,
    and other codes as e.g. {$93}"""
    tokens = _machine().basic_tokens
    prefixed_tokens = _machine().basic_prefixed_tokens
    result = ""
    in_quotes = False
    in_rem = False
    i = 0
    while i < len(data):
        c = data[i]
        i += 1
        if c == ord('"'):
            in_quotes = not in_quotes
        if c >= 0x80 and not in_quotes and not in_rem:
            if c == BASIC_TOKEN_PI:
                result += "{pi}"
            elif c in prefixed_tokens and i < len(data) and data[i] in prefixed_tokens[c]:
                result += prefixed_tokens[c][data[i]]
                i += 1
            elif c - 0x80 < len(tokens) and tokens[c - 0x80] is not None:
                result += tokens[c - 0x80]
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
    bytes that end it; or None if there isn't a valid BASIC program there.

    Each line is a link to the next line (the address after its zero byte),
    its line number, then its text, ending with a zero. It's valid if all of
    it is loaded, each link is beyond its line's number (so the lines go up
    through memory), each line number is at most 63999, each line's only
    zero is at its end, and there are at most 1000 lines."""
    def u8(addr):
        """The byte at a runtime address, or None if it isn't loaded."""
        if addr > 0xffff:
            return None
        binary_addr, _ = movemanager.r2b(RuntimeAddr(addr))
        if binary_addr is None or not memorymanager.is_data_loaded_at_binary_addr(binary_addr):
            return None
        return memory_binary[binary_addr]
    def u16(addr):
        """The word (low byte first) at a runtime address, or None."""
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
    BASIC programs start on the machine: $0801 on the C64; $1001 on the
    VIC-20, or $0401 or $1201 with a RAM expansion; $1c01 on the C128;
    $1001 on the Plus/4; $0401 on the PET), e.g. the one-line 'SYS' program
    at the start of most machine code programs. Each line is labelled (e.g.
    'basic_line_10'), its link to the next line and its line number are
    words, and its text is bytes for the tokens and PETSCII strings, listed
    in a comment, e.g. '; 10 SYS2061'. An address SYS calls in the loaded
    data is an entry point, named 'sys_entry' unless it already has a name
    (so to give it another, name it before calling this, or c64()).

    Returns the address after the program, or None (classifying nothing) if
    there isn't a valid BASIC program there. Stops with an error if no
    address is given for the 1541, which has no BASIC."""
    if runtime_addr is None:
        runtime_addr = _machine().basic_start
        if runtime_addr is None:
            utils.die("commodore.basic_program(): the {0} has no BASIC, so give the program's address".format(_machine().name))
    found = _basic_lines(runtime_addr)
    if found is None:
        return None
    lines, end = found
    # Each line's label, e.g. 'basic_line_10' (or 'basic_line_10_2' for a
    # second line 10), and 'basic_end' for the two zeros at the end
    names = {}
    def line_name(number):
        """The label for the next line with this line number."""
        name = "basic_line_%d" % number
        names[name] = names.get(name, 0) + 1
        return name if names[name] == 1 else "%s_%d" % (name, names[name])
    line_names = [line_name(number) for _, _, number, _ in lines] + ["basic_end"]

    for i, (addr, link, number, text) in enumerate(lines):
        # The line's label and listing, its link (written as the next line's
        # label) and its line number (in decimal)
        label(addr, line_names[i])
        auto_comment(addr, "%d %s" % (number, _basic_line_text(text)))
        word(addr)
        expr(addr, line_names[i + 1])
        word(addr + 2)
        decimal(addr + 2)
        # The text: runs of characters as strings, the rest (tokens and
        # other codes) as bytes. (Bytes from $80 are characters in quotes or
        # after REM, and tokens elsewhere.)
        a = addr + 4
        in_quotes = False
        in_rem = False
        run_start = None
        def end_run(run_end):
            """Mark the run of characters up to run_end, if any, as a
            PETSCII string."""
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

        # SYS to an address in the loaded data: the digits after the first
        # SYS token (after any spaces or '(')
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

    On the C64 a cartridge is at $8000, and on the VIC-20 at $a000, starting
    with the addresses of its cold and warm start code, then a signature in
    PETSCII ('CBM80' on the C64, 'A0CBM' on the VIC-20). On the C128 and the
    Plus/4 a function ROM is at $8000 (or $c000 for the C128's internal
    one), starting with its cold and warm start code (usually JMPs), then an
    ID byte (1 to start it automatically) and 'CBM' in ASCII. (The PET's
    expansion ROMs have no standard header.) The header is taken to be at
    the machine's Machine.cartridge address, $8000 on the C128.

    Stops with an error for the 1541 and the PET. Call it after c64()
    etc."""
    if _machine().name == "1541":
        utils.die("commodore.is_cartridge(): the 1541 has no cartridges")
    if _machine().cartridge is None:
        utils.die("commodore.is_cartridge(): the PET's expansion ROMs have no standard header")
    addr, signature = _machine().cartridge
    if signature == "CBM":
        # The C128's and Plus/4's: code at +0 and +3, then the ID and 'CBM'
        label(addr, "cartridge_cold_start")
        entry(addr)
        label(addr + 3, "cartridge_warm_start")
        entry(addr + 3)
        label(addr + 6, "cartridge_id")
        byte(addr + 6)
        label(addr + 7, "cartridge_signature")
        string(addr + 7, 3, encoding="ascii")
    else:
        # The C64's and VIC-20's: vectors at +0 and +2 (their targets named,
        # unless they have names already), then the signature
        label(addr, "cartridge_cold_start_vector")
        code_ptr(addr, label_name=None if _has_name(memorymanager.get_u16_runtime(RuntimeAddr(addr))) else "cartridge_cold_start")
        label(addr + 2, "cartridge_warm_start_vector")
        code_ptr(addr + 2, label_name=None if _has_name(memorymanager.get_u16_runtime(RuntimeAddr(addr + 2))) else "cartridge_warm_start")
        label(addr + 4, "cartridge_signature")
        string(addr + 4, len(signature), encoding="petscii")
    auto_comment(addr, "Cartridge header")

def _has_name(runtime_addr):
    """Whether the runtime address has an explicit name (e.g. from label()
    or entry(), not just an optional label)"""
    labels = session.current().labels.labels
    return runtime_addr in labels and bool(labels[runtime_addr].explicit_names)

def kernal_rom():
    """For a disassembly of a Kernal ROM (loaded at $e000, or $c000 on the
    C128 and Plus/4): trace the code from the Kernal's jump table (each entry
    named, e.g. 'CHROUT') and the 6502's NMI, reset and IRQ vectors (each
    target named, e.g. 'reset_entry', unless it has a name already). (For
    the 1541's DOS ROM, use dos_rom().) Call it after c64() etc."""
    if _machine().name == "1541":
        utils.die("commodore.kernal_rom(): the 1541 has no Kernal (use dos_rom())")
    for call in _machine().jump_table:
        if _is_loaded(call.addr):
            entry(call.addr, official_name(call.name))
    for addr, name in ((0xfffa, "nmi_entry"), (0xfffc, "reset_entry"), (0xfffe, "irq_entry")):
        target = memorymanager.get_u16_runtime(RuntimeAddr(addr))
        has_name = _has_name(target) or target in session.current().disassembly.optional_labels
        code_ptr(addr, label_name=None if has_name else name)

def basic_rom():
    """For a disassembly of a BASIC ROM (loaded at $a000 on the C64, $c000 on
    the VIC-20, $4000 on the C128 and $8000 on the Plus/4): trace the code
    from its cold and warm start vectors (or JMPs), and name its signature.
    Stops with an error for the 1541 and the PET. Call it after c64()
    etc."""
    machine = _machine()
    base = machine.basic_rom_addr
    if _machine().name == "1541":
        utils.die("commodore.basic_rom(): the 1541 has no BASIC")
    if base is None:
        utils.die("commodore.basic_rom(): the PET's BASIC ROM has no vectors to trace from (use entry())")
    if machine.cartridge[1] == "CBM":
        # The C128's and Plus/4's: JMPs to the cold and warm start code (and
        # on the C128 the IRQ code), then on the Plus/4 an ID byte and 'CBM'
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
    # The C64's and VIC-20's: the cold and warm start vectors (their targets
    # named, unless they have names already), then the signature
    for offset, name in ((0, "basic_cold_start"), (2, "basic_warm_start")):
        target = memorymanager.get_u16_runtime(RuntimeAddr(base + offset))
        label(base + offset, name + "_vector")
        code_ptr(base + offset, label_name=None if _has_name(target) else name)
    label(base + 4, "basic_signature")
    string(base + 4, encoding="petscii")

def dos_rom():
    """For a disassembly of the 1541's DOS ROM (loaded at $c000, after
    drive1541()): trace the code from the vectors at its end (the format
    routine, turning off the motor, and the user commands U1 and U2, each
    named, e.g. 'format'; U3-U8's, to $0500-$050f in buffer 2, are named but
    not traced) and the 6502's NMI, reset and IRQ vectors. Only the vectors
    that are loaded are used, and a target with a name already keeps it."""
    if _machine().name != "1541":
        utils.die("commodore.dos_rom(): call drive1541() first")
    for addr, vector_name, name in drive1541_rom_vectors:
        if not _is_loaded(addr):
            continue
        label(addr, vector_name)
        target = memorymanager.get_u16_runtime(RuntimeAddr(addr))
        if name is None:
            word(addr)
            continue
        has_name = _has_name(target) or target in session.current().disassembly.optional_labels
        code_ptr(addr, label_name=None if has_name else name)
    for addr, name in ((0xfffa, "nmi_entry"), (0xfffc, "reset_entry"), (0xfffe, "irq_entry")):
        if _is_loaded(addr):
            target = memorymanager.get_u16_runtime(RuntimeAddr(addr))
            has_name = _has_name(target) or target in session.current().disassembly.optional_labels
            code_ptr(addr, label_name=None if has_name else name)


# ************************************************************************************************
# The machines' set up

def _set_up(command, machine, names, rom_labels):
    """What c64(), vic20(), c128(), plus4(), pet() and drive1541() do, for
    the Machine: command is the command's name (for the errors), and names
    and rom_labels are as for c64().

    It records the machine for the session (stopping with an error if one
    has been chosen already), sets PETSCII as the text encoding, registers
    the snippets, and names the memory regions, the I/O and the memory
    locations (as optional labels). It makes the Kernal calls and (with
    rom_labels) the ROM routines subroutines, with hooks that comment their
    calls, and sets up the colours' names, the code analysis functions for
    the memory configuration, the 1541 and the VIC-II's interrupts, and the
    BASIC program at the start, if one is loaded there."""
    if names not in NAMES:
        utils.die("commodore.{0}(): names must be one of {1}, not {2!r}".format(command, ", ".join(repr(n) for n in NAMES), names))
    extras = session.current().extras
    if extras.get("commodore.machine") is not None:
        utils.die("commodore.{0}(): this session's machine has already been chosen".format(command))
    extras["commodore.machine"] = machine
    # (So config.set_upper_case_os_calls() can't be called after this, since
    # the names are made now)
    extras["os_calls_named"] = True
    extras["commodore.names"] = names
    extras["commodore.rom_labels"] = rom_labels

    config.set_text_encoding("petscii")
    register_snippets()
    for start, end, name in machine.regions:
        memory_region(start, end, name)
    for start, end in machine.io_ranges:
        io_range(start, end)

    # The memory locations' names (not defined inline in the I/O)
    for addr, name, base in location_names(machine, names, rom_labels):
        optional_label(addr, name, base, definable_inline=not any(start <= addr < end for start, end in machine.io_ranges))

    # The Kernal's jump table, as subroutines with hooks that comment the
    # calls (named with optional labels, not traced as entry points: for a
    # Kernal ROM, see kernal_rom())
    for call in machine.jump_table:
        hooks = _hooks if machine.call_hooks is None else machine.call_hooks
        subroutine(call.addr, official_name(call.name), call.title, None, call.on_entry, call.on_exit, hook=_unless_mapped_out(hooks.get(call.name, default_hook)), is_entry_point=False)
    # A call that prints the string after it (PRIMM) continues after the
    # string
    for addr in machine.inline_string_calls:
        cpu = session.current().cpu
        if cpu is None:
            utils.die("commodore.{0}(): call load() first".format(command))
        cpu.subroutine_hooks[RuntimeAddr(addr)] = _inline_string_hook
    # The ROM routines, likewise (STROUT's hook marks its string)
    if rom_labels:
        for routine in machine.rom_routines:
            subroutine(routine.addr, _routine_name(routine, names), routine.title, None, routine.on_entry, routine.on_exit,
                       hook=_unless_mapped_out(strout_hook if routine.commodore_name == "strout" else default_hook), is_entry_point=False)

    # Colours stored in the colour registers (e.g. 'lda #colour_black : sta
    # vic_border_colour'), but not where the register is mapped out
    for addr in machine.colour_registers:
        for reg in "axy":
            session.current().trace.substitute_constant_list.append(cpu6502.SubConst("st%s $%04x" % (reg, addr), reg, machine.colours, True,
                                                                                     condition=lambda binary_addr, addr=addr: not _mapped_out(binary_addr, addr)))

    # The C128's MMU, or the C64's port at $01 (see _banking_analysis()),
    # before the calls are commented and the colours substituted, since they
    # depend on it (see _mapped_out())
    if _banking() is not None:
        code_analysis_fns = session.current().cpu.code_analysis_fns
        code_analysis_fns.insert(code_analysis_fns.index(session.current().cpu.substitute_constants), _banking_analysis)
    # The 1541's job results and VIAs (see _drive1541_analysis())
    if machine.name == "1541":
        session.current().cpu.code_analysis_fns.append(_drive1541_analysis)
    # The VIC-II's interrupts (see _vic_interrupt_analysis())
    if machine.name in ("c64", "c128"):
        session.current().cpu.code_analysis_fns.append(_vic_interrupt_analysis)

    # The BASIC program at the start, if there is one
    if machine.basic_start is not None and _is_loaded(machine.basic_start):
        basic_program(machine.basic_start)

def c64(names="descriptive", rom_labels=True):
    """Name and comment a C64 program's use of the Kernal, the hardware and
    the memory locations used by the OS and BASIC:

    - memory regions, for the list of memory locations at the top;
    - names for the memory locations (only output if used): the 6510's I/O
      port, zero page, the OS and BASIC workspace, the vectors, the screen
      and sprite pointers, the VIC-II, the SID, the CIAs and the colour RAM;
      with names="commodore", Commodore's names (e.g. 'EXTCOL' rather than
      'vic_border_colour');
    - the Kernal's jump table, e.g. 'CHROUT', with comments where it's
      called (e.g. 'Output $93 (clear screen)'), and where the registers are
      set for it and used after it;
    - with rom_labels (the default), names for the routines in the C64's
      ROMs that programs call (e.g. 'kernal_irq_handler' at $ea31), and the
      labels in Commodore's source for the Kernal and BASIC ROMs. (Use
      rom_labels=False for a program that replaces the ROMs.)
    - names for the colours stored in the VIC-II's colour registers and the
      text colour (e.g. 'colour_black');
    - code that sets a vector (e.g. the IRQ vector at $0314) to an address in
      the program: the address is traced and named (e.g. 'irq_handler');
    - comments on the code that sets up the VIC-II's interrupts (see
      _vic_interrupt_analysis());
    - a BASIC program loaded at $0801 (see basic_program());
    - PETSCII as the text encoding (see config.set_text_encoding());
    - the memory configuration the code sets with the 6510's port at $01
      (switching the ROMs and the I/O out and in), followed through the
      code: the code that sets it is commented (e.g. 'Set the memory
      configuration to RAM, I/O ($35)'), and an address used where it's
      something else than usual is given a plain name (e.g. 'ld020' rather
      than 'vic_border_colour', where the I/O is switched out). See
      c64_configuration() for code whose configuration isn't known from the
      code.

    Call it after loading the program, and before marking any strings
    (since it sets the text encoding). It stops with an error if the
    session's machine has been chosen already.
    """
    _set_up("c64", c64_machine(), names, rom_labels)

def vic20(expansion=None, names="descriptive", rom_labels=True):
    """As c64(), for the VIC-20: its Kernal and BASIC are the C64's, with
    its own hardware (the VIC, two VIAs and the colour RAM) and memory map.

    expansion is the RAM expansion: "none", "3k" (in block 0, $0400-$0fff)
    or "8k" (8K or more, from $2000). It decides where BASIC programs start
    ($1001, $0401 or $1201), and where the screen and its colour RAM are
    ($1e00 and $9600, or with 8K or more, $1000 and $9400). By default (None)
    it's worked out from where the program is loaded: "3k" if there's data at
    $0401, else "none" if there's data at $1001, else "8k" if there's data at
    $1201, else "none"."""
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
    and the I/O at $d000): its workspace, the MMU, the VDC, the VIC-II's and
    the C64's other hardware, its jump table (the C64's and 19 more, e.g.
    JSRFAR and PRIMM, whose string is skipped when tracing), its ROM routines
    and the labels in Commodore's source for its BASIC, monitor, screen
    editor and Kernal, and a BASIC program at $1c01.

    Its workspace has Commodore's names from its source, with descriptive
    names for the most used ones, and those that are the C64's (see
    commodoretables.py); the rest have Commodore's names either way. (A C128
    program in C64 mode is a C64 program: use c64().)

    The MMU's configuration is followed through the code, as the C64's port
    at $01 is (see c128_bank()), and calls to other banks with JSRFAR and
    JMPFAR are commented and their targets traced (see
    pre_trace_far_call())."""
    _set_up("c128", c128_machine(), names, rom_labels)

def plus4(names="descriptive", rom_labels=True):
    """As c64(), for the Plus/4 (and the C16 and C116, which have the same
    ROMs): its workspace, the TED (video, sound, timers and the ROM switch at
    $ff3e/$ff3f), the ACIA, the 6529 ports, its jump table (the C64's and
    PRINT, PRIMM and the monitor), its ROM routines and the labels in
    Commodore's source for its BASIC and Kernal, and a BASIC program at
    $1001. Its workspace's names are as for c128(). The TED's colours
    include their luminance, so they aren't named."""
    _set_up("plus4", plus4_machine(), names, rom_labels)

def pet(basic=4, columns=40, names="descriptive", rom_labels=True):
    """As c64(), for the PET (and the CBM 3000, 4000 and 8000 series), with
    BASIC 1 (the original 1977 ROMs), 2 or 4, and a 40 or 80 column screen
    (columns=80, BASIC 4's 8000 series, with a CRTC at $e880): its workspace
    (which depends on the BASIC version), the PIAs, the VIA, the screen at
    $8000, its jump table at $ffc0 (where only CHROUT has a hook: its LOAD,
    SAVE, VERIFY and SYS are BASIC's commands, not the C64's calls), its ROM
    routines and the labels in Commodore's source for its BASIC and Kernal
    (not BASIC 4's screen editor, which is different for each model), and a
    BASIC program at $0401, listed with that version's keywords (BASIC 4's
    disk commands too). The PET has no colours. Its workspace's names are as
    for c128(). Stops with an error for another BASIC version or width, or
    80 columns without BASIC 4."""
    if basic not in PET_BASIC_VERSIONS:
        utils.die("commodore.pet(): basic must be 1, 2 or 4, not {0!r}".format(basic))
    if columns not in PET_COLUMNS:
        utils.die("commodore.pet(): columns must be 40 or 80, not {0!r}".format(columns))
    if columns == 80 and basic != 4:
        utils.die("commodore.pet(): only BASIC 4 PETs have 80 columns")
    _set_up("pet", pet_machine(basic, columns), names, rom_labels)

def drive1541(rom="1541", names="descriptive", rom_labels=True):
    """As c64(), for code that runs in the 1541 disk drive (e.g. a fast
    loader's drive code, sent with M-W and run with M-E or a job), or its
    DOS ROM (see dos_rom()): the DOS's workspace (the job queue at $00-$04,
    each job's track and sector at $06-$0f and so on) and its five buffers at
    $0300-$07ff ('buffer_0' to 'buffer_4'), the two VIAs (the serial bus at
    $1800, and the disk controller at $1c00), the DOS ROM's routines that
    drive code calls (e.g. 'wait_for_sync' at $f556) and the labels in
    Commodore's source for the DOS ROM, and the NMI vector at $0065.

    Code that writes a job code to the job queue is commented (e.g. 'Job 0:
    read track 18, sector 1 into buffer 0 ($0300)'), with the job code named
    (e.g. 'job_read'), and for a JUMP or EXECUTE job, the code in the job's
    buffer is traced, if it's loaded. The job results the code compares or
    gives to ERRR are named, and stores to the VIAs' ports and tests of
    their bits are commented (see _drive1541_analysis()).

    rom is "1541" (DOS 325302-01 and 901229-05, the default) or "1541-ii"
    (251968-03, the 1541-II's and the 1541C's), which only changes a few ROM
    labels. Most of the workspace has Commodore's names either way; the most
    used have descriptive names (e.g. 'job_queue' rather than 'jobs'). The
    drive has no Kernal, BASIC or cartridges. (For drive code in a C64
    program, see drive1541_code().)"""
    if rom not in DRIVE1541_ROMS:
        utils.die("commodore.drive1541(): rom must be one of {0}, not {1!r}".format(", ".join(repr(r) for r in DRIVE1541_ROMS), rom))
    # (Each buffer is named, unless the program is loaded in it)
    buffers = [n for n in range(5) if not any(_is_loaded(addr) for addr in range(0x0300 + 0x100 * n, 0x0400 + 0x100 * n))]
    _set_up("drive1541", drive1541_machine(rom, buffers), names, rom_labels)
