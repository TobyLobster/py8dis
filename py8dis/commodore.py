"""
Commodore specific functions: commodore.c64() names and comments a C64
program's use of the Kernal, the hardware and the OS workspace, as
acorn.bbc() does for the BBC Micro.

    import commodore
    start = load_prg("game.prg", "6510")
    commodore.c64()

c64() names the memory locations with descriptive names by default (e.g.
'vic_border_colour'); c64(names="commodore") uses the names in Commodore's
documentation instead (e.g. 'extcol'). See commodoretables.py.
"""

from commands import *
import classification
import config
import session
import textencoding
import utils
from memorymanager import BinaryAddr, RuntimeAddr
from snippets6502 import register_snippet

from commodoretables import *
from commodoreromlabels import kernal_rom_labels

# Helpers shared with acorn.py's OS call hooks
from acornhelpers import xy_addr, enum_lookup

NAMES = ("descriptive", "commodore")


# ************************************************************************************************
# The names

def _name(location, names):
    """A Location's name in the given style"""
    if names == "commodore" and location.commodore_name is not None:
        return location.commodore_name
    return location.name

def c64_location_names(names="descriptive", rom_labels=True):
    """The names c64() gives memory locations, as a list of (address, name,
    base address or None): one for each byte of each location (e.g.
    'tape_buffer+1', with the base address of 'tape_buffer'), the ROM
    routines, and (with rom_labels) the labels in Commodore's source for the
    Kernal ROM. Not the Kernal's jump table, which are subroutines.

    A label in Commodore's source with the same name as a Kernal call or
    another location (e.g. PLOT, the routine at &e50a that the jump table's
    plot at &fff0 jumps to) gets '_rom' added, e.g. 'plot_rom'."""
    result = []
    def add(location):
        name = _name(location, names)
        result.append((location.addr, name, None))
        for i in range(1, location.size):
            result.append((location.addr + i, "%s+%d" % (name, i), location.addr))

    for location in c64_ram_locations:
        add(location)
    for vector in c64_vectors:
        if vector.name is not None and vector.addr >= 0x0314:
            add(Location(vector.addr, 2, vector.commodore_name, vector.name))
    for location in c64_more_ram_locations + c64_hardware_locations + c64_cpu_vectors:
        add(location)

    if rom_labels:
        for location in c64_rom_locations:
            add(location)
        named = {addr for addr, _, _ in result} | {call.addr for call in kernal_jump_table}
        for routine in c64_rom_routines:
            name = routine.name
            if names == "commodore" and routine.commodore_name is not None:
                name = routine.commodore_name
            result.append((routine.addr, name, None))
            named.add(routine.addr)

        used = {name for _, name, _ in result} | {call.name for call in kernal_jump_table}
        for addr in sorted(kernal_rom_labels):
            if addr in named:
                continue
            name = kernal_rom_labels[addr]
            if name in used:
                name += "_rom"
            assert name not in used, name
            used.add(name)
            result.append((addr, name, None))
    return result


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
    for vector in c64_vectors:
        name = None
        if vector.name is not None:
            name = vector.commodore_name if names == "commodore" else vector.name
        result[vector.addr] = (name, vector.description, vector.handler)
    return result

def pre_trace_writing_to_vector(p):
    """A program setting one of the vectors (e.g. the IRQ vector) to an
    address in its code: trace it, name it (e.g. 'irq_handler') and comment
    the code."""
    p.entry()

    addr1 = p.get_memory('first_store', 1) + 256*p.get_memory('first_store', 2)
    addr2 = p.get_memory('second_store', 1) + 256*p.get_memory('second_store', 2)
    nn1_addr = p.get_binary_address('nn1')
    nn2_addr = p.get_binary_address('nn2')
    nn1 = p.get_memory('nn1')
    nn2 = p.get_memory('nn2')
    end = p.get_binary_location('end')

    if addr1 == addr2 + 1:
        # The high byte first: swap them so addr1 is the low byte's
        addr1, addr2 = addr2, addr1
        nn1, nn2 = nn2, nn1
        nn1_addr, nn2_addr = nn2_addr, nn1_addr
    vectors = _vector_names(session.current().extras["commodore.names"])
    if addr2 != addr1 + 1 or addr1 not in vectors:
        return
    _, description, handler = vectors[addr1]

    new_addr = nn1 + 256*nn2
    labels = session.current().labels.labels
    if new_addr in labels and labels[new_addr].explicit_names:
        # (Use its first name)
        for move_id, name_list in labels[new_addr].explicit_names.items():
            label_name = name_list[0].text
            break
    else:
        # The first handler for a vector is e.g. 'irq_handler', the next
        # 'irq_handler_2'
        counts = session.current().extras.setdefault("commodore.vector_handler_count", {})
        count = counts.get(handler, 0) + 1
        counts[handler] = count
        label_name = handler if count == 1 else "%s_%d" % (handler, count)
        label(new_addr, label_name)

    p.entry(RuntimeAddr(new_addr))

    if not p.has_explicit_label(p.get_start_loc()):
        p.blank_once(p.get_start_loc())
    disassembly.comment_binary(p.get_start_loc(), "Set the {0} to {1}".format(description, label_name), indent=1, align=Align.AFTER_LABEL, auto_generated=True)
    p.blank_once(end)

    expr(movemanager.b2r(nn1_addr), make_lo(label_name))
    expr(movemanager.b2r(nn2_addr), make_hi(label_name))

def register_snippets():
    """Register commodore's snippets with the current session (once per
    session)"""
    extras = session.current().extras
    if extras.get("commodore.snippets_registered"):
        return
    extras["commodore.snippets_registered"] = True

    stores = {}
    for reg in "axy":
        alternatives = []
        for vector in c64_vectors:
            for addr in (vector.addr, vector.addr + 1):
                alternatives.append("st%s $%x" % (reg, addr))
        stores[reg] = " | ".join(alternatives)

    # e.g. 'lda #<handler : sta $0314 : lda #>handler : sta $0315'
    register_snippet(pre_trace_writing_to_vector, None, """
    lda #nn1
first_store
    {a}
    lda #nn2
second_store
    {a}
end
""".format(**stores))
    # e.g. 'ldx #<handler : ldy #>handler : stx $0314 : sty $0315'
    register_snippet(pre_trace_writing_to_vector, None, """
    ldx #nn1
    ldy #nn2
first_store
    {x}
second_store
    {y}
end
""".format(**stores))
    # e.g. 'lda #<handler : ldx #>handler : sta $0314 : stx $0315'
    register_snippet(pre_trace_writing_to_vector, None, """
    lda #nn1
    ldx #nn2
first_store
    {a}
second_store
    {x}
end
""".format(**stores))


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
            elif c - 0x80 < len(basic_v2_tokens):
                result += basic_v2_tokens[c - 0x80]
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

def basic_program(runtime_addr=0x0801):
    """Classify the tokenised BASIC program at the address (by default the
    start of BASIC on the C64), e.g. the one-line 'SYS' program at the start
    of most machine code programs. Each line is labelled (e.g.
    'basic_line_10'), its link to the next line and its line number are
    words, and its text is bytes for the tokens and PETSCII strings, listed
    in a comment, e.g. '; 10 SYS2061'. An address SYS calls in the loaded
    data is an entry point, named 'sys_entry' unless it already has a name
    (so to give it another, name it before calling this, or c64()).

    Returns the address after the program, or None (classifying nothing) if
    there isn't a valid BASIC program there."""
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
    """For a C64 cartridge loaded at &8000 (with the 'CBM80' signature at
    &8004): name its header, and trace its cold and warm start code."""
    label(0x8000, "cartridge_cold_start_vector")
    code_ptr(0x8000, label_name=None if _has_name(memorymanager.get_u16_runtime(RuntimeAddr(0x8000))) else "cartridge_cold_start")
    label(0x8002, "cartridge_warm_start_vector")
    code_ptr(0x8002, label_name=None if _has_name(memorymanager.get_u16_runtime(RuntimeAddr(0x8002))) else "cartridge_warm_start")
    label(0x8004, "cartridge_signature")
    string(0x8004, 5, encoding="petscii")
    auto_comment(0x8000, "Cartridge header")

def _has_name(runtime_addr):
    labels = session.current().labels.labels
    return runtime_addr in labels and bool(labels[runtime_addr].explicit_names)

def kernal_rom():
    """For a disassembly of a Kernal ROM (loaded at &e000): trace the code
    from the Kernal's jump table (each entry named, e.g. 'chrout') and the
    6502's NMI, reset and IRQ vectors."""
    for call in kernal_jump_table:
        if _is_loaded(call.addr):
            entry(call.addr, call.name)
    for addr, name in ((0xfffa, "nmi_entry"), (0xfffc, "reset_entry"), (0xfffe, "irq_entry")):
        target = memorymanager.get_u16_runtime(RuntimeAddr(addr))
        has_name = _has_name(target) or target in session.current().disassembly.optional_labels
        code_ptr(addr, label_name=None if has_name else name)

def basic_rom():
    """For a disassembly of a BASIC ROM (loaded at &a000): trace the code
    from its cold and warm start vectors, and name its signature."""
    for addr, name in ((0xa000, "basic_cold_start"), (0xa002, "basic_warm_start")):
        target = memorymanager.get_u16_runtime(RuntimeAddr(addr))
        label(addr, name + "_vector")
        code_ptr(addr, label_name=None if _has_name(target) else name)
    label(0xa004, "basic_signature")
    string(0xa004, encoding="petscii")


# ************************************************************************************************
# The C64

def c64_memory_regions():
    """Name the regions of the C64's memory, to group the list of memory
    locations at the top of the output (see memory_region())."""
    memory_region(0x0000, 0x0002, "6510 I/O port")
    memory_region(0x0200, 0x0300, "OS workspace")
    memory_region(0x0300, 0x0334, "Vectors")
    memory_region(0x0334, 0x0400, "Tape buffer")
    memory_region(0x0400, 0x0800, "Screen memory")
    memory_region(0x0800, 0xa000, "BASIC program area")
    memory_region(0xa000, 0xc000, "BASIC ROM")
    memory_region(0xc000, 0xd000, "Upper RAM")
    memory_region(0xd000, 0xd400, "VIC-II")
    memory_region(0xd400, 0xd800, "SID")
    memory_region(0xd800, 0xdc00, "Colour RAM")
    memory_region(0xdc00, 0xdd00, "CIA 1")
    memory_region(0xdd00, 0xde00, "CIA 2")
    memory_region(0xde00, 0xdf00, "I/O 1")
    memory_region(0xdf00, 0xe000, "I/O 2")
    memory_region(0xe000, 0xff81, "Kernal ROM")
    # The 6502's NMI, reset and IRQ vectors follow (a region named by the CPU)
    memory_region(0xff81, 0xfffa, "Kernal entry points")

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
      labels in Commodore's source for the Kernal ROM. (Use
      rom_labels=False for a program that replaces the ROMs.)
    - names for the colours stored in the VIC-II's colour registers (e.g.
      'colour_black');
    - code that sets a vector (e.g. the IRQ vector at &0314) to an address in
      the program: the address is traced and named (e.g. 'irq_handler');
    - a BASIC program loaded at &0801 (see basic_program());
    - PETSCII as the text encoding (see config.set_text_encoding()).
    """
    if names not in NAMES:
        utils.die("commodore.c64(): names must be one of {0}, not {1!r}".format(", ".join(repr(n) for n in NAMES), names))
    extras = session.current().extras
    if extras.get("commodore.machine") is not None:
        utils.die("commodore.c64(): this session's machine has already been chosen")
    extras["commodore.machine"] = "c64"
    extras["commodore.names"] = names

    config.set_text_encoding("petscii")
    register_snippets()
    c64_memory_regions()

    for addr, name, base in c64_location_names(names, rom_labels):
        optional_label(addr, name, base, definable_inline=not 0xd000 <= addr < 0xe000)

    for call in kernal_jump_table:
        subroutine(call.addr, call.name, call.title, None, call.on_entry, call.on_exit, hook=_hooks.get(call.name, default_hook), is_entry_point=False)
    if rom_labels:
        for routine in c64_rom_routines:
            name = routine.name
            if names == "commodore" and routine.commodore_name is not None:
                name = routine.commodore_name
            subroutine(routine.addr, name, routine.title, None, routine.on_entry, routine.on_exit,
                       hook=strout_hook if routine.addr == 0xab1e else default_hook, is_entry_point=False)

    # Colours stored in the colour registers
    for addr in c64_colour_registers:
        for reg in "axy":
            session.current().trace.substitute_constant_list.append(cpu6502.SubConst("st%s $%04x" % (reg, addr), reg, colours, True))

    if _is_loaded(0x0801):
        basic_program(0x0801)
