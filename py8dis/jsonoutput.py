"""
The disassembly as JSON (see docs/json-format.md in the repository, and
docs/py8dis-json.schema.json): the finished disassembly as data, for other
tools to read.

go() writes it, after the asm, if the session has a json_filename (e.g. from
--json on the command line). It's made from the session once emit() has made
the output, so the names are exactly those in the asm, and nothing in the
asm output is changed by making it.
"""

import json

import classification
import config
import cpu6502
import cpu65C02
import cpu8080
import disassembly
import expression
import mainformatter
import memorymanager
import movemanager
import output
import session
import utils

FORMAT  = "py8dis"
VERSION = 1

def write(filename):
    """Write the JSON for the current session's disassembly to a file."""
    with open(filename, "w") as f:
        f.write(dumps(document()))

def dumps(doc):
    """The JSON text for a document: each top level key on its own line, and
    each entry of a list (e.g. each item) on its own line, so the file is
    easy to read and compare. (This is also much quicker than json.dumps()
    with indent, which can't use the json module's C encoder.)"""
    def value_text(value):
        if isinstance(value, list) and value:
            return "[\n  " + ",\n  ".join(json.dumps(entry) for entry in value) + "\n]"
        return json.dumps(value)
    return "{\n" + ",\n".join(json.dumps(key) + ": " + value_text(value) for key, value in doc.items()) + "\n}\n"

def document():
    """The JSON for the current session's disassembly, as a dictionary."""
    s = session.current()
    return {
        "format":         FORMAT,
        "version":        VERSION,
        "cpu":            _cpu_name(s.cpu),
        "assembler":      config.get_assembler().get_name(),
        "loads":          _loads(),
        "moves":          _moves(),
        "constants":      _constants(),
        "memory_regions": [{ "start": start, "end": end, "name": name } for start, end, name in disassembly.effective_memory_regions()],
        "subroutines":    _subroutines(),
        "labels":         _labels(),
        "items":          _items(),
    }

def _cpu_name(cpu):
    import commands
    for name, cpu_class in commands.cpu_names.items():
        if type(cpu) is cpu_class:
            return name
    return type(cpu).__name__

def _loads():
    return [{ "filename": f.filename, "start": f.start, "end": f.end }
            for f in session.current().memory.loaded_files]

def _moves():
    move_definitions = session.current().moves.move_definitions
    return [{ "id": move_id, "binary_addr": int(md.src_binary_addr), "runtime_addr": int(md.dest_runtime_addr), "length": md.length }
            for move_id, md in enumerate(move_definitions) if move_id != movemanager.BASE_MOVE_ID]

def _item_type(c, binary_addr):
    if binary_addr in session.current().classifications.include_binary_files:
        return "include_binary"
    if isinstance(c, classification.Byte):
        return "bytes"
    if isinstance(c, classification.Word):
        return "words"
    if isinstance(c, classification.String):
        return "string"
    assert c.is_code(binary_addr)
    return "instruction"

def _inline_names():
    """The names defined inline, for each binary location, in the order
    they're defined."""
    result = {}
    for label in session.current().labels.labels.values():
        for name_list in label.explicit_names.values():
            for name in name_list:
                if name.definition == "inline":
                    loc = (int(name.defined_at.binary_addr), name.defined_at.move_id)
                    result.setdefault(loc, []).append(name)
    return { loc: [name.text for name in sorted(names, key=lambda name: name.definition_order())]
             for loc, names in result.items() }

def _items():
    memory_binary = session.current().memory.binary
    move_definitions = session.current().moves.move_definitions
    inline_names = _inline_names()
    items = []
    for binary_loc, c, lines in sorted(session.current().disassembly.output_items, key=lambda item: int(item[0].binary_addr)):
        binary_addr = int(binary_loc.binary_addr)
        move_id = binary_loc.move_id
        length = c.length()
        item = {
            "binary_addr":  binary_addr,
            "runtime_addr": int(move_definitions[move_id].convert_binary_to_runtime_addr(binary_loc.binary_addr)),
        }
        if move_id != movemanager.BASE_MOVE_ID:
            item["move_id"] = move_id
        item["length"] = length
        item["bytes"] = memory_binary[binary_addr:binary_addr + length]
        names = inline_names.get((binary_addr, move_id))
        if names:
            item["labels"] = names
        comments = _comments(binary_loc, length)
        if comments:
            item["comments"] = comments
        item["type"] = _item_type(c, binary_addr)
        # (Blank lines, e.g. after an RTS, are layout, so they're left out)
        item["text"] = [text for line in lines for text in line.plain_text() if text != ""]
        if item["type"] == "instruction":
            item.update(_instruction_fields(binary_loc, c, lines[0]))
        elif item["type"] in ("bytes", "words"):
            item.update(_data_fields(binary_addr, length, 1 if item["type"] == "bytes" else 2, lines[0]))
        elif item["type"] == "include_binary":
            item["filename"] = session.current().classifications.include_binary_files[binary_addr]
        items.append(item)
    return items


# Comments, constants and subroutines

def _align(align):
    return align.name.lower()

def _comment(annotation):
    """A comment (or other annotation) for the JSON, or None for one that
    only adds layout (a blank line)."""
    import comment
    if isinstance(annotation, comment.OverlappingInstruction):
        result = { "text": "overlapping: " + annotation.text.text(plain=True), "align": _align(annotation.align), "kind": "overlapping" }
    elif isinstance(annotation, comment.Comment):
        result = { "text": str(annotation.text), "align": _align(annotation.align) }
    else:
        text = str(annotation.text)
        if text.strip() == "":
            return None
        result = { "text": text, "align": _align(annotation.align), "kind": "raw" }
    if annotation.auto_generated:
        result["autogenerated"] = True
    return result

def _comments(binary_loc, length):
    """The comments for the item at binary_loc, in the order they're output
    (for each of its bytes in turn)."""
    annotations = session.current().disassembly.annotations
    result = []
    for i in range(length):
        loc = movemanager.BinaryLocation(binary_loc.binary_addr + i, binary_loc.move_id)
        if loc in annotations:
            for annotation in utils.sorted_annotations(loc, annotations[loc]):
                c = _comment(annotation)
                if c is not None:
                    result.append(c)
    return result

def _constants():
    result = []
    for c in disassembly.sorted_constants():
        entry = { "name": c.name, "value": c.value, "text": disassembly.constant_value_to_string(c.value, c.format) }
        if c.comment:
            entry["comment"] = { "text": str(c.comment), "align": _align(c.align) }
        result.append(entry)
    return result

def _subroutines():
    """The subroutines in the disassembly: those in the loaded data, and
    others (e.g. OS calls named by acorn.py) whose names the asm uses."""
    labels = session.current().labels.labels
    result = []
    for sub in sorted(session.current().trace.subroutines_list, key=lambda sub: int(sub.runtime_addr)):
        runtime_addr = memorymanager.RuntimeAddr(int(sub.runtime_addr))
        binary_addr, _ = movemanager.r2b(runtime_addr, sub.move_id)
        in_data = binary_addr is not None and memorymanager.is_data_loaded_at_binary_addr(binary_addr)
        label = labels.get(runtime_addr)
        named = label is not None and any(name.text == sub.label_name for name_list in label.explicit_names.values() for name in name_list)
        if not (in_data or named):
            continue
        entry = { "runtime_addr": int(sub.runtime_addr) }
        if sub.move_id not in (None, movemanager.BASE_MOVE_ID):
            entry["move_id"] = sub.move_id
        for key, value in (("name", sub.label_name), ("title", sub.title), ("description", sub.description)):
            if value:
                entry[key] = str(value)
        for key, value in (("on_entry", sub.on_entry), ("on_exit", sub.on_exit)):
            if value:
                entry[key] = { str(reg): str(text) for reg, text in value.items() }
        result.append(entry)
    return result


# Labels

def _labels():
    s = session.current()
    move_definitions = s.moves.move_definitions
    headings = s.disassembly.memory_location_headings
    result = []
    for runtime_addr in sorted(s.labels.labels):
        label = s.labels.labels[runtime_addr]
        entry = { "runtime_addr": int(runtime_addr) }

        names = []
        for move_id, name_list in sorted(label.explicit_names.items()):
            for name in sorted(name_list, key=lambda name: name.definition_order()):
                n = { "name": name.text }
                if move_id != movemanager.BASE_MOVE_ID:
                    n["move_id"] = move_id
                n["autogenerated"] = bool(name.is_autogenerated)
                n["definition"] = name.definition or "none"
                if name.definition == "memory_locations" and int(runtime_addr) in headings:
                    n["memory_region"] = headings[int(runtime_addr)]
                names.append(n)
        if names:
            entry["names"] = names

        local_names = []
        for move_id, local_list in sorted(label.local_labels.items()):
            for local in local_list:
                n = { "name": local.name }
                if local.output_name != local.name:
                    n["output_name"] = local.output_name
                if move_id != movemanager.BASE_MOVE_ID:
                    n["move_id"] = move_id
                n["start"] = int(local.start_addr)
                n["end"] = int(local.end_addr)
                if int(runtime_addr) in headings:
                    n["memory_region"] = headings[int(runtime_addr)]
                local_names.append(n)
        if local_names:
            entry["local_names"] = local_names

        expressions = []
        for move_id, expression_list in sorted(label.expressions.items()):
            for text in expression_list:
                e = { "text": str(text) }
                if move_id != movemanager.BASE_MOVE_ID:
                    e["move_id"] = move_id
                expressions.append(e)
        if expressions:
            entry["expressions"] = expressions

        if not (names or local_names or expressions):
            continue

        references = []
        for loc in sorted(set((int(r.binary_addr), r.move_id) for r in label.references)):
            binary_addr, move_id = loc
            ref = { "binary_addr": binary_addr, "runtime_addr": int(move_definitions[move_id].convert_binary_to_runtime_addr(memorymanager.BinaryAddr(binary_addr))) }
            if move_id != movemanager.BASE_MOVE_ID:
                ref["move_id"] = move_id
            references.append(ref)
        if references:
            entry["references"] = references
        result.append(entry)
    return result


# Expressions

def _num_format(binary_addr, value, bits):
    """How a number that isn't given by an expression is shown (see the
    formatters in mainformatter.py), as a 'format' for the JSON, or None if
    it's shown by a formatter py8dis doesn't know (e.g. the control file's
    own)."""
    hex_digits = "hex2" if bits == 8 else "hex4"
    formatter = session.current().disassembly.format_hint.get(binary_addr, mainformatter.uint_formatter)
    if formatter is mainformatter.uint_formatter:
        return "decimal" if value < 10 else hex_digits
    if formatter is mainformatter.uhex_formatter:
        return hex_digits
    if formatter is mainformatter.hexadecimal_formatter:
        return "hex"
    if formatter in (mainformatter.uint_no_hex_formatter, mainformatter.decimal_formatter):
        return "decimal"
    if formatter is mainformatter.sint_formatter:
        return "signed_decimal" if config.get_assembler().supports_signed_integers() else "decimal"
    if formatter is mainformatter.char_formatter:
        if config.get_assembler().char_literal(value) is not None:
            return "char"
        return "decimal" if value < 10 else hex_digits
    if formatter is mainformatter.binary_formatter:
        return "binary"
    if formatter is mainformatter.picture_binary_formatter:
        return "picture_binary"
    return None

def _tree(value):
    """The tree for an expression (see expression.py), label reference or
    other text, for the JSON."""
    if isinstance(value, expression.InContext):
        return _tree(value.value)
    if isinstance(value, disassembly.LabelRef):
        return { "label": int(value.runtime_addr), "name": str(value) }
    if isinstance(value, expression.LazyLeaf):
        return _tree(value.lazy_string)
    if isinstance(value, expression.Num):
        return { "num": value.value, "format": value.format }
    if isinstance(value, expression.Name):
        return { "name": value.name }
    if isinstance(value, expression.Unary):
        return { "op": value.op, "arg": _tree(value.operand) }
    if isinstance(value, expression.Binary):
        return { "op": value.op, "left": _tree(value.left), "right": _tree(value.right) }
    if isinstance(value, expression.Raw):
        return { "raw": value.text }
    if utils.is_integer_type(value):
        return { "num": int(value), "format": "decimal" }
    return { "raw": str(value) }

def _expr(value, binary_addr=None, number=None, bits=8):
    """An expression for the JSON: its text and tree. A number that isn't
    given by an expression (i.e. it's text made by a formatter, see
    classification.get_constant8()) is the number at binary_addr, 'number'."""
    text = str(value)
    if binary_addr is not None and binary_addr not in session.current().classifications.expressions and not isinstance(value, (expression.Expr, utils.LazyString)):
        tree = { "num": number }
        fmt = _num_format(binary_addr, number, bits)
        if fmt is not None:
            tree["format"] = fmt
    else:
        tree = _tree(value)
    return { "text": text, "tree": tree }


# Instructions

# The 6502's addressing modes (see Cpu6502.mode_*), as named in the JSON
_MODES_6502 = {
    cpu6502.Cpu6502.mode_implied:          "implied",
    cpu6502.Cpu6502.mode_immediate:        "immediate",
    cpu6502.Cpu6502.mode_accumulator:      "accumulator",
    cpu6502.Cpu6502.mode_offset:           "relative",
    cpu6502.Cpu6502.mode_indexed_indirect: "zp_x_indirect",
    cpu6502.Cpu6502.mode_indirect_indexed: "zp_indirect_y",
    cpu6502.Cpu6502.mode_abs_indexed_x:    "absolute_x",
    cpu6502.Cpu6502.mode_zp_indexed_x:     "zp_x",
    cpu6502.Cpu6502.mode_abs_indexed_y:    "absolute_y",
    cpu6502.Cpu6502.mode_zp_indexed_y:     "zp_y",
    cpu6502.Cpu6502.mode_indirect_zp:      "zp_indirect",
    cpu6502.Cpu6502.mode_indirect_addr:    "indirect",
    cpu6502.Cpu6502.mode_addr:             "absolute",
    cpu6502.Cpu6502.mode_zp:               "zp",
    cpu6502.Cpu6502.mode_indexed_abs:      "absolute_x_indirect",
}

_ZP_MODES = { "zp", "zp_x", "zp_y", "zp_indirect", "zp_x_indirect", "zp_indirect_y" }

def _instruction_fields(binary_loc, c, instruction):
    """The JSON fields of an instruction (opcode 'c', output as the
    output.Instruction 'instruction')."""
    binary_addr = binary_loc.binary_addr
    cpu = session.current().cpu
    memory_binary = session.current().memory.binary
    result = { "mnemonic": utils.force_case(c.mnemonic.split()[0]) }

    if isinstance(cpu, cpu6502.Cpu6502):
        mode = _MODES_6502[c.addr_mode]
        target = None
        if isinstance(c, (cpu6502.Cpu6502.OpcodeJsr, cpu6502.Cpu6502.OpcodeJmpAbs, cpu6502.Cpu6502.OpcodeConditionalBranch, cpu65C02.Cpu65C02.OpcodeUnconditionalBranch)):
            target = int(c.target(binary_addr))
        if mode in ("implied", "accumulator"):
            value = None
        elif mode == "relative":
            value = target
        elif mode == "immediate" or mode in _ZP_MODES:
            value = memory_binary[binary_addr + 1]
        else:
            value = memorymanager.get_u16_binary(binary_addr + 1)
        bits = 16 if mode not in _ZP_MODES and mode not in ("immediate", "relative") else 8
    else:
        assert isinstance(cpu, cpu8080.Cpu8080)
        target = None
        if isinstance(c, cpu8080.Cpu8080.OpcodeImmediate):
            mode, value, bits = "immediate", memory_binary[binary_addr + 1], 8
        elif isinstance(c, cpu8080.Cpu8080.OpcodeImmediate16):
            mode, value, bits = "immediate16", memorymanager.get_u16_binary(binary_addr + 1), 16
        elif c.operand_length == 2:
            mode, value, bits = "address", memorymanager.get_u16_binary(binary_addr + 1), 16
            if isinstance(c, (cpu8080.Cpu8080.OpcodeJmp, cpu8080.Cpu8080.OpcodeConditionalBranch, cpu8080.Cpu8080.OpcodeCall)):
                target = value
        else:
            mode, value, bits = "implied", None, None

    result["mode"] = mode
    if value is not None and instruction.operand is not None:
        result["operand"] = { "value": value, "expr": _expr(instruction.operand, binary_addr + 1, value, bits) }
    if target is not None:
        result["target"] = target

    if isinstance(cpu, cpu6502.Cpu6502):
        result["cycles"] = c.cycles_description(binary_addr)
        state = cpu.cpu_states[binary_addr]
        if state is not None:
            result["cpu_state"] = _cpu_state(state.pessimistic)
    return result

def _cpu_state(disposition):
    """The 6502's state (a CpuStateDisposition) for the JSON: what's known,
    with None where it isn't."""
    result = {}
    for reg in "axy":
        result[reg] = disposition[reg].value
    for flag in "nvdizc":
        value = disposition[flag]
        result[flag] = bool(value) if value in (True, False, 0, 1) else None
    return result


# Data

def _data_fields(binary_addr, length, element_size, data_block):
    """The JSON fields of bytes or words (output as the output.DataBlock
    'data_block')."""
    expressions = session.current().classifications.expressions
    memory_binary = session.current().memory.binary
    if element_size == 1:
        values = memory_binary[binary_addr:binary_addr + length]
    else:
        values = [memorymanager.get_u16_binary(binary_addr + i) for i in range(0, length, 2)]
    result = { "values": values }
    if isinstance(data_block, output.DataBlock):
        items = data_block.items()
        exprs = [_expr(items[i]) if (binary_addr + i*element_size) in expressions else None for i in range(len(values))]
        if any(e is not None for e in exprs):
            result["exprs"] = exprs
    return result
