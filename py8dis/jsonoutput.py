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
import memorymanager
import movemanager
import session

FORMAT  = "py8dis"
VERSION = 1

def write(filename):
    """Write the JSON for the current session's disassembly to a file."""
    with open(filename, "w") as f:
        json.dump(document(), f, indent=1)
        f.write("\n")

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
        "constants":      [],
        "memory_regions": [],
        "subroutines":    [],
        "labels":         [],
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
        item["type"] = _item_type(c, binary_addr)
        # (Blank lines, e.g. after an RTS, are layout, so they're left out)
        item["text"] = [text for line in lines for text in line.plain_text() if text != ""]
        items.append(item)
    return items
