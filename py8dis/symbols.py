"""
Symbol files and cross-reference listings, made from the JSON document (see
jsonoutput.py), so the names are exactly those in the asm.

A symbol file gives each label name and its (runtime) address, for e.g. an
emulator's debugger. The formats are:

    plain    'name = &ffee', in the assembler's hex syntax, in address order
    vice     VICE's monitor label file ('al 00FFEE .name', as cc65's ld65
             writes with -Ln), loaded with the monitor's 'll' command or
             -moncommands
    beebasm  beebasm's symbol dump ('[{'name':65518L,...}]', as 'beebasm -d'
             writes), in address order then name order
    mame     MAME debugger commands giving each name as a comment at its
             address ('comadd ffee,name'), run with the debugger's 'source'
             command

Each name a label has is given (including local label names, as the asm
uses them), but not expressions (e.g. 'table+1') or constants. VICE and
MAME can't take an address past the top of memory (e.g. pydis_end, for data
that ends there), so such names are left out of those.

A cross-reference listing gives each label, where the asm defines it, and
each instruction or piece of data that refers to it.
"""

import config
import utils

FORMATS = ("plain", "vice", "beebasm", "mame")

def _hex4(addr):
    """An address in the assembler's hex syntax, always with four digits
    (or five, for &10000)."""
    prefix = config.get_assembler().hex4(0xffff)[:-4]
    return prefix + ("%04x" % addr if config.get_lower_case() else "%04X" % addr)

def symbols(doc):
    """Each (runtime address, name) pair, in address order, then name
    order."""
    result = set()
    for label in doc["labels"]:
        for n in label.get("names", []):
            result.add((label["runtime_addr"], n["name"]))
        for n in label.get("local_names", []):
            result.add((label["runtime_addr"], n.get("output_name", n["name"])))
    return sorted(result)

def symbols_text(format, doc):
    """The symbol file, as text, in the given format."""
    pairs = symbols(doc)
    if format == "plain":
        width = max((len(name) for _, name in pairs), default=0)
        return "".join("%-*s = %s\n" % (width, name, _hex4(addr)) for addr, name in pairs)
    if format == "vice":
        return "".join("al %06X .%s\n" % (addr, name) for addr, name in pairs if addr <= 0xffff)
    if format == "beebasm":
        return "[{" + ",".join("'%s':%dL" % (name, addr) for addr, name in pairs) + "}]\n"
    if format == "mame":
        return "".join("comadd %x,%s\n" % (addr, name) for addr, name in pairs if addr <= 0xffff)
    utils.die("Unknown symbol file format '{0}' (expected {1})".format(format, ", ".join(FORMATS)))

def write_symbols(filename, format, doc):
    with open(filename, "w") as f:
        f.write(symbols_text(format, doc))

def xref_text(doc):
    """The cross-reference listing, as text: for each label (by address),
    its names and where the asm defines them, then each reference to it (by
    the address it runs at): the address, where it is (the nearest label
    before it, and the offset from that), and its text in the asm."""
    h = hex_addr = _hex4

    # The item containing each binary address, and the nearest named item at
    # or before each item (in the same move)
    items = doc["items"]
    item_index = {}
    for i, item in enumerate(items):
        for offset in range(item["length"]):
            item_index[item["binary_addr"] + offset] = i
    nearest_label = []
    last = {}
    for item in items:
        move = item.get("move_id", 0)
        if item.get("labels"):
            last[move] = (item["runtime_addr"], item["labels"][0])
        nearest_label.append(last.get(move))

    def where(ref):
        """Where a reference is: the nearest label at or before it, plus an
        offset, e.g. 'print_loop+3'."""
        i = item_index.get(ref["binary_addr"])
        if i is None or nearest_label[i] is None:
            return ""
        addr, name = nearest_label[i]
        offset = ref["runtime_addr"] - addr
        return name if offset == 0 else "%s+%d" % (name, offset)

    def text(ref):
        i = item_index.get(ref["binary_addr"])
        return "" if i is None else items[i]["text"][0]

    lines = ["Cross-reference listing: each label, where it's defined, and what refers to it.", ""]
    for label in doc["labels"]:
        addr = label["runtime_addr"]
        names = []
        for n in label.get("names", []):
            definition = {"inline": "inline", "relative": "relative to the item it's inside",
                          "memory_locations": "Memory locations", "none": "not defined"}[n["definition"]]
            if "memory_region" in n:
                definition += ": " + n["memory_region"]
            names.append("%s (%s)" % (n["name"], definition))
        for n in label.get("local_names", []):
            names.append("%s (local to %s-%s)" % (n.get("output_name", n["name"]), h(n["start"]), h(n["end"] - 1)))
        for e in label.get("expressions", []):
            names.append("%s (expression)" % e["text"])
        lines.append("%s  %s" % (hex_addr(addr), ", ".join(names)))
        refs = label.get("references", [])
        if not refs:
            lines.append("    (not referenced)")
        for ref in sorted(refs, key=lambda r: (r["runtime_addr"], r["binary_addr"])):
            move = "[%d]" % ref["move_id"] if "move_id" in ref else ""
            lines.append(("    %-9s %-28s %s" % (h(ref["runtime_addr"]) + move, where(ref), text(ref))).rstrip())
        lines.append("")
    return "\n".join(lines)

def write_xref(filename, doc):
    with open(filename, "w") as f:
        f.write(xref_text(doc))
