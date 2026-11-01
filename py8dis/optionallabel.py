"""
Optional label

An optional label is a name for an address that's only output if something
uses the address, e.g. the operating system's addresses that acorn.bbc() and
commodore.c64() name (see optional_label() in docs/commands.md).
disassembly.add_optional_label() keeps them in the session's
disassembly.optional_labels, by runtime address, and they're used when a
label's name is chosen (see disassembly.suggest_label_name()).
"""

class OptionalLabel:
    """An optional label (see the module docs).

        name: its name
        base_address: None, or the runtime address of another optional
            label that this name is relative to, e.g. 'irq_vector+1' based
            on irq_vector's address. If this name is used, that label is
            needed too.
        definable_inline: False to always define the label at the top of
            the output ('name = value'), rather than at its place in the
            code
    """
    def __init__(self, name, base_address, definable_inline):
        self.name = name
        self.base_address = base_address
        self.definable_inline = definable_inline

    def __eq__(self, other):
        """Equal if the name, base address and definable_inline all are.
        (Giving the same optional label for an address again is allowed;
        giving a different one is an error: see
        disassembly.add_optional_label().)"""
        if isinstance(other, OptionalLabel):
            return (self.name == other.name and
                self.base_address == other.base_address and
                self.definable_inline == other.definable_inline)
        return False
