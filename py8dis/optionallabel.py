class OptionalLabel:
    def __init__(self, name, base_address, definable_inline):
        self.name = name
        self.base_address = base_address
        self.definable_inline = definable_inline

    def __eq__(self, other):
        if isinstance(other, OptionalLabel):
            return (self.name == other.name and
                self.base_address == other.base_address and
                self.definable_inline == other.definable_inline)
        return False
