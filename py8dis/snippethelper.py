import trace
import classification

class SnippetHelper:
    def __init__(self, memory_binary, binary_loc, match, labels):
        self.memory_binary = memory_binary
        self.binary_loc    = binary_loc
        self.match         = match
        self.labels        = labels

    def get_start_loc(self):
        return self.binary_loc

    def get_binary_address_and_length(self, label_name, prioritise_definition=False):
        # Look for the 'declaration' of the label
        for priority in [prioritise_definition, not prioritise_definition]:
            for label in self.labels[label_name]:
                if label[1] == priority:
                    start, end = self.match.span(label[0])
                    if start is None or (start < 0):
                        # Match not found, could have been one of the '|' options that are not present... keep trying
                        continue
                    length = end - start
                    assert 0 <= start < 0x10000, "label='{0}' index={1} start={2}".format(label_name, label[0], start)
                    return (start, length)

        return (None, None)

    def get_binary_address(self, label_name, prioritise_definition=True):
        binary_addr, _ = self.get_binary_address_and_length(label_name, prioritise_definition=prioritise_definition)
        return binary_addr

    def get_memory(self, label_name, offset=0):
        binary_addr, length = self.get_binary_address_and_length(label_name, prioritise_definition=False)
        if binary_addr:
            binary_addr += offset
            if length == 2:
                assert 0 <= binary_addr < 0xffff
                return self.memory_binary[binary_addr] + 256*self.memory_binary[binary_addr+1]
            elif length <= 1:
                assert 0 <= binary_addr < 0x10000
                return self.memory_binary[binary_addr]
            assert False, "length={0}, label={1}\nlabels:{2}".format(length, label_name, self.labels)
        return None

    def get_expr(self, label_name, *, label_offset=0, final_offset=0):
        binary_addr, length = self.get_binary_address_and_length(label_name, prioritise_definition=False)
        if binary_addr:
            binary_addr += label_offset
            if length == 2:
                assert 0 <= binary_addr < 0xffff
                return classification.get_address16(binary_addr, offset=final_offset)
            elif length <= 1:
                assert 0 <= binary_addr < 0x10000
                return classification.get_address8(binary_addr, offset=0)
            assert False, "length={0}, label={1}\nlabels:{2}".format(length, label_name, self.labels)
        return None

    def get_state(self, label_name, offset=0):
        binary_addr, length = self.get_binary_address_and_length(label_name, prioritise_definition=True)
        if binary_addr:
            binary_addr += offset
            assert 0 <= binary_addr < 0x10000
            return(trace.cpu.cpu_states[binary_addr])

    def check_branch_matches(self, label_name):
        branch_operand_value = self.get_memory(label_name)
        branch_operand_addr = self.get_binary_address(label_name, prioritise_definition=False)
        binary_definition_addr = self.get_binary_address(label_name, prioritise_definition=True)
        expected_branch_operand = binary_definition_addr - branch_operand_addr-1
        if -128 <= expected_branch_operand <= 127:
            # bring into range 0-255
            expected_branch_operand = (256 + expected_branch_operand) & 255
            return expected_branch_operand == branch_operand_value
        return False
