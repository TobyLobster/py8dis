import assembler
import classification
import collections
import copy
import config
import disassembly
import labelmanager
import mainformatter
import memorymanager
import movemanager
import re
import trace
import utils
from memorymanager import BinaryLocation
from align import Align
from maker import make_hex, make_lo, make_hi, make_or, make_and, make_eor, make_xor, make_add, make_subtract, make_multiply, make_divide, make_modulo
from memorymanager import BinaryAddr, RuntimeAddr
import snippets6502
from snippets6502 import snippets

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


class Cpu(object):
    """Abstract base class representing a CPU"""

    def __init__(self):
        self.labels = labelmanager.labels

        self.subroutine_hooks = {}
        self.opcodes = {}
        self.entry_points = []
        self.traced_entry_points = set()
        self.code_analysis_fns = []
        self.trace_done = False

        # After we have traced to classify where the code is, we record what we
        # know about the CPU state after each instruction. This is used to
        # analyse the code. e.g. We look to see if we set a register with an
        # immediate mode constant before a subroutine call so that we can give
        # that constant a proper symbol name.
        self.cpu_states = [None] * 64*1024


    def disassemble_instruction(self, binary_addr):
        """
        Disassemble an instruction at the binary address.

        Identifies the opcode and calls into the opcode object to do
        the actual disassembly.

        Returns a list of possible new addresses, the first entry
        being the address of the next instruction, and the next
        entry being the destination of a jump or branch instruction.
        """

        assert isinstance(binary_addr, memorymanager.BinaryAddr)
        opcode_value = memorymanager.memory_binary[binary_addr]
        if opcode_value not in self.opcodes:
            return [None]
        opcode = self.opcodes[opcode_value]

        with movemanager.move_id_for_binary_addr[binary_addr] as move_id:
            binary_loc = BinaryLocation(binary_addr, move_id)

            # If we hit something that's already classified, we can't/don't
            # re-classify it but that doesn't mean we can't continue to
            # trace until something breaks the control flow.
            if classification.is_classified(binary_addr, 1 + opcode.operand_length):
                # Format the comment using a LazyString and a late_formatter,
                # to be resolved later.
                s = opcode.as_string(binary_addr)

                def late_formatter():
                    return mainformatter.add_inline_comment_including_hexdump(binary_loc, opcode.length(), "", None, config.get_assembler().comment_prefix() + " overlapping: " + str(s)[4:])

                disassembly.add_raw_annotation(binary_loc, utils.LazyString("%s", late_formatter))
            else:
                # Classify the address as code
                classification.add_classification(binary_addr, opcode)
                opcode.update_references(binary_loc)

            # Call the opcode routine to actually disassemble the instruction
            result = opcode.disassemble(binary_loc)
            return result

    def add_entry(self, binary_addr, runtime_addr, move_id, name):
        """Add code entry point"""

        assert not isinstance(binary_addr, memorymanager.RuntimeAddr)
        assert not isinstance(runtime_addr, memorymanager.BinaryAddr)
        self.entry_points.append(binary_addr)
        runtime_addr = movemanager.b2r(binary_addr)
        disassembly.add_label(runtime_addr, name, move_id, is_autogenerated=False)

    def analyse_code(self):
        """Calculates what we know about the CPU state for each instruction
        then runs code analysis. e.g. We look to see if we set a register with
        an immediate mode constant before a subroutine call so that we can give
        that constant a proper symbol name."""

        # Calculate the CPU state at each instruction
        binary_addr = 0
        state = self.CpuState()
        while binary_addr < 0x10000:
            c = classification.get_classification(binary_addr)
            if c is not None:
                if c.is_code(binary_addr):
                    c.update_cpu_state(binary_addr, state)
                    self.cpu_states[binary_addr] = copy.deepcopy(state)
                else:
                    state = self.CpuState()
                binary_addr += c.length()
            else:
                binary_addr += 1

        # Call each of the code analysis functions
        for f in self.code_analysis_fns:
            f()

    def trace(self):
        """Trace all the code from the entry points."""

        # As each instruction is processed, the next possible instructions
        # are added to the 'entry_points' list. The first of these will be
        # the following instruction (if there is one; it might be None).

        # We have a number of regular expressions that represent common segments
        # of code. If we find one of these, then there's likely to be code there.
        # We generate entry_points for these.
        self.find_common_code_with_regex()

        # Work through each entry point
        while len(self.entry_points) > 0:
            entry_point = self.entry_points.pop(0)
            if entry_point not in self.traced_entry_points:
                self.traced_entry_points.add(entry_point)
                new_entry_points = self.disassemble_instruction(entry_point)

                # The first element of new_entry_points is the implicit
                # next instruction (if there is one; it might be None)
                # which is handled slightly differently, as it *isn't*
                # automatically assigned a label (but still gets added
                # to the 'entry_points' list).
                assert len(new_entry_points) >= 1
                implied_entry_point = new_entry_points.pop(0)
                if implied_entry_point is not None:
                    self.entry_points.append(implied_entry_point)

                for new_entry_point in new_entry_points:
                    move_id = movemanager.move_id_for_binary_addr[new_entry_point]
                    runtime_addr = movemanager.b2r(new_entry_point)
                    self.add_entry(new_entry_point, runtime_addr, move_id=move_id, name=None)

        # Calculate the CPU states and analyse the code to add commentary
        self.analyse_code()

        # Do regex style matches to find common code tropes and comment them
        self.analyse_with_regex()

        # We defer final label name generating (using LazyString) until tracing
        # is complete, since e.g. part way through tracing we may not have
        # identified any code at address X and that can affect the label name
        # used for address X.
        self.trace_done = True


    def generate_references(self):
        """Generate references from the label data.

        A label holds the binary_address of each location that references the label."""

        # DEBUG
        #for runtime_addr, label in self.labels.items():
        #    utils.debug("label {0} at runtime_addr: {1} has references: {2}".format(label.all_names(), hex(runtime_addr), [hex(x.binary_addr) for x in label.references]))

        trace.references = collections.defaultdict(list)

        for runtime_addr, label in self.labels.items():
            if label.references:
                label_move_id = label.relevant_active_move_ids[0] if label.relevant_active_move_ids else None

                binary_addr, move_id = movemanager.r2b(runtime_addr, label_move_id)
                if binary_addr == None:
                    # get the first of the possible move_ids suggested by the references and try that
                    best_guess_move_id = next(iter(sorted([ref_binary_loc.move_id for ref_binary_loc in label.references])), None)
                    binary_addr, move_id = movemanager.r2b(runtime_addr, best_guess_move_id)
                    if binary_addr == None:
                        binary_addr, move_id = movemanager.r2b(runtime_addr, None)

                if binary_addr != None:
                    binary_loc = BinaryLocation(binary_addr, move_id)
                    trace.references[binary_loc].extend(label.references)

        # DEBUG
        #for runtime_addr, label in self.labels.items():
        #    utils.debug("label {0} at runtime_addr: {1} has references: {2}".format(label.all_names(), hex(runtime_addr), [hex(x.binary_addr) for x in label.references]))

    def format_runtime_location(self, runtime_addr, move_id):
        result = config.get_assembler().hex4(runtime_addr)
        if move_id != movemanager.BASE_MOVE_ID:
            result += "[{0}]".format(move_id)
        return result

    def format_binary_location(self, binary_loc):
        return config.get_assembler().hex4(binary_loc.binary_addr)

    def add_references_comments(self):
        """Add comments showing the references"""

        for binary_loc, ref_binary_locs in trace.references.items():
            count = utils.count_with_units(len(ref_binary_locs), "time", "times")
            address_list = ", ".join(sorted(self.format_runtime_location(movemanager.b2r(ref_binary_loc.binary_addr), ref_binary_loc.move_id) for ref_binary_loc in ref_binary_locs))
            comment = "{0} referenced {1} by {2}".format(self.format_binary_location(binary_loc), count, address_list)

            disassembly.comment_binary(binary_loc, comment, word_wrap=False, align=Align.BEFORE_LABEL, auto_generated=True)

    def add_reference_frequency_table(self):
        """Output a frequency table of label references."""

        if len(trace.references) == 0:
            return []
        result = [""]

        comment = config.get_assembler().comment_prefix()
        result.append("%s Label references by decreasing frequency:" % comment)

        frequency_table = collections.defaultdict(int)

        longest_label_length = 0
        for runtime_addr, label in labelmanager.labels.items():
            if label.references:
                for move_id, names in label.all_names_by_move_id().items():
                    for name in names:
                        longest_label_length = max(longest_label_length, len(name))
                        frequency_table[name] += len(label.references)

        frequency_table = sorted(frequency_table.items(), key=lambda x: (-x[1], x[0]))
        for name, count in frequency_table:
            if count > 0:
                result.append("%s     %-*s %3d" % (comment, longest_label_length+1, name + ":", count))

        return result

    def label_maker(self, d):
        pass

    #
    # Regex style analysis
    #
    def find_common_code_with_regex(self):
        # Do nothing by default
        pass

    def analyse_with_regex(self):
        # No analysis done by default
        pass

    # Analysis shared between 6502 and 65C02
    def find_common_code_with_regex_for_6502_like_cpus(self):
        """Make sure that any code found with a regex is marked as code"""

        # Make a byte array of memory
        memory_binary = memorymanager.memory_binary
        bytes_array = bytes([0 if x is None else x for x in memory_binary])

        # For each pattern
        for tup in snippets:
            # Find all matches
            matches = re.finditer(tup[0].pattern, bytes_array)

            for match in matches:
                # Mark as code
                binary_addr = BinaryAddr(match.start())
                runtime_addr = movemanager.b2r(binary_addr)
                move_id = movemanager.move_id_for_binary_addr[binary_addr]
                trace.cpu.add_entry(binary_addr, runtime_addr, move_id, name=None)

    def analyse_with_regex_for_6502_like_cpus(self):
        # Make a byte array of memory
        memory_binary = memorymanager.memory_binary
        bytes_array = bytes([0 if x is None else x for x in memory_binary])

        # for each pattern
        for tup in snippets:
            # Find all matches
            matches = re.finditer(tup[0].pattern, bytes_array)
            #utils.debug("Hello: {0}".format(tup[0].pattern))

            for match in matches:
                binary_addr = match.start()
                move_id = movemanager.move_id_for_binary_addr[binary_addr]
                binary_loc = memorymanager.BinaryLocation(binary_addr, move_id)
                helper = SnippetHelper(memory_binary, binary_loc, match, tup[0].labels)
                tup[1](helper)
