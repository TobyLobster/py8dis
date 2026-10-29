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
import session
import re
import trace
import utils
from memorymanager import BinaryLocation
from comment import OverlappingInstruction
from align import Align
from maker import make_hex, make_lo, make_hi, make_or, make_and, make_eor, make_xor, make_add, make_subtract, make_multiply, make_divide, make_modulo
from memorymanager import BinaryAddr, RuntimeAddr



class Cpu:
    """Abstract base class representing a CPU"""

    def __init__(self):
        # (The CPU belongs to the session: see session.py and load(). It must
        # not read the session here, since it may be made before load() is
        # called.)
        self.subroutine_hooks = {}
        self.opcodes = {}
        self.entry_points = []
        self.explicit_entry_points = set()  # binary addresses given as entry points by the user (or a helper like code_ptr()), not just found by tracing
        self.traced_entry_points = set()
        # Snippet matches ignored because they start in the middle of an
        # instruction, as (snippet index, binary address): see
        # snippethelper.SnippetRejected
        self.rejected_snippet_matches = set()
        self.code_analysis_fns = []
        self.trace_done = False

        # After we have traced to classify where the code is, we record what we
        # know about the CPU state after each instruction. This is used to
        # analyse the code. e.g. We look to see if we set a register with an
        # immediate mode constant before a subroutine call so that we can give
        # that constant a proper symbol name.
        self.cpu_states = [None] * 64*1024


    def memory_regions(self):
        """Regions of memory the CPU defines, as for
        disassembly.add_memory_region(): (start, end, name), 'end' exclusive."""
        return []

    def disassemble_instruction(self, binary_addr):
        """
        Disassemble an instruction at the binary address.

        Identifies the opcode and calls into the opcode object to do
        the actual disassembly.

        Returns a list of possible new addresses, the first entry
        being the address of the next instruction, and the next
        entry being the destination of a jump or branch instruction.
        """

        memory_binary = session.current().memory.binary
        assert isinstance(binary_addr, memorymanager.BinaryAddr)

        # Tracing stops at the top of memory (rather than wrapping round to
        # &0000), as it does at the end of the loaded data
        if binary_addr >= 0x10000:
            return [None]
        opcode_value = memory_binary[binary_addr]
        if opcode_value not in self.opcodes:
            return [None]
        opcode = self.opcodes[opcode_value]
        # (An instruction that would run past the top of memory isn't one)
        if binary_addr + opcode.length() > 0x10000:
            return [None]

        with session.current().moves.move_id_for_binary_addr[binary_addr] as move_id:
            binary_loc = BinaryLocation(binary_addr, move_id)

            # If we hit something that's already classified, we can't/don't
            # re-classify it but that doesn't mean we can't continue to
            # trace until something breaks the control flow.
            if classification.is_classified(binary_addr, 1 + opcode.operand_length):
                # Show the instruction in a comment. (It's formatted when it's
                # output, once its labels are named.)
                disassembly.add_annotation(binary_loc, OverlappingInstruction(binary_loc, opcode.length(), opcode.instruction(binary_addr)))
            else:
                # Check if we run out of binary within this instruction
                if not memorymanager.is_data_loaded_at_binary_addr(binary_addr, 1 + opcode.operand_length):
                    # Mark the final partial instruction as being data, not code
                    for i in range(1, 1 + opcode.operand_length):
                        if memory_binary[binary_addr + i] is not None:
                            classification.add_classification(binary_addr, classification.Byte(1))
                        else:
                            break
                    return [None]

                # Classify the address as code
                classification.add_classification(binary_addr, opcode)
                opcode.update_references(binary_loc)

            # Call the opcode routine to work out the list of next addresses to disassmble
            result = opcode.disassemble(binary_loc)
            return result

    def add_entry(self, binary_addr, runtime_addr, move_id, name, *, explicit=False):
        """Add code entry point.

        `explicit` is True for an entry point given by the user (e.g. via
        entry()), rather than one found by tracing."""

        assert not isinstance(binary_addr, memorymanager.RuntimeAddr)
        assert not isinstance(runtime_addr, memorymanager.BinaryAddr)
        self.entry_points.append(binary_addr)
        if explicit:
            self.explicit_entry_points.add(binary_addr)
        runtime_addr = movemanager.b2r(binary_addr)
        disassembly.add_label(runtime_addr, name, move_id, is_autogenerated=False)

    # The most times the code is traced again from the entry points found
    # from what it does (see trace())
    MAX_EFFECT_PASSES = 20

    def calculate_cpu_states(self):
        """Calculate what we know about the CPU state for each instruction
        (in cpu_states)."""
        binary_addr = 0
        state = self.CpuState()
        # (Only the loaded data can be classified, so just loop over that)
        for range_start, range_end in memorymanager.loaded_ranges():
            binary_addr = max(binary_addr, range_start)
            while binary_addr < range_end:
                c = classification.get_classification(binary_addr)
                if c is not None:
                    if c.is_code(binary_addr):
                        c.update_cpu_state(binary_addr, state)
                        # (Use the state's own copy() if it has one, since copy.deepcopy() is slow)
                        self.cpu_states[binary_addr] = state.copy() if hasattr(state, "copy") else copy.deepcopy(state)
                    else:
                        state = self.CpuState()
                    binary_addr += c.length()
                else:
                    binary_addr += 1

    def find_entry_points_from_effects(self):
        """Find entry points from what the code does, using the CPU states
        (e.g. the address stored to a vector), adding them with add_entry().
        Called by trace() once the CPU states are known, and again after each
        time the entry points it adds have been traced. (None by default.)"""
        pass

    def analyse_code(self, *, calculate_states=True):
        """Calculates what we know about the CPU state for each instruction
        (unless calculate_states is False, when it's already known) then
        runs code analysis. e.g. We look to see if we set a register with an
        immediate mode constant before a subroutine call so that we can give
        that constant a proper symbol name."""

        if calculate_states:
            self.calculate_cpu_states()

        # Call each of the code analysis functions, then the session's (e.g.
        # from acorn.py, which may be set up before the CPU is chosen)
        for f in self.code_analysis_fns:
            f()
        for f in session.current().trace.analysis_hooks:
            f()

    def trace(self):
        """Trace all the code from the entry points."""

        # First trace from the entry points given so far
        self.trace_entry_points()

        # We have a number of regular expressions that represent common segments
        # of code and/or data. If we find a match, we can mark code as an
        # entry() point for tracing. (This is done once the code found so far
        # has been traced, so that a match that starts in the middle of an
        # instruction can be ignored: see snippethelper.SnippetRejected. Each
        # match's entry points are traced before the next match is looked at.)
        self.pre_trace_with_regex()
        self.trace_entry_points()

        # Then the entry points found from what the code does, which needs
        # the CPU states. Tracing them can find more code, and add labels,
        # which change the CPU states (a label loses what's known), so this
        # is repeated until no more are found.
        for _ in range(self.MAX_EFFECT_PASSES):
            self.calculate_cpu_states()
            self.find_entry_points_from_effects()
            if len(self.entry_points) == 0:
                break
            self.trace_entry_points()
        else:
            utils.warn("tracing found new entry points from what the code does {0} times, and stopped there".format(self.MAX_EFFECT_PASSES))
            self.calculate_cpu_states()

        # Generate all the references
        self.generate_references()

        # Analyse the code to add commentary (the CPU states are already known)
        self.analyse_code(calculate_states=False)
        
        # Now we have traced and analysed the code we can again look for regex matches
        # and comment in more detail, knowing the cpu_cache for the state of registers 
        # at each instruction can tell us for example how many times we execute a loop.
        self.post_trace_with_regex()

        # We defer final label name generating (using LazyString) until tracing
        # is complete, since e.g. part way through tracing we may not have
        # identified any code at address X and that can affect the label name
        # used for address X.
        self.trace_done = True


    def trace_entry_points(self):
        """Trace the code from each entry point in 'entry_points', and the
        entry points found by doing so, until there are none left."""

        # As each instruction is processed, the next possible instructions
        # are added to the 'entry_points' list. The first of these will be
        # the following instruction (if there is one; it might be None).
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
                    move_id = session.current().moves.move_id_for_binary_addr[new_entry_point]
                    runtime_addr = movemanager.b2r(new_entry_point)
                    self.add_entry(new_entry_point, runtime_addr, move_id=move_id, name=None)

    def generate_references(self):
        """Generate references from the label data.

        A label holds the binary_address of each location that references the label."""

        # DEBUG
        #for runtime_addr, label in session.current().labels.labels.items():
        #    utils.debug("label {0} at runtime_addr: {1} has references: {2}".format(label.all_names(), hex(runtime_addr), [hex(x.binary_addr) for x in label.references]))

        memory_binary = session.current().memory.binary
        session.current().trace.references = collections.defaultdict(list)

        def reached_in_move(runtime_addr, ref_binary_loc):
            """If the runtime address is in the same move as the referring
            instruction, and the binary data there is loaded and belongs to
            that move, return the binary address, otherwise None."""

            move_id = ref_binary_loc.move_id
            md = session.current().moves.move_definitions[move_id]
            if not md.is_in_move_dest(runtime_addr, include_end_address=False):
                return None
            binary_addr = md.convert_runtime_to_binary_addr(runtime_addr)
            if memory_binary[binary_addr] is None:
                return None
            if session.current().moves.move_id_for_binary_addr[binary_addr] != move_id:
                return None

            # A jump, call or branch into the middle of an instruction in its
            # own move is more likely to be reaching a different move's code
            # at that address (unlike a data reference, e.g. self modifying
            # code changing an operand).
            if classification.get_classification(binary_addr) is classification.INSIDE_A_CLASSIFICATION:
                ref = classification.get_classification(ref_binary_loc.binary_addr)
                if getattr(ref, "could_be_call_to_subroutine", lambda: False)():
                    return None
            return binary_addr

        for runtime_addr, label in session.current().labels.labels.items():
            if not label.references:
                continue

            # The location to use when a reference doesn't tell us where it goes
            label_move_id = label.relevant_active_move_ids[0] if label.relevant_active_move_ids else None
            default_binary_addr, default_move_id = movemanager.r2b(runtime_addr, label_move_id)
            if default_binary_addr is None:
                # get the first of the possible move_ids suggested by the references and try that
                best_guess_move_id = next(iter(sorted([ref_binary_loc.move_id for ref_binary_loc in label.references])), None)
                default_binary_addr, default_move_id = movemanager.r2b(runtime_addr, best_guess_move_id)
                if default_binary_addr is None:
                    default_binary_addr, default_move_id = movemanager.r2b(runtime_addr, None)

            for ref_binary_loc in label.references:
                # Code refers to the copy of the runtime address in its own
                # move, if there is one (e.g. where several moves put code at
                # the same runtime address, a branch goes to the code in the
                # same move as the branch).
                binary_addr = reached_in_move(runtime_addr, ref_binary_loc)
                if binary_addr is not None:
                    move_id = ref_binary_loc.move_id
                else:
                    binary_addr, move_id = default_binary_addr, default_move_id

                if binary_addr is not None:
                    session.current().trace.references[BinaryLocation(binary_addr, move_id)].append(ref_binary_loc)

        # DEBUG
        #for runtime_addr, label in session.current().labels.labels.items():
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

        for binary_loc, ref_binary_locs in session.current().trace.references.items():
            count = utils.count_with_units(len(ref_binary_locs), "time", "times")
            address_list = ", ".join(sorted(self.format_runtime_location(movemanager.b2r(ref_binary_loc.binary_addr), ref_binary_loc.move_id) for ref_binary_loc in ref_binary_locs))
            comment = "{0} referenced {1} by {2}".format(self.format_binary_location(binary_loc), count, address_list)

            disassembly.comment_binary(binary_loc, comment, word_wrap=False, align=Align.BEFORE_LABEL, auto_generated=True)

    def add_reference_frequency_table(self):
        """Output a frequency table of label references."""

        if len(session.current().trace.references) == 0:
            return []
        result = [""]

        comment = config.get_assembler().comment_prefix()
        result.append("%s Label references by decreasing frequency:" % comment)

        frequency_table = collections.defaultdict(int)

        longest_label_length = 0
        for runtime_addr, label in session.current().labels.labels.items():
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
    def pre_trace_with_regex(self):
        # Do nothing by default
        pass

    def post_trace_with_regex(self):
        # Do nothing by default
        pass

