"""
CPU

The base class of the CPUs (Cpu). The session's CPU does most of the work of
tracing: following ('tracing') the code from its entry points to find which
bytes are code, classifying each instruction it reaches as code, and then
working out what's known about the registers and flags after each
instruction (the 'CPU state'), which the analysis after tracing uses to add
comments, find more code and name things.

Each CPU is a class derived from Cpu, in its own module: cpu6502.py (with
cpu6510.py and cpu65C02.py derived from it), cpu8080.py and cpuz80.py.
load() (see commands.py) makes the session's CPU (session.current().cpu)
from the name it's given, and go() calls its trace(). After that,
disassembly.py asks it how to name labels (label_maker(),
is_subroutine_call(), is_branch_to()), and go() has it add the 'referenced
by' comments.

Two kinds of address are used: a binary address is where a byte is in the
loaded binary (memorymanager.BinaryAddr), and a runtime address is where it
is when the code runs (memorymanager.RuntimeAddr). They differ for code
that's moved, i.e. copied elsewhere to run (see movemanager.py), and then a
move ID says which move a runtime address is in. Tracing works with binary
addresses, and labels are at runtime addresses.
"""

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
    """The base class of the CPUs. A CPU is responsible for:

    - decoding instructions: 'opcodes' maps each opcode to an opcode object
      (see opcode_at()). The same object is the classification of every
      instruction with that opcode (see classification.py), so its methods
      take the instruction's binary address. It says how long the
      instruction is, where the code goes after it (disassemble()), which
      addresses it refers to (update_references()), how it's written in the
      output (as_lines()) and what it does to the CPU state
      (update_cpu_state());
    - tracing: trace() follows the code from the entry points (add_entry()),
      classifying each instruction as code. A subroutine hook
      (hook_subroutine()) can say where a call to a subroutine returns to,
      for a subroutine that doesn't return normally;
    - following the CPU state: calculate_cpu_states() works out what's known
      after each instruction (e.g. known register values), as a CpuState in
      'cpu_states';
    - analysing the code once it's traced: the functions in
      'code_analysis_fns' use the CPU states to add comments and name
      constants (e.g. Cpu6502.substitute_constants()), and the snippets'
      functions (pre_trace_with_regex(), post_trace_with_regex()) and
      find_entry_points_from_effects() find more code;
    - naming: label_maker() can give some labels names of the CPU's own
      (e.g. 'return_1'), and the references to labels found while tracing
      give the 'referenced by' comments and the frequency table at the end.

    A CPU class provides 'opcodes' (in its __init__()) and its opcode
    classes; a CpuState class (with a copy() method if it can be copied
    faster than with copy.deepcopy()); 'indent_level_dict' ({binary address:
    extra indent}, for indenting loops: see config.set_indent_loops()); and
    the methods hook_subroutine(),
    get_target_binary_addr_preferring_given_move_id() (used by the opcode
    classes and commodore.py), is_subroutine_call() and is_branch_to() (used
    to name labels 'sub_...' and 'loop_...'). It can also provide
    default_subroutine_hook() (for subroutine()) and straight_runs() (used
    by effect patterns and the machine modules), and override opcode_at(),
    memory_regions() and the methods here that do nothing by default
    (find_entry_points_from_effects(), label_maker(),
    pre_trace_with_regex() and post_trace_with_regex())."""

    def __init__(self):
        """Start with no opcodes, entry points or hooks."""
        # (The CPU belongs to the session: see session.py and load(). It must
        # not read the session here, since it may be made before load() is
        # called.)

        # The subroutine hooks, by runtime address (see hook_subroutine())
        self.subroutine_hooks = {}
        # The opcode objects, by opcode (filled in by the derived class)
        self.opcodes = {}
        # The binary addresses still to trace, in the order they'll be traced
        # (see trace_entry_points())
        self.entry_points = []
        self.explicit_entry_points = set()  # binary addresses given as entry points by the user (or a helper like code_ptr()), not just found by tracing
        # The binary addresses already traced, which aren't traced again. (So
        # nonentry() adds an address here to stop tracing there.)
        self.traced_entry_points = set()
        # Snippet matches ignored because they start in the middle of an
        # instruction (or a snippet's function rejected them), as (snippet
        # index, binary address), or (snippet index, match key) for an effect
        # pattern's: see snippethelper.SnippetRejected
        self.rejected_snippet_matches = set()
        # The functions to call (with no arguments) to analyse the code once
        # it's traced and the CPU states are known (see analyse_code())
        self.code_analysis_fns = []
        # True once trace() has finished, after which labels can be named
        # (see disassembly.py)
        self.trace_done = False

        # After we have traced to classify where the code is, we record what we
        # know about the CPU state after each instruction. This is used to
        # analyse the code. e.g. We look to see if we set a register with an
        # immediate mode constant before a subroutine call so that we can give
        # that constant a proper symbol name. (By binary address: the state
        # after the instruction there, or None if it isn't code.)
        self.cpu_states = [None] * 64*1024


    def opcode_at(self, binary_addr):
        """The opcode at binary_addr (from 'opcodes'), or None if there isn't
        one. (The Z80's has prefixes to look at.)"""
        return self.opcodes.get(session.current().memory.binary[binary_addr])

    def memory_regions(self):
        """Regions of memory the CPU defines, as for
        disassembly.add_memory_region(): (start, end, name), 'end' exclusive."""
        return []

    def disassemble_instruction(self, binary_addr):
        """
        Trace the instruction at binary_addr, returning what to trace next.

        Finds the opcode (opcode_at()), classifies the instruction as code
        and records the addresses it refers to (the opcode's
        update_references()), then asks the opcode object where the code
        goes next (its disassemble()). This is all done in the
        instruction's own move, so that runtime addresses are looked up
        there first.

        Returns a list of binary addresses: the first is the next instruction
        (or None if the code doesn't run on to it, e.g. after a return or a
        jump), and any others are the targets of a jump, call or branch.
        Returns [None] if there's no instruction here: an unknown opcode, the
        top of memory, or the end of the loaded data part way through the
        instruction.

        If any of the instruction's bytes are already classified (e.g. as
        data, or as part of another instruction), it isn't classified (and
        its references aren't recorded): it's shown in a comment there
        instead, and tracing carries on from it.
        """

        memory_binary = session.current().memory.binary
        assert isinstance(binary_addr, memorymanager.BinaryAddr)

        # Tracing stops at the top of memory (rather than wrapping round to
        # $0000), as it does at the end of the loaded data
        if binary_addr >= 0x10000:
            return [None]
        opcode = self.opcode_at(binary_addr)
        if opcode is None:
            return [None]
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
                    # Mark the final partial instruction as being data, not
                    # code. (This classifies the opcode byte as a byte of
                    # data, if the byte after it is loaded. The bytes left
                    # unclassified become data at the end anyway: see
                    # classification.classify_leftovers().)
                    if memory_binary[binary_addr + 1] is not None:
                        classification.add_classification(binary_addr, classification.Byte(1))
                    return [None]

                # Classify the address as code
                classification.add_classification(binary_addr, opcode)
                opcode.update_references(binary_loc)

            # Call the opcode routine to work out the list of next addresses to disassmble
            result = opcode.disassemble(binary_loc)
            return result

    def jump_target(self, target_runtime_addr, binary_loc, *, prefer_own_move=False):
        """The binary address to trace for a jump, call or branch to
        target_runtime_addr from the instruction at binary_loc, as a list
        (empty if there isn't one).

        With 'prefer_own_move' (for a branch), the target is in the
        instruction's own move if that move has the address and data is
        loaded there. Otherwise it's in the one move that puts code there, if
        there's only one (e.g. a jump from the main code to code that's
        copied elsewhere to run), or else in the instruction's own move
        anyway. If more than one move puts code there (e.g. several banks of
        code that all run at $8000), and the instruction isn't in one of
        them, which one it reaches isn't known: it isn't traced from here,
        with a warning."""
        own_binary_addr = None
        if prefer_own_move:
            own_binary_addr, _ = movemanager.r2b(target_runtime_addr, binary_loc.move_id)
            if own_binary_addr is not None and memorymanager.is_data_loaded_at_binary_addr(own_binary_addr, 1):
                return [own_binary_addr]
        binary_addr, _ = movemanager.r2b(target_runtime_addr)
        if binary_addr is not None and (own_binary_addr is None or memorymanager.is_data_loaded_at_binary_addr(binary_addr, 1)):
            return [binary_addr]
        if own_binary_addr is not None:
            return [own_binary_addr]
        h = config.get_assembler().hex
        move_ids = sorted(movemanager.move_ids_for_runtime_addr(target_runtime_addr))
        utils.warn("{0}: the jump or call to {1} isn't traced, since more than one move puts code there (moves {2}): trace the right one with entry() in a 'with' block for its move".format(
            h(movemanager.b2r(binary_loc.binary_addr)), h(target_runtime_addr), utils.and_list([str(m) for m in move_ids])))
        return []

    def add_entry(self, binary_addr, runtime_addr, move_id, name, *, explicit=False):
        """Add a code entry point: the code at binary_addr is traced the next
        time trace_entry_points() runs, and gets a label in move_id, named
        'name' (or an auto-generated name, if it's None).

        `explicit` is True for an entry point given by the user (e.g. via
        entry()), rather than one found by tracing. Its label is then named
        as a subroutine's ('sub_...'), and code is taken to come there from
        elsewhere (e.g. it ends a straight run: see
        Cpu6502.straight_runs()).

        (The label's runtime address is worked out from binary_addr: the
        runtime_addr given is only checked not to be a binary address.)"""

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
        """Calculate what we know about the CPU state after each instruction
        (in cpu_states).

        This goes through the code in binary address order, passing one
        CpuState from each instruction to the next, and each instruction's
        update_cpu_state() changes it for what that instruction does. So the
        state after an instruction is worked out from the code before it in
        memory: it's up to the instruction to forget what may not be true,
        e.g. at a label (since code can jump there from elsewhere) or after
        a jump. Anything that isn't code (data) starts a new, empty
        state."""
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
        runs code analysis: each of code_analysis_fns, then the session's
        analysis hooks (trace.analysis_hooks). e.g. We look to see if we set
        a register with an immediate mode constant before a subroutine call
        so that we can give that constant a proper symbol name."""

        if calculate_states:
            self.calculate_cpu_states()

        # Call each of the code analysis functions, then the session's (e.g.
        # from acorn.py, which may be set up before the CPU is chosen)
        for f in self.code_analysis_fns:
            f()
        for f in session.current().trace.analysis_hooks:
            f()

    def trace(self):
        """Trace all the code from the entry points, then analyse it (called
        by go()).

        This traces from the entry points given, then from those that the
        snippets find, then (repeatedly) from those found from what the code
        does. Then it records which labels each instruction refers to
        (generate_references()), works out the comments and names from what
        the code does (analyse_code() and the snippets' post-trace
        functions), and sets trace_done."""

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
        # and comment in more detail: knowing the state of the registers at
        # each instruction (cpu_states) can tell us for example how many times
        # we execute a loop.
        self.post_trace_with_regex()

        # We defer final label name generating (using LazyString) until tracing
        # is complete, since e.g. part way through tracing we may not have
        # identified any code at address X and that can affect the label name
        # used for address X.
        self.trace_done = True


    def trace_entry_points(self):
        """Trace the code from each entry point in 'entry_points', and the
        entry points found by doing so, until there are none left.

        Each address is traced once (see traced_entry_points), as a queue:
        the addresses each instruction leads to are added to the end of the
        list. The target of a jump, call or branch gets a label (with
        add_entry()), but the next instruction doesn't."""

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
        """Generate references from the label data, as
        trace.references: {the binary location referred to: [the binary
        locations of the instructions that refer to it]}.

        A label holds the binary location of each instruction that refers to
        its runtime address (see each opcode's update_references()). Here
        each of those is matched to the binary location it reaches: the
        copy of the address in the instruction's own move, if that move has
        it, and otherwise a default for the label. The default is the copy
        in the label's first relevant move (or, if it has none, the one
        move with the address); failing that, the copy in the lowest
        numbered move that an instruction referring to it is in; and
        failing that, the one move with the address."""

        # DEBUG
        #for runtime_addr, label in session.current().labels.labels.items():
        #    utils.debug("label {0} at runtime_addr: {1} has references: {2}".format(label.all_names(), hex(runtime_addr), [hex(x.binary_addr) for x in label.references]))

        memory_binary = session.current().memory.binary
        session.current().trace.references = collections.defaultdict(list)

        def reached_in_move(runtime_addr, ref_binary_loc):
            """If the runtime address is in the same move as the referring
            instruction, and the binary data there is loaded and belongs to
            that move, return the binary address, otherwise None. (Also None
            for a jump, call or branch into the middle of an instruction:
            see below.)"""

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
        """A runtime address in hex, for a 'referenced by' comment, with the
        move ID after it in brackets if it isn't the base move, e.g.
        '$0902[1]'."""
        result = config.get_assembler().hex4(runtime_addr)
        if move_id != movemanager.BASE_MOVE_ID:
            result += "[{0}]".format(move_id)
        return result

    def format_binary_location(self, binary_loc):
        """The binary address of binary_loc in hex, for the start of a
        'referenced by' comment."""
        return config.get_assembler().hex4(binary_loc.binary_addr)

    def add_references_comments(self):
        """Add comments showing the references (from
        generate_references()): before each location that's referred to,
        e.g. '$2002 referenced 2 times by $200b, $2010', with the binary
        address referred to and the runtime addresses of the instructions
        that refer to it. (Called by go() if config.get_label_references().)"""

        for binary_loc, ref_binary_locs in session.current().trace.references.items():
            count = utils.count_with_units(len(ref_binary_locs), "time", "times")
            address_list = ", ".join(sorted(self.format_runtime_location(movemanager.b2r(ref_binary_loc.binary_addr), ref_binary_loc.move_id) for ref_binary_loc in ref_binary_locs))
            comment = "{0} referenced {1} by {2}".format(self.format_binary_location(binary_loc), count, address_list)

            disassembly.comment_binary(binary_loc, comment, word_wrap=False, align=Align.BEFORE_LABEL, auto_generated=True)

    def add_reference_frequency_table(self):
        """Output a frequency table of label references: the lines of
        comments for the end of the output, listing each name of each label
        that's referred to, with the number of references to its address,
        most first (and then by name). Empty if nothing is referred to."""

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
        """Change the label name suggested in 'd' (a LabelMakingData: see
        disassembly.suggest_label_name()), if this CPU names some labels its
        own way, e.g. 'return_1' for a return instruction. Called for each
        label name chosen, before the user's label maker hook. (Does nothing
        by default.)"""
        pass

    #
    # Regex style analysis
    #
    def pre_trace_with_regex(self):
        """Run the snippets' pre-trace functions, which can add entry points
        (see Cpu6502.pre_trace_with_regex()). Called by trace() once the
        entry points given have been traced."""
        # Do nothing by default
        pass

    def post_trace_with_regex(self):
        """Run the snippets' post-trace functions, which can add comments and
        expressions using the CPU states (see
        Cpu6502.post_trace_with_regex()). Called by trace() at the end."""
        # Do nothing by default
        pass

