"""
Disassembling code (and data).

Classifies bytes of binary data as code.

Classifications are effectively "things in the assembler input which
generate direct output", like instructions or data.

There is at most one classification for any address; in practice by
the end of disassembly there will be exactly one for all addresses in
the target range, because we'll classify anything left over as data.
"""

from __future__ import print_function
import classification
import collections
import config
import constant
import copy
import labelmanager
import mainformatter
import memorymanager
import movemanager
import re
import trace
import utils
from comment import Annotation, Comment
from align import Align

from movemanager import BinaryLocation
from memorymanager import BinaryAddr, RuntimeAddr
from align import Align
from format import Format

# A user supplied function that creates a label name based on context
user_label_maker_hook = None

# The set of labels that have not been explicitly set by the user, but
# just given a default label name by py8dis.
autogenerated_labels = set()

# `classifications` stores classifications indexed by binary address.
classifications = [None] * 64*1024

# `format_hint` stores formatter functions indexed by binary address.
format_hint = {}

# Optional labels are only output if they are used.
#
# `optional_labels` stores tuple (string, base_address, definable_inline) indexed by
# runtime address, as created by `optional_label()`
optional_labels = {}

# `constants` is a list of class Constant.
constants = []

# Annotations are comments or other raw strings output to the assembly.
#
# An address can have an arbitrary number of annotations; we may need
# to slide them around in the code slightly to fit them round multi-byte
# classifications. By using a list we preserve the relative order of
# additions. We do sort this based on the annotation priorities but
# this is a stable sort and preserves order for any particular
# annotation type.
annotations = collections.defaultdict(list)

# `inside_a_classification` is an arbitrary constant value.
#
# We assign this value to the second and subsequent bytes of a multi-byte
# classification (e.g. the operands of an instruction). Its actual value doesn't
# matter, as long as it's not None so we know these bytes have been classified.
inside_a_classification = 0


def set_user_label_maker_hook(hook):
    """Set the user supplied 'hook' function that makes label names."""

    global user_label_maker_hook
    assert user_label_maker_hook is None
    user_label_maker_hook = hook

def comment(runtime_addr, text, *, word_wrap=True, indent=0, align=Align.BEFORE_LABEL, auto_generated=False):
    """Add a comment.

    Define a comment string to appear in the assembly code at the
    given address in the output. The comment can be inlined (added
    to the end of the line), or standalone (a separate line of output).
    The comment can be automatically word wrapped.
    """

    binary_loc = movemanager.r2b_checked(runtime_addr)
    assert memorymanager.is_data_loaded_at_binary_addr(binary_loc.binary_addr)

    comment_binary(binary_loc, text, word_wrap=word_wrap, indent=indent, align=align, auto_generated=auto_generated)

def comment_binary(binary_loc, text, *, word_wrap=False, indent=0, align=Align.BEFORE_LABEL, auto_generated=True, priority=None):
    """Add a comment, either inline or standalone."""

    binary_loc = movemanager.make_binloc(binary_loc)
    new_comment = Comment(text, word_wrap, indent, align=align, priority=priority, auto_generated=auto_generated)

    # Avoid adding the same autogenerated comment multiple times at the same location.
    # This happens e.g. if the same OSWORD data block is used multiple times in a source.
    # Then the block can get the same comments multiple times.
    if auto_generated:
        # Get the final comment at the location
        entry = annotations[binary_loc][-1] if annotations[binary_loc] else None
        if entry:
            if entry.as_string(binary_loc.binary_addr) == new_comment.as_string(binary_loc.binary_addr):
                return

    annotations[binary_loc].append(new_comment)

def add_raw_annotation(binary_loc, text, *, align=Align.BEFORE_LABEL, priority=None):
    """Add a raw string to the output."""

    binary_loc = movemanager.make_binloc(binary_loc)
    annotations[binary_loc].append(Annotation(text, align, priority))

def add_constant(value, name, comment=None, align=Align.INLINE, format=Format.DEFAULT):
    """Create a named constant value."""

    # Make sure we don't add the same constant twice. Assert if trying to
    # redefine a constant with a different value.
    # TODO: inefficient linear search!
    for c in constants:
        if c.name == name:
            assert c.value == value
            return

    constants.append(constant.Constant(value, name, comment, align, format))

def is_simple_name(s):
    """Check the name is a simple valid label name.

    Must be a single letter or underscore followed by any number of
    alphanumerics or underscores"""

    assert utils.is_string_type(s)
    assert len(s) > 0

    def valid_first(c):
        return c.isalpha() or c == "_"
    def valid_later(c):
        return c.isalnum() or c == "_"
    return valid_first(s[0]) and all(valid_later(c) for c in s)

def add_label(runtime_addr, s, move_id, *, definable_inline=True):
    """Add a label at the given runtime address and move_id."""

    memorymanager.is_valid_runtime_addr(runtime_addr, True) # 0x10000 is valid for labels

    label = labelmanager.labels[runtime_addr]
    label.definable_inline = label.definable_inline and definable_inline
    if s is not None:
        if is_simple_name(s):
            label.add_explicit_name(s, move_id)
        else:
            label.add_expression(s, move_id)

    # Make sure the move_id specified is added in the list of relevant and active move ids,
    # since it can be used to annotate the reference
    if move_id and move_id not in label.relevant_active_move_ids:
        label.relevant_active_move_ids.append(move_id)

    return label

def add_optional_label(runtime_addr, s, *, base_addr=None, definable_inline=True):
    """Add a label at the given runtime address, but only output if used.

    When two consecutive bytes share a base label name (e.g. `userv`
    and `userv+1`) then `base_runtime_addr` points to the first byte."""

    assert 0 <= runtime_addr <= 0xffff

    # Check if already present
    if runtime_addr in optional_labels:
        assert optional_labels[runtime_addr] == (s, base_addr, definable_inline), "Optional label at {0} redefined, was {1}".format(hex(runtime_addr), optional_labels[runtime_addr][0])
        return

    # Check base_addr is valid
    if base_addr is not None:
        assert runtime_addr != base_addr
        assert 0 <= base_addr <= 0xffff
        assert base_addr in optional_labels
        assert optional_labels[base_addr][1] is None
    else:
        assert is_simple_name(s), "This is not a simple label name: {0}".format(s)
    optional_labels[runtime_addr] = (s, base_addr, definable_inline)

def add_local_label(runtime_addr, name, start_addr, end_addr, move_id=None):
    """Add a label at the given runtime address, valid only if referenced in the region specified.

    start_addr, end_addr are runtime addresses.
    """

    label = labelmanager.labels[runtime_addr]
    label.add_local_label(name, start_addr, end_addr, move_id)

def get_label(runtime_addr, binary_addr, move_id=None):
    """Get a label name (a lazy string) for the given runtime address.

    `binary_addr` is the equivalent binary address.
    `move_id` is for the active move."""

    runtime_addr = RuntimeAddr(runtime_addr)
    binary_addr = BinaryAddr(binary_addr)

    assert memorymanager.is_valid_runtime_addr(runtime_addr, True) # 0x10000 is valid for labels
    assert memorymanager.is_valid_binary_addr(binary_addr)
    assert move_id is None or movemanager.is_valid_move_id(move_id)

    # We ensure the labelmanager knows there's a label at this address so it can
    # emit a definition. It's tempting to try to defer this until
    # get_final_label() is called, but it's good to have the label exist as
    # early as possible - for example, this means post-tracing code analysis can
    # see where labels exist and what references them.

    # Ensure the label exists (with the appropriate active/relevant move ids)
    labelmanager.labels[runtime_addr]

    return utils.LazyString("%s", lambda: get_final_label(runtime_addr, binary_addr, move_id))

# TODO: May want to expose this to user as it may be useful in a user label maker hook
def is_code(binary_addr):
    """Is the given `binary_addr` classified as an instruction opcode?"""

    classification = classifications[binary_addr]
    if classification is None or classification == inside_a_classification:
        return False
    return classification.is_code(binary_addr)

def suggest_label_name(runtime_addr, binary_addr, move_id):
    """Return a label name and move ID, auto-creating if needed.

    `binary_addr` is the associated binary_address.

    returns a tuple for the label (label name, move_id) and a boolean
    is_autogenerated_label"""

    assert binary_addr is not None
    runtime_addr = RuntimeAddr(runtime_addr)

    # Work out the best move_id to use for the label.
    #
    # The basic idea is that:
    # (a) if we can assign a move ID based on a matching of binary_addr and
    #     runtime_addr move IDs then do that
    # (b) else *if* there is any existing label at the address we will use
    #     it's move_id rather than forcing a new label in BASE_MOVE_ID to
    #     be created.
    #
    # The actual rules are:
    #
    # 1. If a move ID is already specified, use that.
    # 2. Choose the move ID of the binary_address if it's the same
    #    as a move ID of the runtime address.
    # 3. Look for any label at the runtime address that has a
    #    `move_id` that matches one at either the runtime address or
    #    binary address. If found, we have got our ideal label so
    #    return that ((name, move ID), False) tuple.
    #    We look in order through the local labels, then the explicit
    #    labels, then the expressions.
    # 4. If there is only one valid move_id at the runtime address,
    #    select that move ID. (It makes more sense to create a label
    #    there than in the base move ID).
    # 5. All else has failed, so use the base move ID.

    # Rule 1
    if move_id is None:
        move_id = movemanager.move_id_for_binary_addr[binary_addr]
    move_ids2 = movemanager.move_ids_for_runtime_addr(runtime_addr)

    # Rule 2
    if move_id not in move_ids2:
        candidate_move_ids = list(move_ids2)
        if move_id != None:
            candidate_move_ids = [move_id] + candidate_move_ids

        # Get the label
        label = labelmanager.labels.get(runtime_addr)

        for candidate_move_id in candidate_move_ids:
            # Rule 3: Local labels
            if candidate_move_id in label.local_labels:
                for (name, start_addr, end_addr) in label.local_labels[candidate_move_id]:
                    if start_addr <= binary_addr < end_addr:
                        return ((name, candidate_move_id), False)

            # Rule 3: Explicit labels
            if candidate_move_id in label.explicit_names:
                for name in label.explicit_names[candidate_move_id]:
                    return ((name.text, candidate_move_id), False)

            # Rule 3: Expressions
            if candidate_move_id in label.expressions:
                for expression in label.expressions[candidate_move_id]:
                    return ((expression, candidate_move_id), False)

        if len(move_ids2) == 1:
            # Rule 4
            move_id = min(move_ids2)
        else:
            # Rule 5
            move_id = movemanager.BASE_MOVE_ID

    label = labelmanager.labels.get(runtime_addr)
    assert label is not None

    # If the runtime address has a label name, choose the first one.
    # Check the local labels, then explicit names then expressions in
    # our chosen move ID.
    # If that fails try the base move ID.

    # TODO: We might want to move this logic into the Label object, and
    # it could potentially pick one of its own explicit names out based
    # on binary_addr. For now we prefer the first one, since that's how the
    # code used to behave and we're trying to gradually refactor.

    # We are just returning the first name arbitrarily, since we
    # have no basis to choose anything else.

    # We look for a local label, explicit label or expression in the
    # current move_id, or failing that in the BASE_MOVE_ID.
    for (name, start_addr, end_addr) in label.local_labels[move_id]:
        if start_addr <= binary_addr < end_addr:
            return ((name, move_id), False)

    # return with the first explicit name if there is one
    for name in label.explicit_names[move_id]:
        return ((name.text, move_id), False)

    # return with the first expression name, if there is one
    for expression in label.expressions[move_id]:
        return ((expression, move_id), False)

    # Now do the same again, but with the BASE_MOVE_ID
    for (name, start_addr, end_addr) in label.local_labels[movemanager.BASE_MOVE_ID]:
        if start_addr <= binary_addr < end_addr:
            return ((name, move_id), False)

    for name in label.explicit_names[movemanager.BASE_MOVE_ID]:
        return ((name.text, None), False)

    for expression in label.expressions[movemanager.BASE_MOVE_ID]:
        return ((expression, move_id), False)

    # If no explicit label or expression is suitable, try the optional
    # labels.
    if runtime_addr in optional_labels:
        s, base_addr, definable_inline = optional_labels[runtime_addr]
        if not definable_inline:
            label.definable_inline = False
        if base_addr is not None:
            # TODO: If our "suggestion" is not acted on, we will have
            # added this base label unnecessarily. I don't think this
            # is a big deal, but ideally we wouldn't do it.
            add_label(base_addr, optional_labels[base_addr][0], None, definable_inline=definable_inline)
        return ((s, None), False) # TODO: optional labels don't have a move_id at the moment?

    # Make up a brand new label name.
    #
    # if the binary address is not code, then call it "lXXXX"
    binary_addr, _ = movemanager.r2b(runtime_addr)
    if binary_addr is None or not is_code(binary_addr):
        label = utils.force_case("l%04x" % runtime_addr)
    else:
        # TODO: Should probably be user-configurable, but maybe the "c"
        # prefix here is not ideal because I personally tend to mix it
        # up with the following hex digits - a letter > 'f' would be
        # better - perhaps "x" for "executable"? (should be
        # user-configurable as I say, but I am inclined to change the
        # default)

        # Assume label is "cXXXX", c for code, but may change to
        # "sub_cXXXX" or "loop_cXXXX"
        label = utils.force_case("c%04x" % runtime_addr)

        binary_loc_refs = trace.references.get(movemanager.BinaryLocation(binary_addr, move_id), [])

        if all(trace.cpu.is_subroutine_call(ref_binary_loc.binary_addr) for ref_binary_loc in binary_loc_refs):
            # Found a subroutine, label is "sub_XXXX"
            label = "sub_" + label
        else:
            # Look for loops
            #
            # If there is one reference, and it's a branch backwards to
            # the target address, and within loop_limit bytes of the
            # current address then it's a "loop_cXXXX" name.
            if len(binary_loc_refs) == 1:
                ref_binary_addr = list(binary_loc_refs)[0].binary_addr
                ref_runtime_addr = movemanager.b2r(ref_binary_addr)

                # TODO: Maybe check if the instruction at runtime_addr
                # is an RTS and don't use loop_ prefix if it is - or
                # getting fancier, check if there's a straight line
                # sequence terminating in RTS at runtime_addr and don't
                # use loop_ prefix in that case either
                if trace.cpu.is_branch_to(ref_binary_addr, runtime_addr):
                    if 0 <= ref_runtime_addr - runtime_addr < config.get_loop_limit():
                        label = "loop_" + label
                        if config.get_indent_loops():
                            while binary_addr <= ref_binary_addr:
                                c = classifications[binary_addr]
                                if c is not None:
                                    if c.is_code(binary_addr):
                                        c.indent(binary_addr)
                                    binary_addr += c.length()
                                else:
                                    binary_addr += 1
    return ((label, move_id), True)

# TODO: This could and probably should be memo-ised (cached)- this
# would improve efficiency and would also avoid any risk of a
# non-idempotent user label maker function causing weird behaviour
def label_maker(runtime_addr, binary_addr, move_id):
    """Get a label name via calling a user hook.

    `binary_addr` is the associated binary address using the `move_id`.

    Returns the tuple (label_name, move_id)."""

    assert trace.cpu.trace_done

    # Get a suggested label
    suggestion, is_autogenerated = suggest_label_name(runtime_addr, binary_addr, move_id)

    # if the user function is supplied, use it to select the name
    # passing in the suggestion we just made.
    if user_label_maker_hook is not None:
        user_suggestion = user_label_maker_hook(runtime_addr, binary_addr, suggestion)

        # If return value is a string, then make it a (label, move_id)
        # tuple. Bit hacky but it feels nicer not to force user hooks
        # to return a tuple.
        if utils.is_string_type(user_suggestion):
            user_suggestion = (user_suggestion, None)

        # if user changed the label to something new, then return it
        if user_suggestion is not None:
            if user_suggestion != suggestion:
                return user_suggestion

    # At this point, we are going with the original suggestion.
    # If the suggested label is autogenerated then register it as an
    # autogenerated label.
    if is_autogenerated:
        autogenerated_labels.add(suggestion[0])
    return suggestion

def get_final_label(runtime_addr, binary_addr, move_id):
    """Create a final label name for the given location.

    Returns the final label name"""
    assert trace.cpu.trace_done
    assert memorymanager.is_valid_runtime_addr(runtime_addr)
    assert memorymanager.is_valid_binary_addr(binary_addr)
    assert move_id is None or movemanager.is_valid_move_id(move_id)
    name, move_id = label_maker(runtime_addr, binary_addr, move_id)
    if is_simple_name(name):
        labelmanager.labels[runtime_addr].add_explicit_name(name, move_id)

    return name

def is_classified(binary_addr, length=1):
    """Is any address in the given range classified?"""

    return any(x is not None for x in classifications[binary_addr:binary_addr+length])

def add_classification(binary_addr, classification):
    """Sets the classification for the given address.

    A classification has a length in bytes. The first byte is
    classified with the given classification and all following bytes
    are marked with `inside_a_classification`.
    """

    binary_addr = BinaryAddr(binary_addr)
    assert classification is not None
    assert not is_classified(binary_addr, classification.length()), "Binary address {0} is already classified: {1}".format(hex(binary_addr), classification)

    classifications[binary_addr] = classification
    for i in range(1, classification.length()):
        classifications[binary_addr+i] = inside_a_classification

def get_classification(binary_addr):
    return classifications[binary_addr]

def fix_label_names():
    """Fix the final label names.

    get_label() returns LazyString objects so we can defer assignment
    of actual concrete label strings until we've finished the tracing
    process. This function forces a conversion of all label names to
    concrete strings in order to ensure that we have a full set of
    label definitions ready to emit.
    """

    assert trace.cpu.trace_done
    binary_addr = BinaryAddr(0)
    while binary_addr < len(classifications):
        c = classifications[binary_addr]
        if c is not None:
            move_id = movemanager.move_id_for_binary_addr[binary_addr]
            dummy = [str(x) for x in c.as_string_list(movemanager.BinaryLocation(binary_addr, move_id), None)]
            binary_addr += c.length()
        else:
            binary_addr += 1


def calculate_move_ranges():
    """Calculate contiguous memory ranges with a shared move ID."""

    move_ranges = []
    current_range_start = None
    current_range_move_id = None
    for start_addr, end_addr in sorted(memorymanager.load_ranges):
        binary_addr = start_addr
        while binary_addr < end_addr:
            if current_range_start is not None:
                if (binary_addr == current_range_end and movemanager.move_id_for_binary_addr[binary_addr] == current_range_move_id):
                    current_range_end = binary_addr + 1
                else:
                    move_ranges.append((current_range_start, current_range_end))
                    current_range_start = None
            if current_range_start is None:
                current_range_start = binary_addr
                current_range_end = binary_addr + 1
                current_range_move_id = movemanager.move_id_for_binary_addr[binary_addr]
            binary_addr += 1

    if current_range_start != current_range_end:
        move_ranges.append((current_range_start, current_range_end))

    return move_ranges

def constant_value_to_string(value, format):
    """Convert the given value of a constant, return the string value used to define the constant as specified by the format parameter"""

    # If given a string with no format specified, treat it as a string
    if isinstance(value, str) and (format == Format.DEFAULT):
        format = Format.STRING

    if (format == Format.DECIMAL) or ((format == Format.DEFAULT) and config.get_constants_are_decimal()):
        return str(value)
    elif (format == Format.HEX) or ((format == Format.DEFAULT) and not config.get_constants_are_decimal()):
        formatter = config.get_assembler()
        return formatter.hex(value)
    elif format == Format.BINARY:
        formatter = config.get_assembler()
        return mainformatter.binary_formatter(value, 8 if ((value >= 0) and (value < 256)) else 16)
    elif format == Format.STRING:
        formatter = config.get_assembler()
        return str('"' + value + '"')
    assert format == Format.CHAR, "unknown format {0}".format(format)
    return str("'" + value + "'")

def emit_constants():
    formatter = config.get_assembler()
    output = []

    if len(constants) == 0:
        return output

    # Length of indent string
    indent_len = len(config.get_indent_string())

    output.append("{0} Constants".format(formatter.comment_prefix()))

    # We want to align the equals symbols in the list of constants, so
    # we find the longest name. Add one to allow for a space after the name
    max_name_len = max(len(c.name)+1 for c in constants)
    max_name_len  = utils.round_up(max_name_len, indent_len)    # Round up to next indent level

    # Similarly, get the longest value as a string so we can align the comments
    # so that we can align the inline comments.
    max_value_len = max(len(constant_value_to_string(c.value, c.format)) for c in constants)

    # Comment column is after 'name = value'
    comment_column = max_name_len + 3 + max_value_len
    comment_column = utils.round_up(comment_column, indent_len) # Round up to next indent level

    # Natural sort the constants
    convert = lambda text: int(text) if text.isdigit() else text.lower()
    alphanum_key = lambda key: [convert(c) for c in re.split('([0-9]+)', key.name)]
    for c in sorted(constants, key=alphanum_key):
        value = constant_value_to_string(c.value, c.format)

        # output a comment on the line before the definition
        if (c.align == Align.BEFORE_LINE) or (c.align == Align.BEFORE_LABEL):
            output.append("{0}".format(mainformatter.format_comment(c.comment, indent=0)))

        # output the definition with an optional inline comment
        output.append(mainformatter.explicit_label_with_inline_comment(
            c.name,
            value,
            None,
            align_value_column=max_name_len,
            inline_comment=c.comment if c.align == Align.INLINE else None,
            align_comment_column=comment_column)
            )

        # output a comment on the line after the definition
        if (c.align == Align.AFTER_LINE) or (c.align == Align.AFTER_LABEL):
            output.append("{0}".format(mainformatter.format_comment(c.comment, indent=0)))
    output.append("")
    return output

def emit(print_output=True):
    """Outputs the disassembly.
    """

    formatter = config.get_assembler()
    output = []

    # Output any prologue
    output.extend(formatter.disassembly_start())

    # Length of indent string
    indent_len = len(config.get_indent_string())

    # Emit constants first
    output.extend(emit_constants())

    # For debugging py8dis output all labels, their addresses and move_ids
    if config.get_show_all_labels():
        output.extend(labelmanager.all_labels_as_comments())

    # Break the output down into sub-ranges which share the same move
    # ID. We completely ignore the classifications here; moves are more
    # important and can bisect a classification. We call isolate_range
    # to fix up the classifications afterwards.
    move_ranges = calculate_move_ranges()

    for start_addr, end_addr in move_ranges:
        isolate_range(start_addr, end_addr)

    # Generate the disassembly proper, but don't emit it just yet. We
    # do this so we can emit label definitions in the "best" move
    # region and then emit any leftover labels as explicit definitions
    # below.

    # d is the main disassembly output.
    d = []

    def record_emit_point(binary_addr, move_id):
        md = movemanager.move_definitions[move_id]
        runtime_addr = md.convert_binary_to_runtime_addr(binary_addr)
        labelmanager.labels[runtime_addr].notify_emit_opportunity(move_id)

    # Calculate the move_ids that will emit output?
    for start_addr, end_addr in move_ranges:
        move_id = movemanager.move_id_for_binary_addr[start_addr]
        if move_id != movemanager.BASE_MOVE_ID:
            record_emit_point(start_addr, movemanager.BASE_MOVE_ID)

        addr = start_addr
        while addr < end_addr:
            for i in range(0, classifications[addr].length()):
                record_emit_point(addr + i, move_id)
            addr += classifications[addr].length()
        assert addr == end_addr
        record_emit_point(end_addr, move_id)
        if move_id != movemanager.BASE_MOVE_ID:
            record_emit_point(end_addr, movemanager.BASE_MOVE_ID)

    # Output disassembly for each range in turn
    old_end_addr = None
    for start_addr, end_addr in move_ranges:
        if old_end_addr == None:
            # Output an ORG at the beginning
            d.extend(formatter.code_start(start_addr, end_addr, True))
            old_end_addr = start_addr

        move_id = movemanager.move_id_for_binary_addr[start_addr]

        # Handle start of a new !pseudopc block
        if move_id != movemanager.BASE_MOVE_ID:
            # Output any base move labels just before starting a new !pseudopc block
            d.extend(emit_labels(BinaryLocation(start_addr, movemanager.BASE_MOVE_ID), False))

            # Output start of !pseudopc block
            dest_runtime_addr = movemanager.b2r(start_addr)
            block_title_comment = mainformatter.format_comment("Move {0}: {1} to {2} for length {3}".format(move_id, config.get_assembler().hex(start_addr), config.get_assembler().hex(dest_runtime_addr), end_addr - start_addr), 0)
            d.extend(["", block_title_comment])
            pseudopc_args = (dest_runtime_addr, start_addr, end_addr - start_addr, move_id)
            d.extend(formatter.pseudopc_start(*pseudopc_args))
        else:
            # If a new ORG is needed, output that
            if start_addr != old_end_addr:
                d.extend(formatter.code_start(start_addr, end_addr, False))

        # output at each address within the block
        was_code = None
        addr = start_addr
        while addr < end_addr:
            # if we have just transitioned from data to code, add a blank line
            now_is_code = is_code(addr)
            if now_is_code and was_code == False:
                d.extend([""])
            was_code = now_is_code

            # output the line itself
            d.extend(emit_addr(BinaryLocation(addr, move_id)))

            # move to the next address
            addr += classifications[addr].length()
        assert addr == end_addr

        # Emit labels at the end address of the move range
        d.extend(emit_labels(BinaryLocation(end_addr, move_id), True))

        # Handle the end of the !pseudopc block
        if move_id != movemanager.BASE_MOVE_ID:
            # Output the end of the !pseudopc block
            pseudopc_args = (movemanager.b2r(start_addr), start_addr, end_addr - start_addr, move_id)
            d.extend(formatter.pseudopc_end(*pseudopc_args))

            # Output any base move labels after the !pseudopc block is done
            d.extend(emit_labels(BinaryLocation(end_addr, movemanager.BASE_MOVE_ID), False))
        old_end_addr = end_addr


    # Emit labels which haven't been emitted inline with the disassembly.
    output.append("{0} Memory locations".format(formatter.comment_prefix()))

    # Find the longest such explicit label name
    align_name_length = labelmanager.find_max_explicit_name_length()
    align_name_length = indent_len * ((align_name_length + indent_len - 1) // indent_len)

    # Add the explicit label names (aligned) to the output
    for addr in sorted(labelmanager.labels):
        output.extend(labelmanager.labels[addr].explicit_definition_string_list(align_name_length))

    # Add the main disassembly to the output
    output.extend(d)

    # Show label reference histogram
    if config.get_label_references():
        output.extend(trace.cpu.add_reference_histogram())

    # Show auto-generated labels
    if config.get_show_autogenerated_labels():
        if len(autogenerated_labels) > 0:
            output.append("")
            output.append("{0} Automatically generated labels:".format(formatter.comment_prefix()))
            for label in sorted(autogenerated_labels):
                output.append("{0}     {1}".format(formatter.comment_prefix(), label))

    # Finish off disassembly
    output.extend(formatter.disassembly_end())

    # Join all lines of output
    result = "\n".join(formatter.sanitise(str(line)) for line in output)

    # Return the assembly listing
    return result

def split_classification(binary_addr):
    """If a move boundary is in the middle of an instruction etc, then
    split the classification."""

    if binary_addr >= 0x10000:
        return
    if classifications[binary_addr] != inside_a_classification:
        return

    # TODO: Do we need to check and not warn if this is just an automatic string/byte classification?
    utils.warn("move boundary at binary address {0} splits a classification".format(config.get_assembler().hex(binary_addr)))
    split_addr = binary_addr
    while classifications[binary_addr] == inside_a_classification:
        binary_addr -= 1
    first_split_length = split_addr - binary_addr
    classifications[split_addr] = classification.Byte(classifications[binary_addr].length() - first_split_length)
    classifications[binary_addr] = classification.Byte(first_split_length)

# It's possible (but unlikely) there is a multi-byte classification straddling the
# ends of our range; if so, split them so we can output the precise range wanted.
def isolate_range(start_addr, end_addr):
    """If a move boundary is in the middle of an instruction etc, then
    split the classification."""

    split_classification(start_addr)
    split_classification(end_addr)

def emit_labels(binary_loc, output_annotations=True):
    """Emit labels and non-inline annotations for the given address"""

    binary_loc = movemanager.make_binloc(binary_loc)

    result = []
    md = movemanager.move_definitions[binary_loc.move_id]
    runtime_addr = md.convert_binary_to_runtime_addr(binary_loc.binary_addr)

    if output_annotations:
        for annotation in utils.sorted_annotations(annotations[binary_loc]):
            if annotation.align == Align.BEFORE_LABEL:
                result.append(annotation.as_string(binary_loc.binary_addr))

    result.extend(labelmanager.labels[runtime_addr].definition_string_list(runtime_addr, binary_loc))

    if output_annotations:
        for annotation in utils.sorted_annotations(annotations[binary_loc]):
            if annotation.align == Align.AFTER_LABEL:
                result.append(annotation.as_string(binary_loc.binary_addr))
    return result

def emit_addr(binary_loc):
    """Emit labels, the output for the classification, any remaining
    annotations in the range of the classification"""

    result = []
    classification_length = classifications[binary_loc.binary_addr].length()

    # We queue up labels defined "within" a multi-byte classification first
    # because we might need to create a new label at binary_loc.binary_addr
    # to help in defining them.
    pending_labels = []
    for i in range(1, classification_length):
        runtime_addr = movemanager.b2r(binary_loc.binary_addr + i)
        if runtime_addr in labelmanager.labels:
            if labelmanager.labels[runtime_addr].definable_inline:
                label_list = labelmanager.labels[runtime_addr].definition_string_list(movemanager.b2r(binary_loc.binary_addr), binary_loc)
                pending_labels.extend(label_list)

    # Emit label definitions for this address.
    result.extend(emit_labels(binary_loc))

    # Emit any label definitions for addresses within the classification.
    result.extend(pending_labels)

    # Emit any annotations before outputting the line itself
    for annotation in utils.sorted_annotations(annotations[binary_loc]):
        if annotation.align == Align.BEFORE_LINE:
            result.append(annotation.as_string(binary_loc.binary_addr))

    # Emit the classification itself.
    result.extend(classifications[binary_loc.binary_addr].as_string_list(binary_loc, annotations))

    # Emit any annotations before outputting the line itself
    for annotation in utils.sorted_annotations(annotations[binary_loc]):
        if annotation.align == Align.AFTER_LINE:
            result.append(annotation.as_string(binary_loc.binary_addr))

    # Emit any annotations which would fall within the classification.
    # We do this after the classification itself; this does have some
    # logic (we're "rounding to the end of the classification") and in
    # particular this works better than "rounding to start" does with
    # the current way overlapping instructions are emitted as comments.
    for i in range(1, classification_length):
        binary_loc = BinaryLocation(binary_loc.binary_addr + 1, binary_loc.move_id)

        for annotation in utils.sorted_annotations(annotations[binary_loc]):
            if annotation.align != Align.INLINE:
                result.append(annotation.as_string(binary_loc.binary_addr))

    return result
