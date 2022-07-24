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
import copy

import config
import labelmanager
import memorymanager
import movemanager
import trace
import utils

user_label_maker_hook = None

autogenerated_labels = set()

# `classifications` stores classifications indexed by binary address.
classifications = [None] * 64*1024

# `format_hint` stores formatter functions indexed by binary address.
format_hint = {}

# `optional_labels` stores tuple (string, base_address) indexed by
# runtime address, as created by `optional_label()`
optional_labels = {}

# `constants` is a list of (value, name) tuples.
constants = []

# Annotations are comments or other raw strings output to the assembly.
#
# An address can have an arbitrary number of annotations; we may need
# to slide them around in the code slightly to fit them round multi-byte
# classifications. By using a list we preserve the relative order of
# additions; we do sort this based on the annotation priorities but
# this is a stable sort and preserves order for any particular
# annotation type.
annotations = collections.defaultdict(list)

# We assign the `partial_classification` constant value to the second
# and subsequent bytes of a multi-byte classification (e.g. The
# operands of an instruction). Its value doesn't really matter, as long
# as it's not None so we know these bytes have been classified.
partial_classification = 0


# TODO: We should probably check all disassembly ranges are non-overlapping and merge any adjacent ones.


def set_user_label_maker_hook(hook):
    """Set the 'hook' function that makes label names."""

    global user_label_maker_hook
    assert user_label_maker_hook is None
    user_label_maker_hook = hook

def add_comment(addr, text, inline=False, priority=None):
    """Add a comment, either inline or standalone."""

    # TODO: The Comment object may no longer add value. And/or we may
    # want to tweak how this works so Comment objects can contain
    # LazyStrings that aren't evaluated immediately on construction.
    annotations[addr].append(Comment(text, inline, priority))

def add_raw_annotation(addr, text, inline=False, priority=None):
    """Add a raw string to the output."""

    annotations[addr].append(Annotation(text, inline, priority))

def add_constant(value, name):
    """Create a named constant value."""

    # TODO: inefficient linear search!
    for v, n in constants:
        if n == name:
            assert v == value
            return
    constants.append((value, name))

def is_simple_name(s):
    """Check the name is a simple valid label name.

    Must be a single letter or underscore followed by any number of alphanumerics or underscores"""

    assert utils.is_string_type(s)
    assert len(s) > 0

    def valid_first(c):
        return c.isalpha() or c == "_"
    def valid_later(c):
        return c.isalnum() or c == "_"
    return valid_first(s[0]) and all(valid_later(c) for c in s)

def add_label(runtime_addr, s, move_id):
    """Add a label at the given runtime address and move_id."""

    assert 0 <= runtime_addr <= 0x10000 # 0x10000 is valid for labels, not code/data TODO?

    label = labelmanager.labels[runtime_addr]
    if s is not None:
        if is_simple_name(s):
            label.add_explicit_name(s, move_id)
        else:
            label.add_expression(s, move_id)
    return label

def add_optional_label(runtime_addr, s, base_addr=None):
    """Add a label at the given runtime address, but only output if used.

    When two consecutive bytes share a base label name (e.g. `userv` and `userv+1`) then `base_runtime_addr` points to the first byte."""

    assert 0 <= runtime_addr <= 0xffff

    # Check if already present
    if runtime_addr in optional_labels:
        assert optional_labels[runtime_addr] == (s, base_addr)
        return

    # Check base_addr is valid
    if base_addr is not None:
        assert runtime_addr != base_addr
        assert 0 <= base_addr <= 0xffff
        assert base_addr in optional_labels
        assert optional_labels[base_addr][1] is None
    else:
        assert is_simple_name(s)
    optional_labels[runtime_addr] = (s, base_addr)

def add_local_label(runtime_addr, name, start_addr, end_addr, move_id=None):
    """Add a label at the given runtime address, valid only if referenced in the region specified.

    start_addr, end_addr are runtime addresses.
    """

    label = labelmanager.labels[runtime_addr]
    label.add_local_label(name, start_addr, end_addr, move_id)

# TODO: Later it might make sense for context to default to None, but for now don't want this.
def get_label(runtime_addr, context, move_id=None):
    """Get a label name (a lazy string) for the given runtime address.

    `context` is the equivalent binary address.
    `move_id` is for the active move."""

    runtime_addr = int(runtime_addr)
    context = memorymanager.BinaryAddr(context)

    assert 0 <= runtime_addr <= 0x10000 # 0x10000 is valid for labels, not code/data TODO?
    assert memorymanager.is_valid_binary_addr(context)
    assert move_id is None or movemanager.is_valid_move_id(move_id)

    # We need to ensure the labelmanager knows there's a label at this
    # address so it can emit a definition. It's tempting to try to
    # defer this until get_final_label() is called, but it's good to
    # have the label exist as early as possible - for example, this
    # means post-tracing code analysis can see where labels exist and
    # what references them.
    # TODO: It is a bit clunky to have to do the "ensure it exists" via
    # this dummy dictionary lookup though.
    dummy = labelmanager.labels[runtime_addr]

    return utils.LazyString("%s", lambda: get_final_label(runtime_addr, context, move_id))

# TODO: May want to expose this to user as it may be useful in a user label maker hook
# TODO: This might need tweaking so we don't classify "move source" as code - move.py currently shows this
def is_code(binary_addr):
    """Is the given `binary_addr` classified as an instruction opcode?"""

    classification = classifications[binary_addr]
    if classification is None or classification == partial_classification:
        return False
    return classification.is_code(binary_addr)

# TODO: Should I call these "references", since they may be things like
# expressions? then again, I am calling things labels when they are
# really expressions too.
def suggest_label_name(runtime_addr, context, move_id):
    """Return a label name and move ID, auto-creating if needed.

    `context` is the associated binary_address.

    returns a tuple for the label (label name, move_id) and a boolean
    is_autogenerated_label"""

    assert context is not None
    runtime_addr = memorymanager.RuntimeAddr(runtime_addr)
    #if runtime_addr == 0x6a7:
    #    print("BBB", hex(context), move_id)

    # Work out the best move_id to use for the label.
    #
    # The basic idea is that if we can't assign a move ID based on a
    # matching of context and runtime_addr move IDs, *if* there is any
    # existing label for any of those move IDs we will use it rather
    # than forcing a new label in base_move_id to be created.
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
        move_id = movemanager.move_id_for_binary_addr[context]
        move_ids2 = movemanager.move_ids_for_runtime_addr(runtime_addr)
        #if runtime_addr == 0x6a7:
        #    print("CCC", move_id, move_ids2)

        # Rule 2
        if move_id not in move_ids2:
            move_ids3 = [move_id] + list(move_ids2)

            # Get the label
            label = labelmanager.labels.get(runtime_addr)
            for candidate_move_id in move_ids3:
                # Rule 3: Local labels
                if candidate_move_id in label.local_labels:
                    for (name, start_addr, end_addr) in label.local_labels[candidate_move_id]:
                        if start_addr <= context < end_addr:
                            return ((name, candidate_move_id), False)

                # Rule 3: Explicit labels
                if candidate_move_id in label.explicit_names:
                    for name in label.explicit_names[candidate_move_id]:
                        return ((name.name, candidate_move_id), False)

                # Rule 3: Expressions
                if candidate_move_id in label.expressions:
                    for expression in label.expressions[candidate_move_id]:
                        return ((expression, candidate_move_id), False)

            if len(move_ids2) == 1:
                # Rule 4
                move_id = min(move_ids2)
            else:
                # Rule 5
                move_id = movemanager.base_move_id

    label = labelmanager.labels.get(runtime_addr)
    #print("YYY %04x" % runtime_addr)
    assert label is not None

    # If the runtime address has a label name, choose the first one.
    # Check the local labels, then explicit names then expressions in
    # our chosen move ID. If that fails try the base move ID.

    # TODO: We might want to move this logic into the Label object, and
    # it could potentially pick one of its own explicit names out based
    # on context. For now we prefer the first one, since that's how the
    # code used to behave and we're trying to gradually refactor.

    # We are just returning the first name arbitrarily, since we
    # have no basis to choose anything else.

    # We look for a local label, explicit label or expression in the
    # current move_id, or failing that in the base_move_id.
    for (name, start_addr, end_addr) in label.local_labels[move_id]:
        if start_addr <= context < end_addr:
            return ((name, move_id), False)
    for name in label.explicit_names[move_id]:
        return ((name.name, move_id), False)
    for expression in label.expressions[move_id]:
        return ((expression, move_id), False)

    for (name, start_addr, end_addr) in label.local_labels[movemanager.base_move_id]:
        if start_addr <= context < end_addr:
            return ((name, move_id), False)
    for name in label.explicit_names[movemanager.base_move_id]:
        return ((name.name, None), False)
    for expression in label.expressions[movemanager.base_move_id]:
        return ((expression, move_id), False)

    # If no explicit label or expression is suitable, try the optional
    # labels.
    if runtime_addr in optional_labels:
        s, base_addr = optional_labels[runtime_addr]
        if base_addr is not None:
            # TODO: If our "suggestion" is not acted on, we will have
            # added this base label unnecessarily. I don't think this
            # is a big deal, but ideally we wouldn't do it.
            add_label(base_addr, optional_labels[base_addr][0], None)
        return ((s, None), False) # TODO: optional labels don't have a move_id at the moment?

    # Make up a brand new label name.
    #
    # if the binary address is not code, then call it "lXXXX"
    # TODO: Is this runtime->binary stuff correct?
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
        addr_refs = trace.references.get(binary_addr, [])
        if all(trace.cpu.is_subroutine_call(runtime_addr) for runtime_addr in addr_refs):
            # Found a subroutine, label is "sub_XXXX"
            label = "sub_" + label
        else:
            # Look for loops
            #
            # If there is one reference, and it's a branch backwards to
            # the target address, and within loop_limit bytes of the
            # current address then it's a "loop_cXXXX" name.
            if len(addr_refs) == 1:
                addr_ref = list(addr_refs)[0]

                # TODO: Maybe check if the instruction at runtime_addr
                # is an RTS and don't use loop_ prefix if it is - or
                # getting fancier, check if there's a straight line
                # sequence terminating in RTS at runtime_addr and don't
                # use loop_ prefix in that case either
                if trace.cpu.is_branch_to(addr_ref, runtime_addr) and 0 <= movemanager.b2r(addr_ref) - runtime_addr < config.get_loop_limit():
                    label = "loop_" + label
                    if config.get_indent_loops():
                        while binary_addr <= addr_ref:
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
def label_maker(addr, context, move_id):
    """Get a label name via calling a user hook.

    `context` is the associated binary address using the `move_id`.

    Returns the tuple (label_name, move_id)."""

    assert trace.cpu.trace_done

    # Get a suggested label
    suggestion, is_autogenerated = suggest_label_name(addr, context, move_id)

    # if the user function is supplied, use it to select the name
    # passing in the suggestion we just made.
    if user_label_maker_hook is not None:
        user_suggestion = user_label_maker_hook(addr, context, suggestion)

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

def get_final_label(addr, context, move_id):
    """Create a final label name.

    `context` is the associated binary address using the `move_id`.

    Returns the final label name"""
    #if addr == 0x6a7:
    #    print("FFF", hex(context), move_id)
    assert trace.cpu.trace_done
    assert memorymanager.is_valid_binary_addr(addr)
    assert memorymanager.is_valid_binary_addr(context)
    assert move_id is None or movemanager.is_valid_move_id(move_id)
    name, move_id = label_maker(addr, context, move_id)
    if is_simple_name(name):
        labelmanager.labels[addr].add_explicit_name(name, move_id)

    return name

def is_classified(binary_addr, length=1):
    """Is any address in the given range classified?"""

    return any(x is not None for x in classifications[binary_addr:binary_addr+length])

def add_classification(binary_addr, classification):
    """Sets the classification for the given address.

    A classification has a length in bytes. The first byte is
    classified with the given classification and all following bytes
    are marked with `partial_classification`.
    """

    binary_addr = memorymanager.BinaryAddr(binary_addr)
    assert classification is not None
    assert not is_classified(binary_addr, classification.length())

    classifications[binary_addr] = classification
    for i in range(1, classification.length()):
        classifications[binary_addr+i] = partial_classification

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
    binary_addr = memorymanager.BinaryAddr(0)
    while binary_addr < len(classifications):
        c = classifications[binary_addr]
        if c is not None:
            dummy = [str(x) for x in c.as_string_list(binary_addr, None)]
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
    if current_range_start  != (current_range_end - 1):
        move_ranges.append((current_range_start, current_range_end))

    return move_ranges


def emit():
    """Outputs the disassembly.
    """

    formatter = config.get_assembler()
    output = []

    # Output any prologue
    output.extend(formatter.disassembly_start())

    # Length of indent string
    indent_len = len(config.get_indent_string())

    # Emit constants first in the order they were defined.
    if len(constants) > 0:
        output.append(("%s Constants") % (formatter.comment_prefix()))

        # Get the longest name rounded up to the nearest indent amount
        max_len = 0
        for value, name in constants:
            max_len = max(max_len, len(name))

        max_len = indent_len * (max_len+indent_len-1)//indent_len

        for value, name in sorted(constants, key=lambda x: x[1]):
            if utils.is_integer_type(value):
                if config.get_constants_are_decimal():
                    value = str(value)
                else:
                    value = formatter.hex(value)
            output.append(formatter.explicit_label(name, value, None, max_len))
        output.append("")

    # For debugging py8dis output all labels, their addresses and move_ids
    if config.get_show_all_labels():
        output.extend(labelmanager.all_labels_as_comments())

    # Break the output down into sub-ranges which share the same move
    # ID. We completely ignore the classifications here; moves are more
    # important and  can bisect a classification. We call isolate_range
    # to fix up the classifications afterwards.
    move_ranges = calculate_move_ranges()

    for start_addr, end_addr in move_ranges:
        isolate_range(start_addr, end_addr)

    # Generate the disassembly proper, but don't emit it just yet. We
    # do this so we can emit label definitions in the "best" move
    # region and then emit any leftover labels as explicit definitions
    # below.
    #
    # TODO: This is *not* emitting labels "after" the last address in
    # some cases - e.g. move.py -a currently doesn't emit pydis_end
    # inline. (To be fair, this is a bit of an edge case, but ideally
    # it would work.)

    # d is the main disassembly output.
    d = []

    # TODO: dfs226.py vs dfs226b.py - range starting at 00xaf38 and the
    # range after are different between the two (not just the 0x6000
    # offset) - and even just looking at dfs226.py in isolation, the
    # 0xaf7c end seems wrong compared to the move()s - I *suspect* this
    # has something to do with classifications of "raw data" straddling
    # the end of the range and not being handled properly or at least
    # consistently

    def record_emit_point(binary_addr, move_id):
        md = movemanager.move_definitions[move_id]
        runtime_addr = md[0] + (binary_addr - md[1]) # TODO: OK!?
        labelmanager.labels[runtime_addr].notify_emit_opportunity(move_id)

    # Calculate the move_ids that will emit output?
    for start_addr, end_addr in move_ranges:
        move_id = movemanager.move_id_for_binary_addr[start_addr]
        if move_id != movemanager.base_move_id:
            record_emit_point(start_addr, movemanager.base_move_id)

        addr = start_addr
        while addr < end_addr:
            for i in range(0, classifications[addr].length()):
                record_emit_point(addr + i, move_id)
            addr += classifications[addr].length()
        assert addr == end_addr
        record_emit_point(end_addr, move_id)
        if move_id != movemanager.base_move_id:
            record_emit_point(end_addr, movemanager.base_move_id)


    # Output disassembly for each range in turn
    old_end_addr = None
    for start_addr, end_addr in move_ranges:
        if old_end_addr == None:
            # Output an ORG at the beginning
            d.extend(formatter.code_start(start_addr, end_addr, True))
            old_end_addr = start_addr

        move_id = movemanager.move_id_for_binary_addr[start_addr]

        # Handle start of a new !pseudopc block
        if move_id != movemanager.base_move_id:
            # Output any base move labels just before starting a new !pseudopc block
            d.extend(emit_labels(start_addr, movemanager.base_move_id))

            # Output start of !pseudopc block
            pseudopc_args = (movemanager.b2r(start_addr), start_addr, end_addr - start_addr)
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
            d.extend(emit_addr(addr, move_id))

            # move to the next address
            addr += classifications[addr].length()
        assert addr == end_addr

        # Emit labels and annotations at the end address of the move range
        d.extend(emit_labels(end_addr, move_id))

        # Handle the end of the !pseudopc block
        if move_id != movemanager.base_move_id:
            # Output the end of the !pseudopc block
            pseudopc_args = (movemanager.b2r(start_addr), start_addr, end_addr - start_addr)
            d.extend(formatter.pseudopc_end(*pseudopc_args))

            # Output any base move labels after the !pseudopc block is done
            d.extend(emit_labels(end_addr, movemanager.base_move_id))
        old_end_addr = end_addr


    # Emit labels which haven't been emitted inline with the disassembly.
    output.append(("%s Memory locations") % (formatter.comment_prefix()))

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
            output.append("%s Automatically generated labels:" % formatter.comment_prefix())
            for label in sorted(autogenerated_labels):
                output.append("%s     %s" % (formatter.comment_prefix(), label))

    # Finish off disassembly
    output.extend(formatter.disassembly_end())

    # Actually print the listing
    print("\n".join(formatter.sanitise(str(line)) for line in output))

def split_classification(binary_addr):
    """If a move boundary is in the middle of an instruction etc, then
    split the classification."""

    if binary_addr >= 0x10000:
        return
    if classifications[binary_addr] != partial_classification:
        return

    # TODO: Do we need to check and not warn if this is just an automatic string/byte classification?
    utils.warn("move boundary at binary address %s splits a classification" % config.get_assembler().hex(binary_addr))
    split_addr = binary_addr
    while classifications[binary_addr] == partial_classification:
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

def emit_labels(binary_addr, move_id):
    """Emit labels and non-inline annotations for the given address"""

    result = []
    for annotation in utils.sorted_annotations(annotations[binary_addr]):
        if not annotation.inline:
            result.append(annotation.as_string(binary_addr))

    md = movemanager.move_definitions[move_id]
    runtime_addr = md[0] + (binary_addr - md[1]) # TODO: OK!?
    result.extend(labelmanager.labels[runtime_addr].definition_string_list(runtime_addr, move_id))
    return result

def emit_addr(binary_addr, move_id):
    """Emit labels, the output for the classification, any remaining
    annotations in the range of the classification"""

    result = []
    classification_length = classifications[binary_addr].length()

    # We queue up labels defined "within" a multi-byte classification first
    # because we might need to create a new label at binary_addr to help in
    # defining them.
    pending_labels = []
    for i in range(1, classification_length):
        runtime_addr = movemanager.b2r(binary_addr + i)
        if runtime_addr in labelmanager.labels:
            label_list = labelmanager.labels[runtime_addr].definition_string_list(movemanager.b2r(binary_addr), move_id)
            pending_labels.extend(label_list)

    # Emit label definitions for this address.
    result.extend(emit_labels(binary_addr, move_id))

    # Emit any label definitions for addresses within the classification.
    result.extend(pending_labels)

    # Emit the classification itself.
    result.extend(classifications[binary_addr].as_string_list(binary_addr, annotations))

    # Emit any annotations which would fall within the classification.
    # We do this after the classification itself; this does have some
    # logic (we're "rounding to the end of the classification") and in
    # particular this works better than "rounding to start" does with
    # the current way overlapping instructions are emitted as comments.
    for i in range(1, classification_length):
        if len(annotations[binary_addr + i]) > 0:
            # TODO: Get rid of this warning? It is perhaps annoying at
            # least where "overlapping" instruction streams are added
            # as annotations. I've commented it out for now as annoying
            # is exactly right.
            pass # utils.warn("annotation at binary address %s is being emitted at %s" % (config.get_assembler().hex(binary_addr + i), config.get_assembler().hex(binary_addr)))
        for annotation in utils.sorted_annotations(annotations[binary_addr + i]):
            if not annotation.inline:
                result.append(annotation.as_string(binary_addr))
    return result


class Annotation(object):
    """A raw string to add to the output."""

    def __init__(self, text, inline=False, priority=None):
        if priority is None:
            priority = 0
        self.text = text
        self.inline = inline
        self.priority = priority

    def as_string(self, addr):
        return str(self.text)


class Comment(Annotation):
    """A comment, either inline or standalone.

    Derives from the Annotation class."""

    def __init__(self, text, inline=False, priority=None):

        def late_formatter():
            return "\n".join("%s %s" % (config.get_assembler().comment_prefix(), line) for line in str(text).split("\n"))

        Annotation.__init__(self, utils.LazyString("%s", late_formatter), inline, priority)

# TODO: We seem to assert some simple constants have their own value -
# is this wrong/weird?

# TODO: TobyLobster's Chuckie Egg disassembly shows that we're not
# necessarily doing the best we can when striking a balance between
# splitting/merging classifications and forcing the use of derived
# labels. l0c00 is being generated as an expression even though we
# should probably be splitting the byte data up so we can just label
#  0xc00 directly. I think part of the problem is we don't even
# *know* 0c00 is going to generate a label until we start str()-ing
# the instruction classifications - obviously we could make the
# disassembly process spit out labelled addresses explicitly during
# disassembly and that may well be the right approach, then label
# *names* are a str()-stage thing but the fact that an address will be
# labelled is known as soon as we finish tracing.

# TODO: Do we need to make some provision for user-controlled labelling
# at *binary* addresses, or without any "implicit, because unambiguous,
# move() application"? Imagine we have a move()d chunk of code - we
# want a label on that code *at the binary address* so the
# LDA rom_copy,Y:STA ram_copy,Y loop can use a custom label for
# rom_copy. I *think* at the moment it would be hard/impossible for
# user code to successfully define the "rom_copy" label.

# TODO: Note that in move.py, l0908 is an automatically generated label
# which we would like to heuristically assign a non-None move_id, but
# this doesn't happen yet.
