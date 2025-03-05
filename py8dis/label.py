import collections
import memorymanager
import movemanager
import disassembly
import config
from memorymanager import BinaryAddr, RuntimeAddr

class Label(object):
    class Name(object):
        """Class for a label's name. Records whether it has been emitted yet."""
        def __init__(self, name, *, priority=None):
            self.text = name
            self.emitted = False
            self.priority = priority

        def __str__(self):
            return self.text + " (Emitted: " + str(self.emitted) + ")"

        def __repr__(self):
            return self.__str__()

    def __init__(self, runtime_addr):
        self.runtime_addr = RuntimeAddr(runtime_addr)

        # Remember the relevant active_move_ids in operation at this point of label creation.
        # These are used to later 'best guess' in which move the label should be output.
        relevant_move_ids = movemanager.move_ids_for_runtime_addr(self.runtime_addr)
        self.relevant_active_move_ids = [x for x in movemanager.active_move_ids[:] if x in relevant_move_ids]

        self.references = []         # Holds the binary locations that reference this label

        # `local_labels` stores tuples (name, start_addr, end_addr)
        # indexed by move_id, as created by `add_local_label()`
        self.local_labels = collections.defaultdict(list)

        # `explicit_names` holds lists since we want to remember the
        # order user-added names were provided.
        self.explicit_names = collections.defaultdict(list)

        # Non-simple names go in a different list
        self.expressions = collections.defaultdict(list)

        # Set of move_id's that apply at this label's address
        self.emit_opportunities = set()

        # By default, allow label to be defined inline
        self.definable_inline = True

    def add_reference(self, reference_binary_loc):
        assert isinstance(reference_binary_loc, movemanager.BinaryLocation)
        self.references.append(reference_binary_loc)

    def is_only_an_expression(self):
        return not self.explicit_names and not self.local_labels and self.expressions

    def is_empty(self):
        # Check references
        for ref in self.references:
            return False

        # Check local labels
        for move_id, name_data in self.local_labels.items():
            if name_data:
                return False

        # Check explicit names
        for move_id, name_list in self.explicit_names.items():
            for name in name_list:
                return False

        # Check expressions
        for move_id, expression_list in self.expressions.items():
            if expression_list:
                return False
        return True

    def all_names_by_move_id(self):
        """Return all label names and expressions for this label for each move_id"""

        result = collections.defaultdict(set)

        # Add all local names
        for move_id, name_data in self.local_labels.items():
            if name_data:
                result[move_id].add(name_data[0])

        # TODO: For performance, we could maintain this set in
        # add_explicit_name() and any other "add" functions rather
        # than regenerating it every time, but for now I want
        # guaranteed consistency over speed.
        for move_id, name_list in self.explicit_names.items():
            for name in name_list:
                result[move_id].add(name.text)

        # Add expressions
        for move_id, expression_list in self.expressions.items():
            result[move_id].update(expression_list)
        return result

    def all_names(self):
        """Return all label names and expressions for this label"""

        result = set()

        # Add all local names
        for name_data in self.local_labels.values():
            if name_data:
                result.add(name_data[0])

        for name_list in self.explicit_names.values():
            for name in name_list:
                result.add(name.text)

        # Add expressions
        for expression_list in self.expressions.values():
            result.update(expression_list)
        return result

    def description(self):
        """Return all label names and expressions for this label as a descriptive string"""

        result = ""

        # Add all local names
        for name_data in self.local_labels.values():
            if name_data:
                result += name_data[0] + " (local), "

        for name_list in self.explicit_names.values():
            for name in name_list:
                result += name.text + " (explicit), "

        # Add expressions
        for expression_list in self.expressions.values():
            for expr in expression_list:
                result += expr + " (expression), "
        if result.endswith(", "):
            result = result[0:-2]
        return result

    def add_explicit_name(self, name, move_id, priority=None):
        """Add a simple named label"""

        if move_id is None:
            move_id = movemanager.BASE_MOVE_ID

        assert disassembly.is_simple_name(name)
        assert movemanager.is_valid_move_id(move_id)

        # TODO: What if the name already exists but with a different
        # move_id? We probably shouldn't allow it to exist with both -
        # we don't want to assume the assembler will accept duplicate
        # definitions of the same label name.
        #
        # For auto-generated labels at least we may want to be
        # appending some sort of suffix to allow differently named
        # variants of the label to exist in different move IDs.
        #
        # Imagine we're tracing some code, and move IDs 0 and 1 both
        # contain "bne &905"; we don't want to generate one l0905 label
        # and put it in one move ID and leave the other one implicit.
        if name not in self.all_names():
            self.explicit_names[move_id].append(self.Name(name, priority=priority))

    def add_local_label(self, name, start_addr, end_addr, move_id):
        """Add a local label"""

        if move_id is None:
            move_id = movemanager.BASE_MOVE_ID

        assert disassembly.is_simple_name(name)
        assert movemanager.is_valid_move_id(move_id)

        self.local_labels[move_id].append((name, start_addr, end_addr))

    def add_expression(self, s, move_id):
        """Add an expression to use when referencing a runtime address"""

        assert not disassembly.is_simple_name(s)
        assert movemanager.is_valid_move_id(move_id)

        if s not in self.all_names():
            self.expressions[move_id].append(s)

    def find_max_explicit_name_length(self):
        """Find the length of the longest explicit name not emitted.

        Used to help formatting the list of label definitions."""

        max_name_length = 0
        for name_list in self.explicit_names.values():
            for name in name_list:
                if not name.emitted:
                    max_name_length = max(max_name_length, name.text)
        return max_name_length

    def explicit_definition_string_list(self, align_value_column):
        """Return a list of the explicit `label = value` output strings."""

        # Note that we don't invoke the label hook or anything here -
        # if a name got *used* for the label at some point, it should
        # have been added into the label object so we know to emit it
        # here.
        assembler = config.get_assembler()

        # Gather the names and sort them.
        gathered_names = []
        for name_list in self.explicit_names.values():
            for name in name_list:
                if not name.emitted:
                    gathered_names.append(name.text)
                    name.emitted = True
        gathered_names = sorted(gathered_names)

        result = []
        for name in gathered_names:
            result.append(assembler.explicit_label(name, assembler.hex4(self.runtime_addr), offset=None, align_column=align_value_column))

        return result

    def notify_emit_opportunity(self, move_id):
        """Record that the move_id is used at this label's address'."""

        assert movemanager.is_valid_move_id(move_id)
        if move_id not in self.emit_opportunities:
            self.emit_opportunities.add(move_id)

    def definition_string_list(self, emit_addr, binary_loc):
        """Get a list of the labels in a move_id as a list of strings."""

        assert movemanager.is_valid_move_id(binary_loc.move_id)

        # Emit any definitions for this move_id.
        result = self.definition_string_list_internal(emit_addr, binary_loc)

        # Definitions for move IDs which will never get an opportunity
        # to be emitted inline in their preferred move ID are emitted
        # in the lowest-numbered move ID they can be emitted inline for.
        if (len(self.emit_opportunities) > 0) and (binary_loc.move_id == min(self.emit_opportunities)):
            leftover_move_ids = set(self.explicit_names.keys()) - self.emit_opportunities
            for move_id in leftover_move_ids:
                assert movemanager.is_valid_move_id(move_id)
                result.extend(self.definition_string_list_internal(emit_addr, binary_loc))
        return result

    def collate_explicit_names_for_move_id(self, emit_addr, offset, binary_loc):
        assembler = config.get_assembler()
        result = []

        if not self.definable_inline:
            return result

        filtered_and_sorted = sorted(
            [item for item in self.explicit_names[binary_loc.move_id] if not item.emitted],
            key=lambda x: float('inf') if x.priority is None else x.priority)

        for name in filtered_and_sorted:
            if offset == 0:
                if disassembly.is_simple_name(name.text):
                    result.append(assembler.inline_label(name.text))
            else:
                if disassembly.is_simple_name(name.text):
                    result.append(assembler.explicit_label(name.text, disassembly.get_label(emit_addr, binary_loc.binary_addr, move_id=binary_loc.move_id), offset))
            name.emitted = True
        return result

    def definition_string_list_internal(self, emit_addr, binary_loc):
        """Get a list of the explicit labels in a move_id as a list of strings."""

        assert movemanager.is_valid_move_id(binary_loc.move_id)
        result = []
        assert emit_addr <= self.runtime_addr
        offset = self.runtime_addr - emit_addr
        # We only emit for "matching" move_id; we leave it for
        # explicit_definition_string_list() to return any things which
        # we never would emit otherwise.
        result.extend(self.collate_explicit_names_for_move_id(emit_addr, offset, binary_loc))
        return result

    def __str__(self) -> str:
        result = hex(self.runtime_addr) + str(self.relevant_active_move_ids) + ": " + str(self.description()) + " references:" + ', '.join(str(x) for x in self.references)
        return result

    def __repr__(self) -> str:
        return self.__str__()
