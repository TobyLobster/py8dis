"""
Stats

The statistics at the end of the output: how much of the program is code,
data and strings. classification.get_stats() counts them from the
classification of each byte, once everything is classified, and
disassembly.emit() writes them as comments (unless
config.set_show_stats(False)).
"""

class Stats:
    """Counts of what the classified bytes are (see
    classification.get_stats()). All are numbers of bytes except
    num_instructions and num_strings:

        num_total_bytes   all the classified bytes (not shown in the output)
        num_instructions  instructions
        num_code_bytes    bytes of instructions
        num_data_bytes    bytes of byte data (from byte(), and everything
                          left over, see classification.classify_leftovers())
        num_data_words    bytes (not words) of word data
        num_string_bytes  bytes of strings
        num_strings       strings
    """

    def __init__(self):
        self.num_total_bytes = 0
        self.num_instructions = 0
        self.num_code_bytes = 0
        self.num_data_bytes = 0
        self.num_data_words = 0
        self.num_string_bytes = 0
        self.num_strings = 0

    def total_data(self):
        """The number of bytes that aren't code: data bytes, data words and
        strings."""
        return self.num_data_bytes + self.num_data_words + self.num_string_bytes
