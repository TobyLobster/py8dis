"""
Machine type

The MachineType enum: which Acorn machine a program is for. acorn.py's
hardware() uses it to name that machine's hardware addresses, and
acorntables.py's hardware_labels table says which machines have each one.
"""

from enum import Enum, auto

class MachineType(Enum):
    """Enum representing the Acorn machine types: the BBC Micro (model B),
    the B+, the Master, the 6502 second processor (whose only hardware is
    its side of the Tube) and the Electron."""
    MACHINE_BBC = auto()
    MACHINE_BPLUS = auto()
    MACHINE_MASTER = auto()
    MACHINE_6502SP = auto()
    MACHINE_ELECTRON = auto()
