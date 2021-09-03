from commands import *
import utils

# TODO: Do this automatically just from "import acorn"?
# TODO: Rename now it's not pure entry points
# TODO: Split this up somehow into "tube or host" and "just host"?
def label_os_entry_points():
    optional_label(0x00f2, "os_text_ptr")
    optional_label(0x00f4, "romsel_copy")
    optional_label(0x00f6, "osrdsc_ptr")

    # TODO: These aren't ideal, as e.g. "STA &201" will not be interpreted as userv+1.
    optional_label(0x0200, "userv")
    optional_label(0x0202, "brkv")
    optional_label(0x0204, "irq1v")
    optional_label(0x0206, "irq2v")
    optional_label(0x0208, "cliv")
    optional_label(0x020a, "bytev")
    optional_label(0x020c, "wordv")
    optional_label(0x020e, "wrchv")
    optional_label(0x0210, "rdchv")
    optional_label(0x0212, "filev")
    optional_label(0x0214, "argsv")
    optional_label(0x0216, "bgetv")
    optional_label(0x0218, "bputv")
    optional_label(0x021a, "gbpbv")
    optional_label(0x021c, "findv")
    optional_label(0x021e, "fscv")
    optional_label(0x0220, "evntv")
    optional_label(0x0222, "uptv")
    optional_label(0x0224, "netv")
    optional_label(0x0226, "vduv")
    optional_label(0x0228, "keyv")
    optional_label(0x022a, "insv")
    optional_label(0x022c, "remv")
    optional_label(0x022e, "cnpv")
    optional_label(0x0230, "ind1v")
    optional_label(0x0232, "ind2v")
    optional_label(0x0234, "ind3v")

    optional_label(0xfe30, "romsel")

    optional_label(0xffb9, "osrdsc")
    optional_label(0xffbc, "vduchr")
    optional_label(0xffbf, "oseven")
    optional_label(0xffc2, "gsinit")
    optional_label(0xffc5, "gsread")
    optional_label(0xffc8, "nvrdch")
    optional_label(0xffcb, "nvwrch")
    optional_label(0xffce, "osfind")
    optional_label(0xffd1, "osgbpb")
    optional_label(0xffd4, "osbput")
    optional_label(0xffd7, "osbget")
    optional_label(0xffda, "osargs")
    optional_label(0xffdd, "osfile")
    optional_label(0xffe0, "osrdch")
    optional_label(0xffe3, "osasci")
    optional_label(0xffe7, "osnewl")
    optional_label(0xffee, "oswrcr")
    optional_label(0xffee, "oswrch")
    optional_label(0xfff1, "osword")
    optional_label(0xfff4, "osbyte")
    optional_label(0xfff7, "oscli")


def is_sideways_rom():
    comment(0x8000, "Sideways ROM header")
    label(0x8000, "rom_header")
    def check_entry(addr, entry_type):
        jmp_abs_opcode = 0x4c
        label(addr, entry_type + "_entry")
        if memory[addr] == jmp_abs_opcode:
            entry_points.append(addr)
            label(utils.get_abs(addr + 1), entry_type + "_handler")
        else:
            byte(addr, 3)
    check_entry(0x8000, "language")
    check_entry(0x8003, "service")
    label(0x8006, "rom_type")
    label(0x8007, "copyright_offset")
    copyright_offset = memory[0x8007]
    expr(0x8007, "copyright - rom_header")
    label(0x8008, "binary_version")
    label(0x8009, "title")
    nul_at_title_end = stringz(0x8009, True) - 1
    if nul_at_title_end < (0x8000 + copyright_offset):
        label(nul_at_title_end, "version")
        stringz(nul_at_title_end + 1, True)
    label(0x8000 + copyright_offset, "copyright")
    stringz(0x8000 + copyright_offset + 1)
    # TODO: We could recognise tube transfer/relocation data in header
