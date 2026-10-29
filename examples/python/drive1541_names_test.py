"""drive1541_test's code, with commodore.drive1541(rom="1541-ii",
names="commodore"): the 1541-II's DOS ROM, and the names in Commodore's
source (e.g. 'jobs' rather than 'job_queue')."""

from commands import *
import commodore

load(0x0500, "orig/drive1541_names_test.orig", "6502", "583f9f28a1cbd3fb3e9cacab5ffe3c97")
commodore.drive1541(rom="1541-ii", names="commodore")
entry(0x0500, "drive_code")
go()
