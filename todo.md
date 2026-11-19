# py8dis: to do

Ideas for improvements, roughly in order of value (19 Nov 2026).

1. **What subroutines leave behind.** At the moment nothing is known after a JSR. Some facts about a subroutine don't depend on how it was called: which registers and flags it never writes (so a caller's X, say, is still known after the call), and what's known at every one of its RTSs (e.g. the carry is always clear). Carry these past each JSR to it, and note them in the subroutine's "On Exit" notes where a caller relies on them. *(Done 19 Nov, including registers and flags saved on the stack and got back: see docs/cpus.md.)*

2. **Suggest control-file lines for what py8dis can't prove.** Where a jump table's dispatch is found but its index can't be bounded (e.g. anfs418 &8c93/&a13b/&a997, dfs226 &8740/&b238, Open ROMs &fe0a, memory128), or a table is rejected (e.g. Open ROMs BASIC's overlapping token tables), print a suggestion, e.g. `# probable RTS jump table at $a4c9, X not known: rts_code_ptr(...)`, ready to paste into the control file. *(Done 19 Nov: a note for each table whose index isn't known, with the entries it seems to have (see docs/cpus.md). The examples had two, anfs418 &a99d (9 entries) and Open ROMs kernal &fe0e (17), which their control files now mark. Not done: notes for tables found but rejected, e.g. because an entry points into data.)*

3. **Size data tables, not just jump tables.** The index ranges already say e.g. that `sine_table,y` has 32 entries and `bit_table,x` 8. Mark such tables as data of that length and say what indexes them. Find pointer tables used as `lda lo,x : sta ptr : lda hi,x : sta ptr+1 : lda (ptr),y`, and write their entries as label expressions, as is done for jump tables. *(Done 19 Nov: see docs/cpus.md, "Data tables". The examples get 164 tables of bytes, 3 of words, and no tables of pointers: the two found are in RAM or already marked by their control files.)*

4. **Track known values in zero page as well as registers.** E.g. after `lda #<buf : sta ptr : lda #>buf : sta ptr+1`, a memory loop through `(ptr),y` could say "Clear 256 bytes of memory from buf onwards" rather than "from (l0074)", and a jump table whose index was stored in zero page first could be found. The effect patterns already know some memory within a straight run; this would bring it into the joined states.

5. **Stop tracing past "ALWAYS branch" when the bytes are clearly data.** OS 1.20 &f581 is still disassembled as code, though the same code reads it as a table (`ora cf581,y`). If what follows an always-taken branch is also read as indexed data, prefer data. (Stopping on the branch alone is riskier, since code there may be reached in ways py8dis doesn't see.)

6. **More loop comments.** Search loops, e.g. memory128's "Search key_table (16 bytes) for A". On the 65C02, `stz table,x` loops are memory clears that the set-loop snippets don't yet recognise (basic4 is 65C02 code).

7. **Speed.** Joining the states at labels made the big ROMs 1.4 to 1.7 times slower, since every tracing pass works out every state again. Working out only what changed since the last pass should recover most of that. The full test suite takes about 210s.

8. **The Z80.** The known bits, ranges, joins at labels and jump tables are all 6502-only. The Z80's state tracking could get the same (the Spectrum ROM, bbcbasic and opense would benefit). The biggest item here.

9. **Sets of values.** *(Done 19 Nov: each register is known as the set of values it could have, a 256-bit mask (py8dis/valuesets.py), instead of its known bits and range. The operations are exact, ranges wrap round (so after 'ldx #16 : loop: ... dex : bpl loop' X is 0 to 16 at the loop and $ff after it), ASL keeps the values above $7f (A is the even values $9e to $fe after 'cmp #$cf : bcc skip : asl'), and joins keep e.g. 0 or $80. py8dis now finds Open ROMs kernal's table of control code routines (&fe0e) itself, since it knows X is 0 to 16 there, so the control file only labels it.)*
