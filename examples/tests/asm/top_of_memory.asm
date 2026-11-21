; Code and data at the top of memory, $ffe0-$ffff, for top_of_memory and
; top_of_memory_string (see their control files). These used to crash py8dis
; (an IndexError or an assertion):
; - a branch that wraps round past the top of memory to zero page;
; - code that runs right up to $ffff (and would carry on at $0000);
; - an instruction starting at $fffe, whose operand would run past the top;
; - a printable string that runs up to $ffff (top_of_memory_string, where
;   the code at the end isn't traced).
; Assemble with:
;
;   acme -o ../orig/top_of_memory.orig top_of_memory.asm

    * = $ffe0

start
    ldx #$80
    bmi $0020               ; wraps round to $0020
    jmp last

    !text "THE TOP OF MEMORY", 0
    !fill $fffd - *, 0

last
    bit $412c               ; ($fffe is ',', BIT abs, and $ffff 'A')
