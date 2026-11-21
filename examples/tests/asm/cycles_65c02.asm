; 65C02 cycle counts (shown with config.set_show_cycles(True)), for
; python/cycles_65c02.py: ADC and SBC take an extra cycle in decimal mode, in
; every addressing mode, and an absolute indexed BIT or shift takes an extra
; cycle if indexing crosses a page (it can't from an address at the start of
; a page). Assemble with:
;
;   acme -o ../orig/cycles_65c02.orig cycles_65c02.asm
;
; (It isn't meant to do anything useful when run.)

!cpu 65c02

* = $2000

start
    sed
    adc #1                  ; 2/3
    sbc #1                  ; 2/3
    sbc $1234               ; 4/5
    sbc ($70,x)             ; 6/7
    cld
    bit $1234,x             ; 4/5
    bit $1200,x             ; 4 (from the start of a page)
    asl $1234,x             ; 6/7
    rol $1200,x             ; 6 (from the start of a page)
    bra done                ; 3 (the target's in the same page)
done
    rts
