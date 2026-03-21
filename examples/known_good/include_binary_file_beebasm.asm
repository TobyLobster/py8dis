; Memory locations

    org &0e00

.pydis_start
    equs "Hello"                                                      ; 0e00: 48 65 6c... Hel
    INCBIN "orig/include_binary_data.bin"
    equs " world"                                                     ; 0e0d: 20 77 6f...  wo
.pydis_end


save pydis_start, pydis_end

; Stats:
;     Total size (Code + Data) = 19 bytes
;     Code                     = 0 bytes (0%)
;     Data                     = 19 bytes (100%)
;
;     Number of instructions   = 0
;     Number of data bytes     = 8 bytes
;     Number of data words     = 0 bytes
;     Number of string bytes   = 11 bytes
;     Number of strings        = 2

