// Memory locations

// Zero page ($0000-$00ff)
l0070   = $0070

// MOS entry points ($ffb3-$fff9)
OSASCI  = $ffe3
OSNEWL  = $ffe7
OSWRCH  = $ffee

    * = $2000

pydis_start
start
    // Select mode 7
    lda #$16                                                          // 2000: a9 16       ..
    jsr OSWRCH                                                        // 2002: 20 ee ff     .. // Write character 22
    lda #7                                                            // 2005: a9 07       ..
    jsr OSWRCH                                                        // 2007: 20 ee ff     .. // Write character 7
    // Turn the cursor off
    lda #$17                                                          // 200a: a9 17       ..
    jsr OSWRCH                                                        // 200c: 20 ee ff     .. // Write character 23
    lda #1                                                            // 200f: a9 01       ..
    jsr OSWRCH                                                        // 2011: 20 ee ff     .. // Write character 1
    lda #0                                                            // 2014: a9 00       ..
    jsr OSWRCH                                                        // 2016: 20 ee ff     .. // Write character 0
    jsr OSWRCH                                                        // 2019: 20 ee ff     .. // Write character
    jsr OSWRCH                                                        // 201c: 20 ee ff     .. // Write character
    jsr OSWRCH                                                        // 201f: 20 ee ff     .. // Write character
    jsr OSWRCH                                                        // 2022: 20 ee ff     .. // Write character
    jsr OSWRCH                                                        // 2025: 20 ee ff     .. // Write character
    jsr OSWRCH                                                        // 2028: 20 ee ff     .. // Write character
    jsr OSWRCH                                                        // 202b: 20 ee ff     .. // Write character
    // Set logical colour 1 to physical colour 4
    ldx #$13                                                          // 202e: a2 13       ..
    txa                                                               // 2030: 8a          .  // A=$13
    jsr OSWRCH                                                        // 2031: 20 ee ff     .. // Write character 19
    lda #1                                                            // 2034: a9 01       ..
    jsr OSWRCH                                                        // 2036: 20 ee ff     .. // Write character 1
    lda #4                                                            // 2039: a9 04       ..
    jsr OSWRCH                                                        // 203b: 20 ee ff     .. // Write character 4
    lda #0                                                            // 203e: a9 00       ..
    jsr OSWRCH                                                        // 2040: 20 ee ff     .. // Write character 0
    jsr OSWRCH                                                        // 2043: 20 ee ff     .. // Write character
    jsr OSWRCH                                                        // 2046: 20 ee ff     .. // Write character
    // Position text cursor at (X,Y)
    lda #$1f                                                          // 2049: a9 1f       ..
    jsr OSWRCH                                                        // 204b: 20 ee ff     .. // Write character 31
    txa                                                               // 204e: 8a          .
    jsr OSWRCH                                                        // 204f: 20 ee ff     .. // Write character
    tya                                                               // 2052: 98          .
    jsr OSWRCH                                                        // 2053: 20 ee ff     .. // Write character
    // Position text cursor at (?,3)
    lda #$1f                                                          // 2056: a9 1f       ..
    jsr OSWRCH                                                        // 2058: 20 ee ff     .. // Write character 31
    lda l0070                                                         // 205b: a5 70       .p
    jsr OSWRCH                                                        // 205d: 20 ee ff     .. // Write character
    lda #3                                                            // 2060: a9 03       ..
    jsr OSWRCH                                                        // 2062: 20 ee ff     .. // Write character 3
    // PLOT 69,640,512
    lda #$19                                                          // 2065: a9 19       ..
    jsr OSWRCH                                                        // 2067: 20 ee ff     .. // Write character 25
    lda #$45 // 'E'                                                   // 206a: a9 45       .E
    jsr OSWRCH                                                        // 206c: 20 ee ff     .. // Write character 69
    lda #$80                                                          // 206f: a9 80       ..
    jsr OSWRCH                                                        // 2071: 20 ee ff     .. // Write character 128
    lda #2                                                            // 2074: a9 02       ..
    jsr OSWRCH                                                        // 2076: 20 ee ff     .. // Write character 2
    lda #0                                                            // 2079: a9 00       ..
    jsr OSWRCH                                                        // 207b: 20 ee ff     .. // Write character 0
    lda #2                                                            // 207e: a9 02       ..
    jsr OSWRCH                                                        // 2080: 20 ee ff     .. // Write character 2
    // Print "Hi"
    lda #$48 // 'H'                                                   // 2083: a9 48       .H
    jsr OSWRCH                                                        // 2085: 20 ee ff     .. // Write character 72
    lda #$69 // 'i'                                                   // 2088: a9 69       .i
    jsr OSWRCH                                                        // 208a: 20 ee ff     .. // Write character 105
    // Start a new line
    lda #$0d                                                          // 208d: a9 0d       ..
    jsr OSWRCH                                                        // 208f: 20 ee ff     .. // Write character 13
    lda #$0a                                                          // 2092: a9 0a       ..
    jsr OSWRCH                                                        // 2094: 20 ee ff     .. // Write character 10
    // Start a new line
    lda #$0d                                                          // 2097: a9 0d       ..
    jsr OSASCI                                                        // 2099: 20 e3 ff     .. // Write newline (characters 10 and 13)
    jsr OSNEWL                                                        // 209c: 20 e7 ff     .. // Write newline (characters 10 and 13)
    rts                                                               // 209f: 60          `

end_of_plot
    // The end of a VDU sequence that earlier code started
    lda #0                                                            // 20a0: a9 00       ..
    jsr OSWRCH                                                        // 20a2: 20 ee ff     .. // Write character 0
    jsr OSWRCH                                                        // 20a5: 20 ee ff     .. // Write character
    jsr OSWRCH                                                        // 20a8: 20 ee ff     .. // Write character
    // Position text cursor at (5,6)
    lda #$1f                                                          // 20ab: a9 1f       ..
    jsr OSWRCH                                                        // 20ad: 20 ee ff     .. // Write character 31
    lda #5                                                            // 20b0: a9 05       ..
    jsr OSWRCH                                                        // 20b2: 20 ee ff     .. // Write character 5
    lda #6                                                            // 20b5: a9 06       ..
    jmp OSWRCH                                                        // 20b7: 4c ee ff    L.. // Write character 6

pydis_end


// Label references by decreasing frequency:
//     OSWRCH:  40
//     OSASCI:   1
//     OSNEWL:   1
//     l0070:    1

// Automatically generated labels:
//     l0070

// Stats:
//
//     Total size (Code + Data) = 186 bytes
//     Code                     = 186 bytes (100%)
//     Data                     = 0 bytes (0%)
//
//     Number of instructions   = 74
//     Number of data bytes     = 0 bytes
//     Number of data words     = 0 bytes
//     Number of string bytes   = 0 bytes
//     Number of strings        = 0

