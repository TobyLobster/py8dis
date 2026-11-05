# Text encodings

By default py8dis reads text as ASCII. Commodore machines use their own character codes, and the Apple II uses ASCII with bit 7 set, so for a Commodore program:

```python
config.set_text_encoding("petscii")
```

makes PETSCII (the character codes used with CHROUT) the session's text encoding. (`commodore.c64()` and the other Commodore set-ups do this for you.) For an Apple II program, it's `config.set_text_encoding("apple")`. The session's encoding is used for:

- strings, including the ones py8dis finds by itself;
- the characters at the end of the hex dump;
- the character comments on immediate values (`lda #$41 ; 'a'`);
- character literals, e.g. from `char()`, or the character CHROUT outputs (see [Commodore](machines/commodore.md)).

The encodings are:

| Name        | What it is |
| ----------- | ---------- |
| `"ascii"`   | ASCII (the default) |
| `"petscii"` | PETSCII, Commodore's character codes |
| `"screen"`  | Commodore screen codes, as stored in screen memory |
| `"apple"`   | The Apple II's high ASCII: ASCII with bit 7 set, as its ROM, keyboard and screen use it |

A string command's `encoding=` gives one string another encoding, e.g. `string(0xc04e, 21, encoding="screen")` for text copied straight to the screen, or `encoding="ascii"`. Set the session's encoding before marking any strings: each string keeps the encoding it was marked with.

## The characters

The characters are those of acme's `!pet` and `!scr`, so that acme can write the strings as text, e.g. `!pet "Hello", $0d` and `!scr "Score"`.

As in acme, lower case letters are the unshifted letters (PETSCII $41-$5A, screen codes $01-$1A), and upper case letters the shifted ones (PETSCII $C1-$DA, screen codes $41-$5A). That's the text as it appears in the C64's lower/upper case character set. (In the default upper case/graphics set, both appear as upper case letters or graphics.)

Codes that acme's characters would get wrong, such as PETSCII $5C (a pound sign on the C64, but a backslash to acme), and the graphics characters, are written as numbers.

In high ASCII, bytes $A0-$FE are the characters space to `~`, and all other bytes (including a CR, $8D) are written as numbers. Since its characters all have bit 7 set, `stringhi()` and `stringhiz()` end a string at a byte with bit 7 clear (see [commands.md](commands.md#strings)).

## How each assembler writes them

### acme

A character literal is in the session's encoding: acme's output starts with `!ct pet` (or `!ct scr`), which makes `lda #'a'` PETSCII. So an ASCII string in it is written with `!raw`, rather than `!text` (which would be converted).

acme has no directive for high ASCII, so a high ASCII string is ASCII in an `!xor $80` block. The block XORs the numbers in it too, so a CR is written `$0d` and a zero `$80`, and an expression given for a byte is written `(cr) xor $80`:

```
message
    !xor $80 {
    !text "Hello", $0d, $80
    }
```

A high ASCII character literal is ASCII with bit 7 set: `lda #'A' | $80`. (beebasm, Baron and xa write it the same way, with `or` in beebasm and Baron.)

### 64tass

64tass's `.text` and character literals use its current encoding, so its output defines the encodings it uses at the top, with `.enc` and `.cdef` (each run of characters and its first byte, e.g. `.cdef "az", $41` for PETSCII), and selects the session's: `"petscii"`, or `"screencodes"` for screen codes (not 64tass's own `"screen"`, which `64tass -a` changes). So `.text "Hello"` and `lda #'a'` are PETSCII in a C64 program.

A string in another encoding, e.g. ASCII in a C64 program, selects its own just for that string (`.enc "none"`, then `.enc "petscii"` again). `"none"` is ASCII unless 64tass is run with `-a`, so don't use that option. A program with only ASCII text has none of this.

High ASCII is the encoding `"apple"`, defined with `.cdef " ~", $a0`, so in an Apple II program `.text "Hello", $8d` and `lda #'A'` have bit 7 set.

### ca65

ca65's character map (`.charmap`, from a character in the source to a byte) applies to every string and character literal, and can't be switched for one string. So ca65's output is like acme's: if the session's encoding is PETSCII, screen codes or high ASCII and the output has text in it, the output starts with the character map for it (e.g. `.charmap $61, $41 ; 'a'`; for high ASCII, one line for each of the 95 characters), and its strings and character literals are text (`.byte "Hello"`, `lda #'a'`). Strings in other encodings, ASCII included, are written as bytes with the text in a comment.

### beebasm, Baron and xa

beebasm, Baron and xa have no PETSCII, screen code or high ASCII directives, and no PETSCII or screen code character literals. So these strings are written as bytes with the text in a comment, e.g. `equb &c8, &45, &4c, &4c, &4f ; petscii "Hello"` or `equb &c8, &e5, &ec, &ec, &ef ; apple "Hello"`, and PETSCII and screen code characters are numbers with the character in a comment (`lda #$41 ; 'a'`). A high ASCII character literal is ASCII with bit 7 set (`lda #'A' or &80`).
