# Text encodings

By default py8dis reads text as ASCII. Commodore machines use their own character codes, so for a Commodore program:

```python
config.set_text_encoding("petscii")
```

makes PETSCII (the character codes used with CHROUT) the session's text encoding. (`commodore.c64()` and the other Commodore set-ups do this for you.) It's used for:

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

A string command's `encoding=` gives one string another encoding, e.g. `string(0xc04e, 21, encoding="screen")` for text copied straight to the screen, or `encoding="ascii"`. Set the session's encoding before marking any strings: each string keeps the encoding it was marked with.

## The characters

The characters are those of acme's `!pet` and `!scr`, so that acme can write the strings as text, e.g. `!pet "Hello", $0d` and `!scr "Score"`.

As in acme, lower case letters are the unshifted letters (PETSCII $41-$5A, screen codes $01-$1A), and upper case letters the shifted ones (PETSCII $C1-$DA, screen codes $41-$5A). That's the text as it appears in the C64's lower/upper case character set. (In the default upper case/graphics set, both appear as upper case letters or graphics.)

Codes that acme's characters would get wrong, such as PETSCII $5C (a pound sign on the C64, but a backslash to acme), and the graphics characters, are written as numbers.

## How each assembler writes them

### acme

A character literal is in the session's encoding: acme's output starts with `!ct pet` (or `!ct scr`), which makes `lda #'a'` PETSCII. So an ASCII string in it is written with `!raw`, rather than `!text` (which would be converted).

### 64tass

64tass's `.text` and character literals use its current encoding, so its output defines the encodings it uses at the top, with `.enc` and `.cdef` (each run of characters and its first byte, e.g. `.cdef "az", $41` for PETSCII), and selects the session's: `"petscii"`, or `"screencodes"` for screen codes (not 64tass's own `"screen"`, which `64tass -a` changes). So `.text "Hello"` and `lda #'a'` are PETSCII in a C64 program.

A string in another encoding, e.g. ASCII in a C64 program, selects its own just for that string (`.enc "none"`, then `.enc "petscii"` again). `"none"` is ASCII unless 64tass is run with `-a`, so don't use that option. A program with only ASCII text has none of this.

### ca65

ca65's character map (`.charmap`, from a character in the source to a byte) applies to every string and character literal, and can't be switched for one string. So ca65's output is like acme's: if the session's encoding is PETSCII or screen codes and the output has text in it, the output starts with the character map for it (e.g. `.charmap $61, $41 ; 'a'`), and its strings and character literals are text (`.byte "Hello"`, `lda #'a'`). Strings in other encodings, ASCII included, are written as bytes with the text in a comment.

### beebasm, Baron and xa

beebasm, Baron and xa have no PETSCII or screen code directives, and no such character literals. So these strings are written as bytes with the text in a comment, e.g. `equb &c8, &45, &4c, &4c, &4f ; petscii "Hello"`, and characters are numbers with the character in a comment (`lda #$41 ; 'a'`).
