# Running the tests

The `examples` folder holds py8dis's tests:

- `examples/python`: the control files;
- `examples/orig`: the programs they disassemble;
- `examples/known_good`: the output they should give;
- `examples/asm_to_create_test_binaries`: the source of the small test programs written for py8dis, and `go`, which builds them.

To run them all and check the output:

``` sh
cd examples
./run_tests.py -c
```

Each test disassembles a program for one or more assemblers, assembles the output, and checks that it gives the original program back, byte for byte. With `-c`, it also checks the output against `known_good`. Some tests check the JSON, symbol file and cross-reference output too.

py8dis itself needs only Python 3. The tests also use these, when they're installed, and skip what needs them otherwise:

- the assemblers (acme, beebasm, Baron, xa, 64tass, ca65, Merlin 32, z88dk-z80asm and sjasmplus), to check that each disassembly assembles to the original program;
- the [jsonschema](https://pypi.org/project/jsonschema/) package (`pip install jsonschema`), to check the JSON output against its schema (see [output-files.md](output-files.md)). Without it, `run_tests.py -c` says so at the end.

`./run_tests.py --help` lists the other options:

| Option              | What it does |
| ------------------- | ------------ |
| `-c`                | check the output against `known_good` |
| `-m`                | copy the output to `known_good`, after a change that's meant to change it (the program is still checked) |
| `-x`                | make extra files for debugging (the assemblers' reports, symbol files etc.) |
| `-a ASSEMBLER ...`  | only test with these assemblers |
| `-j JOBS`           | how many tests to run at once (by default, the number of CPUs) |
| `NAME ...`          | only run these tests |

The tests and what each one covers are listed in `run_tests.py`. Besides the disassemblies, it has:

- the error tests (control files in `examples/python/errors`), each of which should make py8dis stop with a particular error message;
- the warning tests (in `examples/python/warnings`), each of which should give a particular warning.

With `-c`, when all the tests are run, it also runs `session_tests.py` (several disassemblies in one process, using py8dis as a library, and a check that each of py8dis's modules can be imported on its own) and `render_tests.py` (how each kind of line is written for each assembler; `./render_tests.py --print` shows what each test gives now).

On GitHub, the tests are run on every push and pull request (`.github/workflows/tests.yml`), with Python 3.9 and 3.14 and all nine assemblers: acme, xa, 64tass and ca65 (cc65) from Ubuntu's packages, and beebasm, Baron, Merlin 32, z88dk-z80asm and sjasmplus built from source (and cached). The results are on the repository's Actions tab.
