# Secret scan limits

The gitleaks job and `mask` / egress share two fail-closed corners that need an owner decision before they can be relaxed.

## Blob exemptions

The scan refuses a blob when its bytes look like UTF-16, or when a NUL byte hides text. A printable byte followed by 1, 2, or 3 NUL bytes counts as one character, in either byte order, and the gap may change from character to character. A gap of exactly 4 NULs does not start a run and is not a character by itself, so a file that is only that gap still passes. The same gap does not wipe out a run that has already started, so a 4-NUL gap every few characters is refused. A gap of 5 or more NULs, or a separator that is not a NUL, resets the run and is not refused. Those remaining shapes are deliberate encodings, in the same class as the deferred base64 and hex forms. A PNG, JPEG, GIF, PDF, ELF, zip, or gzip header is not enough: the rest of the blob is still checked. A `.pyc` header, under any file name, is the pyc-magic blob whose second through fourth bytes are `\r\r\n`. The parent process does not call `marshal.load` on it. If its git blob id is already on the base revision, or the base allow file names that id, a child process may load it. A crash in that child, including a signal exit, is a refusal. Every other pyc-magic blob is refused before that load. Inside the child, the value has to be one `types.CodeType` and `marshal.load` has to consume the whole value. Every string on that code object is scanned, including nested code objects: constants, names, locals, free variables, cells, the filename, the name, and the qualified name. The code, line, and exception tables are scanned for a long UTF-16 run. On bytecode the base already lists, a shorter run in the line table or the exception table (about 14 characters or fewer) is not refused. Unlisted bytecode never reaches that walk. Bytes and strings are still refused when they are UTF-16 or hide ASCII after a NUL.

That heuristic also refuses many real binaries. ELF objects and executables are mostly zeros, so they look like UTF-16. PDFs often have text after a NUL. Fonts (TTF and similar) trip the same checks. Any marshal error refuses the blob. A bytes or string constant, a tuple or dict of those, a compiled file that stores UTF-16, and the same bytes renamed to `.txt` are refused. The scan job runs that check on Python 3.13.18. The pin does not stop a crash inside marshal. Refusing unlisted bytecode before the load does. The CI tests job runs on Python 3.12, so it does not execute this prescan on 3.13.18. The repository has no binaries today. The first commit that adds an ELF, PDF, or font stays red until the base branch lists that blob.

To allow one blob:

1. On the default branch, add its git blob id, one per line, to `scripts/gitleaks_blob_allow.txt`.
2. That file is owned in `.github/CODEOWNERS`. A pull request cannot grant its own exemption: the job reads the list from the base revision (`git show BASE_SHA:scripts/gitleaks_blob_allow.txt`). On a push to the default branch the working tree is the post-merge content.
3. The exemption skips only the NUL / UTF-16 precheck. Gitleaks still scans the blob. A different blob at the same path is refused. A token after a NUL in an exempted blob is refused.

## Narrow JWT wraps

`mask` joins wrapped lines of a JSON Web Token when the pieces do not look like separate words. A bare token wrapped at a narrow width still leaks. The counts below are produced by `tests/test_jwt_wrap_widths.py`: 200 tokens, a 33-character header, a 43-character payload, and a 43-character signature, wrapped on a fixed width. The first count is 8 or more signature characters still visible after `mask`. The second is the whole signature, after newlines are removed.

| Width | 8 or more characters | Whole signature |
| --- | --- | --- |
| 4 | 96/200 | 65/200 |
| 5 | 66/200 | 59/200 |
| 6 | 25/200 | 19/200 |
| 7 | 6/200 | 6/200 |
| 8 | 12/200 | 9/200 |
| 9 | 6/200 | 6/200 |
| 10 | 13/200 | 13/200 |
| 11 | 0/200 | 0/200 |
| 12 | 6/200 | 6/200 |
| 13 | 0/200 | 0/200 |
| 14 | 0/200 | 0/200 |
| 15 | 41/200 | 41/200 |
| 16 | 0/200 | 0/200 |

Width 15 is 41/200, about one in five. Width 4 is 96/200 on this generator. Closing these widths without gluing ordinary prose is not part of this scan.

## Controls and progress bars

Egress refuses every C0 control except tab, line feed, and carriage return, plus DEL and the C1 range. The CLI exits nonzero and writes nothing. That includes the sequences progress bars use:

- cursor up (`ESC[A`, `ESC[1A`)
- cursor hide and show (`ESC[?25l`, `ESC[?25h`)
- cursor horizontal absolute (`ESC[G`)
- bracketed paste

`mask` does not erase a benign paragraph because of one of those sequences or a stray C1 byte. It drops the control and leaves the surrounding words. A control with a token on both sides, a token run starting at the control, or an unfinished `ESC[` that a token's own digit or `m` / `K` / `J` completes, still blanks that view. An 8-bit CSI (`U+009B`, as in a `9B 31 6D` color sequence) is refused rather than stripped. Colored text that uses a finished 7-bit SGR sequence is still readable, and a token inside it is still redacted.
