# Secret scan limits

The gitleaks job and `mask` / egress share two fail-closed corners that need an owner decision before they can be relaxed.

## Blob exemptions

The scan refuses a blob when its bytes look like UTF-16, or when a NUL byte hides text. The file name is not an exemption. A PNG, JPEG, GIF, PDF, ELF, zip, gzip, or historical pyc header is accepted only when the rest of the blob is not UTF-16 and does not carry a token after a NUL.

That heuristic also refuses many real binaries. ELF objects and executables are mostly zeros, so they look like UTF-16. PDFs often have text after a NUL. Fonts (TTF and similar) trip the same checks. A CPython `.pyc` is accepted only when `marshal.load` on the bytes after the 16-byte header consumes the whole blob and leaves nothing. The scan job runs that parser on Python 3.13. A header in front of UTF-16 text, the same bytes under another name, or a real code object with UTF-16 appended is still refused. The repository has no binaries today. The first commit that adds an ELF, PDF, or font stays red until the base branch lists that blob.

To allow one blob:

1. On the default branch, add its git blob id, one per line, to `scripts/gitleaks_blob_allow.txt`.
2. That file is owned in `.github/CODEOWNERS`. A pull request cannot grant its own exemption: the job reads the list from the base revision (`git show BASE_SHA:scripts/gitleaks_blob_allow.txt`). On a push to the default branch the working tree is the post-merge content.
3. The exemption skips only the NUL / UTF-16 precheck. Gitleaks still scans the blob. A different blob at the same path is refused. A token after a NUL in an exempted blob is refused.

## Controls and progress bars

Egress refuses every C0 control except tab, line feed, and carriage return, plus DEL and the C1 range. The CLI exits nonzero and writes nothing. That includes the sequences progress bars use:

- cursor up (`ESC[A`, `ESC[1A`)
- cursor hide and show (`ESC[?25l`, `ESC[?25h`)
- cursor horizontal absolute (`ESC[G`)
- bracketed paste

`mask` does not erase a benign paragraph because of one of those sequences or a stray C1 byte. It drops the control and leaves the surrounding words. A control with a token on both sides, a token run starting at the control, or an unfinished `ESC[` that a token's own digit or `m` / `K` / `J` completes, still blanks that view. An 8-bit CSI (`U+009B`, as in a `9B 31 6D` color sequence) is refused rather than stripped. Colored text that uses a finished 7-bit SGR sequence is still readable, and a token inside it is still redacted.
