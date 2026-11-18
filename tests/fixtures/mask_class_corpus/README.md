# Mask class corpus

Each case is built at runtime from a synthetic token. The test checks `mask`,
`has_secrets`, egress output, and `mask_secrets.py --check`.

Benign lines are generated in the test. A run must not flag more than 7 of
the 1,694 benign lines.

## Deferred to follow-up pull requests

These encodings are not in this corpus:

- base32
- colon-separated hex
- `\x` hex escapes and octal escapes
- numeric character references without a semicolon
- quoted-printable soft line breaks
- nested encodings
- base64 runs longer than 256 characters, including the long-base64 finding
