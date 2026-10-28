# Credential-input guarantees and limits

These guarantees describe the current development source, not the published
prerelease binaries. They apply to the CLI's shared credential/policy-file
loader—including the non-bundled supplied-session Preview's V1 authorization
sources, V2/V4 cookie file, V3 form credential and V5/V6 imported-code file—and the native
provider's administrator-token loader. Source selection, byte
ceilings, validation, redacted errors and the absence of raw credential-value
arguments remain unchanged.

## File opening

Both loaders open once and validate metadata from that same handle before
reading bytes. There is no separate pathname precheck. Unix uses
`O_NOFOLLOW | O_NONBLOCK`: the final symbolic-link component is refused, and a
FIFO cannot wait for a writer before handle validation rejects it. Nonblocking
open does not impose a deadline on regular-file I/O. See the
[Linux open contract](https://man7.org/linux/man-pages/man2/open.2.html).

Windows opens with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`
and anonymous security quality of service. It rejects every opened reparse-point
attribute and every non-regular file, including directories, before reading.
The flags obtain the object handle for validation; they do not prove that the
whole path contains no reparse points. See Microsoft's
[CreateFile contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
and Rust's [security quality-of-service option](https://doc.rust-lang.org/std/os/windows/fs/trait.OpenOptionsExt.html#tymethod.security_qos_flags).
Platforms outside Unix and Windows refuse file input.

Use trusted local regular files and trusted parent directories. Final-component
protection is not ancestor containment or a hard-link provenance check. The
opened file's contents can still be modified; handle validation is not an
immutable snapshot. Bounded reads and size checks remain in force. Opening a
special or network path can contact its owner before handle validation, so
there is no general no-contact or bounded-latency guarantee for arbitrary paths.

## Owned intake memory

V7 selects no imported credential. Its validated non-secret policy and explicit
private output selection create one bounded OS-random S256/state transaction.
The CLI reserves a new local handoff file only after policy/composition/output
preflight; runtime receives a bounded one-shot writer, never a file path. The
handoff URI deliberately contains protocol state and challenge but no verifier.
It is private, not report output, and never printed by the command. The exact
registered callback receives the code in a bounded guarded POST body, not a
query string. Raw framing/form bytes are guarded before fallible parsing and
kept out of general response observers. The complete qualified callback must
be committed before the once-only token exchange; every target credential use
retains that same knowledge-authority chain. Unknown response parameters are
bounded and discarded; provider descriptions and URLs remain inert.

The file is create-only (Unix 0600, Windows inherited directory ACL) and removed
only while its parent and file identity still match task ownership. A replaced
or unverifiable path is retained with a static warning. Trusted/quiescent parent
assumptions still apply; regular-file writes and arbitrary host-library writers
are not promised interruptible, and no claim covers OS/HTTP-library/allocator
copies. Neither the handoff nor listener grants browser/profile/account access.

The selected V5 imported OAuth transaction uses the same single-handle bounded
regular-file intake, after non-secret policy/source preflight and output
reservation. Its complete bytes move into guarded ownership before fallible
TSV/context/S256 validation; no path is handed to the runtime for reopening.
The code and verifier are form-body values only at the exact separately
authorized IdP endpoint, never argv, a URL/query, a general observer or a saved
body digest. A private bounded token reducer guards the response bytes and
retains only the opaque Bearer credential plus classified facts. This does not
claim to erase transport-library, kernel, Python controller, environment or
allocator copies. See the V5 protocol and trust limitations in
`supplied-session-review.md`.

The CLI guards its owned input bytes before fallible validation. Environment
values enter the guard before Unicode and size checks. File/stdin reads use
fixed, initialized guarded storage, including bytes a reader writes before
returning an error. The one-byte overflow probe and any removed terminal LF or
CRLF are wiped while still owned. A successful handoff moves the existing
allocation into the scanner constructor without an extra intake copy. The V2
cookie source is one explicitly named, bounded regular file; its complete bytes
move into one zeroizing backing allocation before row validation. It is not
available from argv, environment, stdin, browser storage or directory search.

This CLI erasure guarantee ends at constructor handoff. Existing downstream
root/principal `PayloadSeed` or `String` copies and their lifetimes are unchanged;
they are not covered by this intake guarantee. The supplied-session path moves
its guarded V1 authorization allocation or V2 cookie backing allocation into its
context-owned transport state. V2 transiently composes an applicable `Cookie`
header for one exact admitted request; neither path establishes erasure of
transport-library copies. The provider
already guards its token input with `Zeroizing`; it also wipes a removed
line-ending suffix before truncation and retains its existing token-ownership
contract.

Neither loader claims to erase OS environment storage, allocator history,
process dumps, HTTP-library buffers or every successful downstream copy.
Stdin remains a bounded-byte source whose EOF/lifecycle must be controlled by
the invoking host; these changes do not add an input deadline.

Implementation and validation evidence are tracked separately in the
[corrective-maintenance ledger](../audits/native-oast-corrective-maintenance.md).
