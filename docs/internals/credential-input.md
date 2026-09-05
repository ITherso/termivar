# Credential-input guarantees and limits

These guarantees describe the current development source, not the published
alpha.1 binaries. They apply to the CLI's shared credential/policy-file loader
and the native provider's administrator-token loader. Source selection, byte
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

The CLI guards its owned input bytes before fallible validation. Environment
values enter the guard before Unicode and size checks. File/stdin reads use
fixed, initialized guarded storage, including bytes a reader writes before
returning an error. The one-byte overflow probe and any removed terminal LF or
CRLF are wiped while still owned. A successful handoff moves the existing
allocation into the scanner constructor without an extra intake copy.

This CLI erasure guarantee ends at constructor handoff. Existing downstream
root/principal `PayloadSeed` or `String` copies and their lifetimes are unchanged;
they are not covered by this intake guarantee. The provider already guards its
token input with `Zeroizing`; it now also wipes a removed line-ending suffix
before truncation and retains its existing token-ownership contract.

Neither loader claims to erase OS environment storage, allocator history,
process dumps, HTTP-library buffers or every successful downstream copy.
Stdin remains a bounded-byte source whose EOF/lifecycle must be controlled by
the invoking host; these changes do not add an input deadline.

Implementation and validation evidence are tracked separately in the
[corrective-maintenance ledger](../audits/native-oast-corrective-maintenance.md).
